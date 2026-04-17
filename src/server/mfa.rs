//! Two-factor authentication endpoints and helpers.
//!
//! After a successful password step, `authorize_post` calls `render_mfa_step` which
//! either renders a TOTP challenge page (user enrolled) or an enrollment page
//! (realm requires MFA, user not yet enrolled). Both forms POST here to
//! `/realms/{realm}/mfa` to complete the second step.

use askama::Template;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Path, State};
use axum::http::header::SET_COOKIE;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use qrcode::render::svg;
use qrcode::QrCode;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use super::authorize::AuthorizeQuery;
use super::error::AppError;
use super::AppState;
use crate::audit::{AuditAction, LogEventParams};
use crate::branding;
use crate::crypto::{self, totp};
use crate::db;
use crate::models::User;

/// State packed into the mfa_challenges row as JSON. For an already-enrolled user
/// only `authorize` is set; for a forced-enrollment flow `pending_enrollment` carries
/// the proposed secret + recovery code hashes so we don't write `user_mfa` until the
/// user confirms a code.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeState {
    pub authorize: AuthorizeQuery,
    pub pending_enrollment: Option<PendingEnrollment>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingEnrollment {
    pub secret_b32: String,
    pub recovery_code_hashes: Vec<String>,
    /// Plaintext recovery codes — only kept long enough to display on the
    /// enrollment page. Cleared once user confirms a code.
    pub recovery_code_plain: Vec<String>,
}

const CHALLENGE_TTL_SECS: i64 = 300;

#[derive(Template)]
#[template(path = "mfa_challenge.html")]
#[allow(dead_code)] // fields are read by Askama template rendering
struct ChallengeTemplate {
    realm_name: String,
    challenge_token: String,
    error_message: Option<String>,
    branding_title: String,
    branding_primary_color: String,
    branding_background_color: String,
    branding_custom_css: Option<String>,
}

#[derive(Template)]
#[template(path = "mfa_enroll.html")]
#[allow(dead_code)] // fields are read by Askama template rendering
struct EnrollTemplate {
    realm_name: String,
    challenge_token: String,
    secret: String,
    qr_svg: String,
    recovery_codes: Vec<String>,
    error_message: Option<String>,
    branding_title: String,
    branding_primary_color: String,
    branding_background_color: String,
    branding_custom_css: Option<String>,
}

/// Called from `authorize_post` after successful password verification when MFA is
/// either already enrolled or required by the realm. Creates the mfa_challenges row,
/// renders the challenge or enrollment page, returns the response (with no session
/// cookie — session is created only after MFA succeeds).
pub fn render_mfa_step(
    conn: &rusqlite::Connection,
    state: &AppState,
    realm: &str,
    user: &User,
    user_mfa: Option<&crate::models::UserMfa>,
    realm_requires_mfa: bool,
    authorize: AuthorizeQuery,
) -> Result<Response, AppError> {
    let challenge_token = generate_random_token();
    let challenge_token_hash = crypto::hex_encode(&Sha256::digest(challenge_token.as_bytes()));

    let realm_branding = branding::load_branding(&state.config.realms_dir, realm);

    let (state_blob, response_html) = if user_mfa.is_some() {
        // User already enrolled: show TOTP challenge.
        let challenge_state = ChallengeState {
            authorize,
            pending_enrollment: None,
        };
        let html = ChallengeTemplate {
            realm_name: realm.to_string(),
            challenge_token: challenge_token.clone(),
            error_message: None,
            branding_title: realm_branding.title.clone(),
            branding_primary_color: realm_branding.primary_color.clone(),
            branding_background_color: realm_branding.background_color.clone(),
            branding_custom_css: realm_branding.custom_css.clone(),
        }
        .render()
        .map_err(|e| AppError::Internal(e.to_string()))?;
        (challenge_state, html)
    } else {
        // Realm requires MFA but user not yet enrolled: render enrollment page.
        // Generate proposed secret + 10 recovery codes; persist proposal in challenge state.
        if !realm_requires_mfa {
            return Err(AppError::Internal(
                "render_mfa_step called with no enrollment and no requirement".to_string(),
            ));
        }
        let (secret_b32, _) = totp::generate_secret();
        let (recovery_plain, recovery_hashes) = generate_recovery_codes(10);

        let issuer = format!("anz ({realm})");
        let uri = totp::build_otpauth_uri(&issuer, &user.username, &secret_b32);
        let qr_svg = QrCode::new(uri.as_bytes())
            .map_err(|e| AppError::Internal(format!("qr code: {e}")))?
            .render::<svg::Color<'_>>()
            .min_dimensions(200, 200)
            .build();

        let challenge_state = ChallengeState {
            authorize,
            pending_enrollment: Some(PendingEnrollment {
                secret_b32: secret_b32.clone(),
                recovery_code_hashes: recovery_hashes,
                recovery_code_plain: recovery_plain.clone(),
            }),
        };

        state.audit.log_event(LogEventParams {
            realm,
            action: AuditAction::MfaEnrollmentRequired,
            user_id: Some(&user.id),
            client_id: None,
            ip: None,
            success: true,
            detail: None,
        });

        let html = EnrollTemplate {
            realm_name: realm.to_string(),
            challenge_token: challenge_token.clone(),
            secret: secret_b32,
            qr_svg,
            recovery_codes: recovery_plain,
            error_message: None,
            branding_title: realm_branding.title.clone(),
            branding_primary_color: realm_branding.primary_color.clone(),
            branding_background_color: realm_branding.background_color.clone(),
            branding_custom_css: realm_branding.custom_css.clone(),
        }
        .render()
        .map_err(|e| AppError::Internal(e.to_string()))?;
        (challenge_state, html)
    };

    let blob_json =
        serde_json::to_string(&state_blob).map_err(|e| AppError::Internal(e.to_string()))?;
    let expires_at = Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS);
    db::mfa_challenge::create(
        conn,
        &challenge_token_hash,
        &user.id,
        &blob_json,
        expires_at,
    )?;

    Ok(Html(response_html).into_response())
}

#[derive(Debug, Deserialize)]
pub struct MfaForm {
    pub challenge_token: String,
    pub code: String,
}

/// POST /realms/{realm}/mfa
pub async fn submit(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    Form(form): Form<MfaForm>,
) -> Result<Response, AppError> {
    let ip = addr.ip();

    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    let token_hash = crypto::hex_encode(&Sha256::digest(form.challenge_token.as_bytes()));
    let challenge = db::mfa_challenge::get(&conn, &token_hash)?
        .ok_or_else(|| AppError::Unauthorized("challenge expired or invalid".to_string()))?;

    let user = db::user::get_user_by_id(&conn, &challenge.user_id)?
        .ok_or_else(|| AppError::Internal("user not found".to_string()))?;

    // Per-user TOTP rate limit (separate from the per-IP login limit).
    if let Err(retry_after) = state.check_mfa_rate_limit(&user.id) {
        state.audit.log_event(LogEventParams {
            realm: &realm,
            action: AuditAction::MfaRateLimited,
            user_id: Some(&user.id),
            client_id: None,
            ip: Some(ip),
            success: false,
            detail: Some(&format!("retry_after={retry_after}s")),
        });
        return Err(AppError::TooManyRequests(format!(
            "Too many MFA attempts. Retry after {retry_after} seconds."
        )));
    }

    let challenge_state: ChallengeState = serde_json::from_str(&challenge.authorize_params)
        .map_err(|e| AppError::Internal(format!("corrupt challenge state: {e}")))?;

    // Verify the submitted code. The TOTP secret comes from either the pending
    // enrollment (forced-enrollment flow) or the existing user_mfa row (challenge
    // flow for an already-enrolled user). Recovery codes only apply to the latter.
    let verification = verify_code(
        &conn,
        &user.id,
        &form.code,
        challenge_state.pending_enrollment.as_ref(),
    )?;

    if !verification.success {
        state.record_mfa_attempt(&user.id);
        state.audit.log_event(LogEventParams {
            realm: &realm,
            action: AuditAction::MfaFailure,
            user_id: Some(&user.id),
            client_id: None,
            ip: Some(ip),
            success: false,
            detail: None,
        });
        // Re-render the same page with an error. Keep the challenge alive so the
        // user can retry without going back through password.
        return rerender_with_error(
            &conn,
            &state,
            &realm,
            &user,
            &form.challenge_token,
            &challenge_state,
            "Invalid code. Try again.",
        );
    }

    // Success path. Commit the enrollment (if applicable), consume the challenge,
    // create session, redirect to the original consumer with an auth code.
    if let Some(pending) = &challenge_state.pending_enrollment {
        db::user_mfa::enroll(
            &conn,
            &user.id,
            &pending.secret_b32,
            &pending.recovery_code_hashes,
        )?;
        state.audit.log_event(LogEventParams {
            realm: &realm,
            action: AuditAction::MfaEnrolled,
            user_id: Some(&user.id),
            client_id: None,
            ip: Some(ip),
            success: true,
            detail: Some("source=forced_login"),
        });
    }

    let action = if verification.was_recovery {
        AuditAction::MfaRecoveryUsed
    } else {
        AuditAction::MfaSuccess
    };
    state.audit.log_event(LogEventParams {
        realm: &realm,
        action,
        user_id: Some(&user.id),
        client_id: None,
        ip: Some(ip),
        success: true,
        detail: None,
    });

    db::mfa_challenge::delete(&conn, &token_hash)?;

    // From here it's the original "after password" tail of authorize_post: create
    // session, generate auth code, redirect to the consumer's redirect_uri.
    let session_token = generate_random_token();
    let session_token_hash = crypto::hex_encode(&Sha256::digest(session_token.as_bytes()));
    let session_lifetime = Duration::seconds(state.config.session_lifetime_secs as i64);
    let session_expires = Utc::now() + session_lifetime;
    db::session::create_session(
        &conn,
        &realm_obj.id,
        &user.id,
        &session_token_hash,
        session_expires,
    )?;
    state.audit.log_event(LogEventParams {
        realm: &realm,
        action: AuditAction::SessionCreated,
        user_id: Some(&user.id),
        client_id: None,
        ip: Some(ip),
        success: true,
        detail: None,
    });

    let session_cookie = format!(
        "anz_session_{realm}={session_token}; HttpOnly; SameSite=Lax; Path=/realms/{realm}; Max-Age={}",
        state.config.session_lifetime_secs
    );

    let redirect = super::authorize::generate_auth_code_redirect_for(
        &conn,
        &state,
        &realm_obj.id,
        &challenge_state.authorize,
        &user.id,
    )?;

    Ok(([(SET_COOKIE, session_cookie)], redirect).into_response())
}

struct CodeVerification {
    success: bool,
    was_recovery: bool,
}

fn verify_code(
    conn: &rusqlite::Connection,
    user_id: &str,
    submitted_code: &str,
    pending: Option<&PendingEnrollment>,
) -> Result<CodeVerification, AppError> {
    // 1. If we have a pending enrollment, only TOTP is checked (no recovery codes
    //    yet — the user hasn't confirmed they have any).
    if let Some(p) = pending {
        let ok = totp::verify_code(&p.secret_b32, submitted_code)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(CodeVerification {
            success: ok,
            was_recovery: false,
        });
    }

    // 2. Already enrolled. Try TOTP first. If that fails, try the code as a
    //    recovery code (single-use).
    let mfa = db::user_mfa::get(conn, user_id)?
        .ok_or_else(|| AppError::Internal("user_mfa missing for enrolled user".to_string()))?;
    if totp::verify_code(&mfa.secret_base32, submitted_code)
        .map_err(|e| AppError::Internal(e.to_string()))?
    {
        return Ok(CodeVerification {
            success: true,
            was_recovery: false,
        });
    }

    // Recovery code path: hash and try to consume.
    let code_hash = crypto::hex_encode(&Sha256::digest(submitted_code.as_bytes()));
    let consumed = db::user_mfa::consume_recovery_code(conn, user_id, &code_hash)?;
    Ok(CodeVerification {
        success: consumed,
        was_recovery: consumed,
    })
}

fn rerender_with_error(
    _conn: &rusqlite::Connection,
    state: &AppState,
    realm: &str,
    _user: &User,
    challenge_token: &str,
    challenge_state: &ChallengeState,
    error: &str,
) -> Result<Response, AppError> {
    let realm_branding = branding::load_branding(&state.config.realms_dir, realm);

    let html = if let Some(pending) = &challenge_state.pending_enrollment {
        let issuer = format!("anz ({realm})");
        let uri = totp::build_otpauth_uri(&issuer, "user", &pending.secret_b32);
        let qr_svg = QrCode::new(uri.as_bytes())
            .map_err(|e| AppError::Internal(format!("qr code: {e}")))?
            .render::<svg::Color<'_>>()
            .min_dimensions(200, 200)
            .build();
        EnrollTemplate {
            realm_name: realm.to_string(),
            challenge_token: challenge_token.to_string(),
            secret: pending.secret_b32.clone(),
            qr_svg,
            recovery_codes: pending.recovery_code_plain.clone(),
            error_message: Some(error.to_string()),
            branding_title: realm_branding.title,
            branding_primary_color: realm_branding.primary_color,
            branding_background_color: realm_branding.background_color,
            branding_custom_css: realm_branding.custom_css,
        }
        .render()
        .map_err(|e| AppError::Internal(e.to_string()))?
    } else {
        ChallengeTemplate {
            realm_name: realm.to_string(),
            challenge_token: challenge_token.to_string(),
            error_message: Some(error.to_string()),
            branding_title: realm_branding.title,
            branding_primary_color: realm_branding.primary_color,
            branding_background_color: realm_branding.background_color,
            branding_custom_css: realm_branding.custom_css,
        }
        .render()
        .map_err(|e| AppError::Internal(e.to_string()))?
    };

    Ok(Html(html).into_response())
}

fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_recovery_codes(n: usize) -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    for _ in 0..n {
        let mut bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut bytes);
        let code = URL_SAFE_NO_PAD.encode(bytes);
        let hash = crypto::hex_encode(&Sha256::digest(code.as_bytes()));
        plain.push(code);
        hashes.push(hash);
    }
    (plain, hashes)
}
