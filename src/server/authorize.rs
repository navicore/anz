use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::header::SET_COOKIE;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::error::AppError;
use super::AppState;
use crate::crypto::{csrf, password as pw};
use crate::db;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    realm_name: String,
    error_message: Option<String>,
    csrf_token: String,
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    message: String,
}

fn validate_authorize_params(q: &AuthorizeQuery) -> Result<(), String> {
    if q.response_type != "code" {
        return Err("unsupported response_type".to_string());
    }
    if q.code_challenge.is_none() || q.code_challenge.as_deref() == Some("") {
        return Err("code_challenge is required (PKCE)".to_string());
    }
    match q.code_challenge_method.as_deref() {
        Some("S256") => {}
        None => return Err("code_challenge_method is required (must be S256)".to_string()),
        _ => return Err("only S256 code_challenge_method is supported".to_string()),
    }
    Ok(())
}

/// GET /realms/{realm}/authorize — show login form (or redirect if session exists)
pub async fn authorize_get(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Query(q): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Validate params
    if let Err(msg) = validate_authorize_params(&q) {
        let tmpl = ErrorTemplate { message: msg };
        return Ok(Html(tmpl.render().unwrap_or_default()).into_response());
    }

    let conn = state.db.lock().map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    // Validate client
    let client = db::client::get_client_by_client_id(&conn, &realm_obj.id, &q.client_id)?
        .ok_or_else(|| AppError::BadRequest("unknown client_id".to_string()))?;

    if !client.redirect_uris.contains(&q.redirect_uri) {
        return Err(AppError::BadRequest("redirect_uri not registered".to_string()));
    }

    // Check for existing session
    let session_cookie_name = format!("anz_session_{realm}");
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            if let Some(session_token) = extract_cookie(cookies, &session_cookie_name) {
                let token_hash = hex::encode(Sha256::digest(session_token.as_bytes()));
                if let Ok(Some(session)) =
                    db::session::get_session_by_token_hash(&conn, &realm_obj.id, &token_hash)
                {
                    // Session exists — generate auth code and redirect
                    return generate_auth_code_redirect(
                        &conn,
                        &state,
                        &realm_obj.id,
                        &q,
                        &session.user_id,
                    );
                }
            }
        }
    }

    // No session — show login form
    let csrf_token = csrf::generate_csrf_token();
    let csrf_cookie = format!(
        "anz_csrf_{realm}={csrf_token}; HttpOnly; SameSite=Lax; Path=/realms/{realm}"
    );

    let tmpl = LoginTemplate {
        realm_name: realm,
        error_message: None,
        csrf_token,
        client_id: q.client_id,
        redirect_uri: q.redirect_uri,
        response_type: q.response_type,
        scope: q.scope.unwrap_or_else(|| "openid".to_string()),
        state: q.state.unwrap_or_default(),
        code_challenge: q.code_challenge.unwrap_or_default(),
        code_challenge_method: q.code_challenge_method.unwrap_or_default(),
        nonce: q.nonce,
    };

    let html = tmpl.render().map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(([(SET_COOKIE, csrf_cookie)], Html(html)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeForm {
    pub csrf_token: String,
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

/// POST /realms/{realm}/authorize — validate credentials, issue auth code, redirect
pub async fn authorize_post(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeForm>,
) -> Result<Response, AppError> {
    let conn = state.db.lock().map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    // Verify CSRF (double-submit cookie pattern)
    let csrf_cookie_name = format!("anz_csrf_{realm}");
    let csrf_from_cookie = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| extract_cookie(cookies, &csrf_cookie_name))
        .unwrap_or_default();

    if !csrf::verify_csrf_token(&form.csrf_token, &csrf_from_cookie) {
        return render_login_error(&realm, &form, "Invalid request. Please try again.");
    }

    // Validate client and redirect_uri
    let client = db::client::get_client_by_client_id(&conn, &realm_obj.id, &form.client_id)?
        .ok_or_else(|| AppError::BadRequest("unknown client_id".to_string()))?;

    if !client.redirect_uris.contains(&form.redirect_uri) {
        return Err(AppError::BadRequest("redirect_uri not registered".to_string()));
    }

    // Authenticate user
    let user = db::user::get_user_by_username(&conn, &realm_obj.id, &form.username)?;
    let authenticated = match &user {
        Some(u) => pw::verify_password(&form.password, &u.password_hash),
        None => {
            // Timing oracle prevention
            pw::dummy_verify();
            false
        }
    };

    if !authenticated {
        return render_login_error(&realm, &form, "Invalid username or password");
    }

    let user = user.unwrap();

    // Create session
    let session_token = generate_random_token();
    let session_token_hash = hex::encode(Sha256::digest(session_token.as_bytes()));
    let session_lifetime = Duration::seconds(state.config.session_lifetime_secs as i64);
    let session_expires = Utc::now() + session_lifetime;
    db::session::create_session(
        &conn,
        &realm_obj.id,
        &user.id,
        &session_token_hash,
        session_expires,
    )?;

    let session_cookie = format!(
        "anz_session_{realm}={session_token}; HttpOnly; SameSite=Lax; Path=/realms/{realm}; Max-Age={}",
        state.config.session_lifetime_secs
    );

    // Generate auth code and redirect
    let q = AuthorizeQuery {
        response_type: form.response_type,
        client_id: form.client_id,
        redirect_uri: form.redirect_uri,
        scope: Some(form.scope),
        state: Some(form.state),
        code_challenge: Some(form.code_challenge),
        code_challenge_method: Some(form.code_challenge_method),
        nonce: form.nonce,
    };

    let (redirect_response, _) = generate_auth_code_redirect_inner(
        &conn, &state, &realm_obj.id, &q, &user.id,
    )?;

    // Clear CSRF cookie, set session cookie
    let clear_csrf = format!(
        "anz_csrf_{realm}=; HttpOnly; SameSite=Lax; Path=/realms/{realm}; Max-Age=0"
    );

    Ok((
        [
            (SET_COOKIE, session_cookie),
            (SET_COOKIE, clear_csrf),
        ],
        redirect_response,
    )
        .into_response())
}

fn generate_auth_code_redirect(
    conn: &rusqlite::Connection,
    state: &AppState,
    realm_id: &str,
    q: &AuthorizeQuery,
    user_id: &str,
) -> Result<Response, AppError> {
    let (redirect, _) = generate_auth_code_redirect_inner(conn, state, realm_id, q, user_id)?;
    Ok(redirect.into_response())
}

fn generate_auth_code_redirect_inner(
    conn: &rusqlite::Connection,
    state: &AppState,
    realm_id: &str,
    q: &AuthorizeQuery,
    user_id: &str,
) -> Result<(Redirect, String), AppError> {
    let raw_code = generate_random_token();
    let code_hash = hex::encode(Sha256::digest(raw_code.as_bytes()));

    let lifetime = Duration::seconds(state.config.auth_code_lifetime_secs as i64);
    let expires_at = Utc::now() + lifetime;

    db::auth_code::insert_auth_code(
        conn,
        realm_id,
        &q.client_id,
        user_id,
        &code_hash,
        &q.redirect_uri,
        q.scope.as_deref().unwrap_or("openid"),
        q.code_challenge.as_deref().unwrap_or(""),
        expires_at,
    )?;

    let state_param = q.state.as_deref().unwrap_or("");
    let redirect_url = format!(
        "{}?code={}&state={}",
        q.redirect_uri,
        urlencoding::encode(&raw_code),
        urlencoding::encode(state_param),
    );

    Ok((Redirect::to(&redirect_url), raw_code))
}

fn render_login_error(
    realm: &str,
    form: &AuthorizeForm,
    error_msg: &str,
) -> Result<Response, AppError> {
    let csrf_token = csrf::generate_csrf_token();
    let csrf_cookie = format!(
        "anz_csrf_{realm}={csrf_token}; HttpOnly; SameSite=Lax; Path=/realms/{realm}"
    );

    let tmpl = LoginTemplate {
        realm_name: realm.to_string(),
        error_message: Some(error_msg.to_string()),
        csrf_token,
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        response_type: form.response_type.clone(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
        nonce: form.nonce.clone(),
    };

    let html = tmpl.render().map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(([(SET_COOKIE, csrf_cookie)], Html(html)).into_response())
}

fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn extract_cookie<'a>(cookies: &'a str, name: &str) -> Option<String> {
    for part in cookies.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

// hex encoding helper (avoid adding another dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
