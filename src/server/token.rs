use axum::extract::{Path, State};
use axum::Form;
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::error::AppError;
use super::AppState;
use crate::audit::{AuditAction, LogEventParams};
use crate::crypto::{self, keys, pkce, token as jwt};
use crate::db;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn token(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: axum::http::HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Json<Value>, AppError> {
    // Extract client_secret from form body (client_secret_post) or
    // Authorization Basic header (client_secret_basic)
    let client_secret = form
        .client_secret
        .clone()
        .or_else(|| extract_basic_auth_secret(&headers));

    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    match form.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(
            &conn,
            &state,
            &realm,
            &realm_obj.id,
            &form,
            client_secret.as_deref(),
        ),
        "refresh_token" => handle_refresh_token(
            &conn,
            &state,
            &realm,
            &realm_obj.id,
            &form,
            client_secret.as_deref(),
        ),
        _ => Err(AppError::BadRequest("unsupported grant_type".to_string())),
    }
}

fn handle_authorization_code(
    conn: &rusqlite::Connection,
    state: &AppState,
    realm: &str,
    realm_id: &str,
    form: &TokenRequest,
    client_secret: Option<&str>,
) -> Result<Json<Value>, AppError> {
    let raw_code = form
        .code
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("code is required".to_string()))?;
    let redirect_uri = form
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("redirect_uri is required".to_string()))?;
    let code_verifier = form
        .code_verifier
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("code_verifier is required (PKCE)".to_string()))?;

    // Hash the raw code and look it up
    let code_hash = crypto::hex_encode(&Sha256::digest(raw_code.as_bytes()));
    let auth_code = db::auth_code::consume_auth_code(conn, &code_hash)?
        .ok_or_else(|| AppError::BadRequest("invalid or expired authorization code".to_string()))?;

    // Verify client_secret for confidential clients
    verify_client_secret(conn, realm_id, &auth_code.client_id, client_secret)?;

    // Verify redirect_uri matches
    if auth_code.redirect_uri != redirect_uri {
        return Err(AppError::BadRequest("redirect_uri mismatch".to_string()));
    }

    // Verify PKCE
    if !pkce::verify_s256(code_verifier, &auth_code.code_challenge) {
        return Err(AppError::BadRequest("PKCE verification failed".to_string()));
    }

    // Look up user
    let user = db::user::get_user_by_id(conn, &auth_code.user_id)?
        .ok_or_else(|| AppError::Internal("user not found".to_string()))?;

    // Get signing key (prefers RS256 over EdDSA when both are active in the realm)
    let signing_key = db::signing_key::get_preferred_signing_key(conn, realm_id)?
        .ok_or_else(|| AppError::Internal("no signing key found".to_string()))?;

    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);
    let encoding_key =
        keys::encoding_key_from_pem(signing_key.algorithm, &signing_key.private_key_pem)
            .map_err(|e| AppError::Internal(e.to_string()))?;

    // Build ID token (groups only included when "groups" scope is requested)
    let id_claims = jwt::build_id_token_claims(&jwt::IdTokenParams {
        issuer: &issuer,
        sub: &user.id,
        aud: &auth_code.client_id,
        lifetime_secs: state.config.id_token_lifetime_secs,
        username: &user.username,
        email: &user.email,
        nonce: auth_code.nonce.clone(),
        groups: &user.groups,
        scopes: &auth_code.scopes,
    });
    let id_token = jwt::encode_jwt(
        &id_claims,
        &signing_key.kid,
        &encoding_key,
        signing_key.algorithm,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Build access token
    let access_claims = jwt::build_access_token_claims(
        &issuer,
        &user.id,
        &issuer,
        state.config.access_token_lifetime_secs,
        &auth_code.scopes,
        &auth_code.client_id,
    );
    let access_token = jwt::encode_jwt(
        &access_claims,
        &signing_key.kid,
        &encoding_key,
        signing_key.algorithm,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Issue refresh token (preserves nonce so refresh-issued ID tokens echo it, per OIDC Core § 12)
    let raw_refresh = generate_random_token();
    let refresh_hash = crypto::hex_encode(&Sha256::digest(raw_refresh.as_bytes()));
    let refresh_lifetime = Duration::seconds(state.config.refresh_token_lifetime_secs as i64);
    let refresh_expires = Utc::now() + refresh_lifetime;
    db::refresh_token::insert_refresh_token(
        conn,
        &db::refresh_token::NewRefreshToken {
            realm_id,
            client_id: &auth_code.client_id,
            user_id: &user.id,
            token_hash: &refresh_hash,
            scopes: &auth_code.scopes,
            nonce: auth_code.nonce.as_deref(),
            expires_at: refresh_expires,
        },
    )?;

    state.audit.log_event(LogEventParams {
        realm,
        action: AuditAction::TokenIssued,
        user_id: Some(&user.id),
        client_id: Some(&auth_code.client_id),
        ip: None,
        success: true,
        detail: Some("grant=authorization_code"),
    });

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_lifetime_secs,
        "id_token": id_token,
        "refresh_token": raw_refresh,
    })))
}

fn handle_refresh_token(
    conn: &rusqlite::Connection,
    state: &AppState,
    realm: &str,
    realm_id: &str,
    form: &TokenRequest,
    client_secret: Option<&str>,
) -> Result<Json<Value>, AppError> {
    let raw_token = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("refresh_token is required".to_string()))?;

    let token_hash = crypto::hex_encode(&Sha256::digest(raw_token.as_bytes()));
    let old_token = db::refresh_token::consume_refresh_token(conn, &token_hash)?
        .ok_or_else(|| AppError::BadRequest("invalid or expired refresh token".to_string()))?;

    // Verify client_secret for confidential clients
    verify_client_secret(conn, realm_id, &old_token.client_id, client_secret)?;

    // Look up user
    let user = db::user::get_user_by_id(conn, &old_token.user_id)?
        .ok_or_else(|| AppError::Internal("user not found".to_string()))?;

    // Get signing key (prefers RS256 over EdDSA when both are active in the realm)
    let signing_key = db::signing_key::get_preferred_signing_key(conn, realm_id)?
        .ok_or_else(|| AppError::Internal("no signing key found".to_string()))?;

    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);
    let encoding_key =
        keys::encoding_key_from_pem(signing_key.algorithm, &signing_key.private_key_pem)
            .map_err(|e| AppError::Internal(e.to_string()))?;

    // New access token
    let access_claims = jwt::build_access_token_claims(
        &issuer,
        &user.id,
        &issuer,
        state.config.access_token_lifetime_secs,
        &old_token.scopes,
        &old_token.client_id,
    );
    let access_token = jwt::encode_jwt(
        &access_claims,
        &signing_key.kid,
        &encoding_key,
        signing_key.algorithm,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // New ID token (echo the original nonce per OIDC Core § 12)
    let id_claims = jwt::build_id_token_claims(&jwt::IdTokenParams {
        issuer: &issuer,
        sub: &user.id,
        aud: &old_token.client_id,
        lifetime_secs: state.config.id_token_lifetime_secs,
        username: &user.username,
        email: &user.email,
        nonce: old_token.nonce.clone(),
        groups: &user.groups,
        scopes: &old_token.scopes,
    });
    let id_token = jwt::encode_jwt(
        &id_claims,
        &signing_key.kid,
        &encoding_key,
        signing_key.algorithm,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // New refresh token (rotation; preserves original nonce across refreshes)
    let new_raw_refresh = generate_random_token();
    let new_refresh_hash = crypto::hex_encode(&Sha256::digest(new_raw_refresh.as_bytes()));
    let refresh_lifetime = Duration::seconds(state.config.refresh_token_lifetime_secs as i64);
    let refresh_expires = Utc::now() + refresh_lifetime;
    db::refresh_token::insert_refresh_token(
        conn,
        &db::refresh_token::NewRefreshToken {
            realm_id,
            client_id: &old_token.client_id,
            user_id: &user.id,
            token_hash: &new_refresh_hash,
            scopes: &old_token.scopes,
            nonce: old_token.nonce.as_deref(),
            expires_at: refresh_expires,
        },
    )?;

    state.audit.log_event(LogEventParams {
        realm,
        action: AuditAction::TokenRefreshed,
        user_id: Some(&user.id),
        client_id: Some(&old_token.client_id),
        ip: None,
        success: true,
        detail: None,
    });

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_lifetime_secs,
        "id_token": id_token,
        "refresh_token": new_raw_refresh,
    })))
}

/// Extract client_secret from an HTTP Basic Authorization header.
/// Format: `Authorization: Basic base64(client_id:client_secret)`
fn extract_basic_auth_secret(headers: &axum::http::HeaderMap) -> Option<String> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?,
    )
    .ok()?;
    let (_client_id, secret) = decoded.split_once(':')?;
    Some(secret.to_string())
}

/// Validate client_secret for confidential clients. Public clients (no secret) pass through.
fn verify_client_secret(
    conn: &rusqlite::Connection,
    realm_id: &str,
    client_id: &str,
    provided_secret: Option<&str>,
) -> Result<(), AppError> {
    let client = db::client::get_client_by_client_id(conn, realm_id, client_id)?
        .ok_or_else(|| AppError::Unauthorized("invalid client credentials".to_string()))?;

    if let Some(expected_hash) = &client.client_secret_hash {
        let provided = provided_secret.unwrap_or("");
        let provided_hash = crypto::hex_encode(&Sha256::digest(provided.as_bytes()));
        let matches: bool = provided_hash
            .as_bytes()
            .ct_eq(expected_hash.as_bytes())
            .into();
        if !matches {
            return Err(AppError::Unauthorized(
                "invalid client credentials".to_string(),
            ));
        }
    }
    Ok(())
}

fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn setup() -> (rusqlite::Connection, String) {
        let conn = crate::db::open_in_memory().unwrap();
        let realm =
            crate::db::realm::create_realm(&conn, "test", crate::models::SigningAlgorithm::EdDsa)
                .unwrap();
        (conn, realm.id)
    }

    #[test]
    fn public_client_passes_without_secret() {
        let (conn, realm_id) = setup();
        db::client::create_client(&conn, &realm_id, "public-app", &[], None).unwrap();
        assert!(verify_client_secret(&conn, &realm_id, "public-app", None).is_ok());
    }

    #[test]
    fn confidential_client_passes_with_correct_secret() {
        let (conn, realm_id) = setup();
        let secret = "my-secret-value";
        let hash = crypto::hex_encode(&Sha256::digest(secret.as_bytes()));
        db::client::create_client(&conn, &realm_id, "secure-app", &[], Some(&hash)).unwrap();
        assert!(verify_client_secret(&conn, &realm_id, "secure-app", Some(secret)).is_ok());
    }

    #[test]
    fn confidential_client_rejects_wrong_secret() {
        let (conn, realm_id) = setup();
        let hash = crypto::hex_encode(&Sha256::digest(b"correct"));
        db::client::create_client(&conn, &realm_id, "secure-app", &[], Some(&hash)).unwrap();
        assert!(verify_client_secret(&conn, &realm_id, "secure-app", Some("wrong")).is_err());
    }

    #[test]
    fn confidential_client_rejects_missing_secret() {
        let (conn, realm_id) = setup();
        let hash = crypto::hex_encode(&Sha256::digest(b"secret"));
        db::client::create_client(&conn, &realm_id, "secure-app", &[], Some(&hash)).unwrap();
        assert!(verify_client_secret(&conn, &realm_id, "secure-app", None).is_err());
    }

    #[test]
    fn missing_client_is_rejected() {
        let (conn, realm_id) = setup();
        assert!(verify_client_secret(&conn, &realm_id, "nonexistent", Some("any")).is_err());
    }

    // -- HTTP-level integration tests --

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn build_test_router() -> axum::Router {
        let conn = crate::db::open_in_memory().unwrap();
        crate::db::realm::create_realm(&conn, "test", crate::models::SigningAlgorithm::EdDsa)
            .unwrap();
        let audit = crate::audit::AuditLogger::new(false, "/dev/null");
        let config = crate::config::Config::default();
        let cipher = std::sync::Arc::new(crate::crypto::secret_cipher::SecretCipher::noop());
        crate::server::build_router(config, conn, audit, cipher)
    }

    fn token_form_request(realm: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!("/realms/{realm}/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn http_token_rejects_wrong_secret() {
        let router = build_test_router();

        let resp = router
            .oneshot(token_form_request(
                "test",
                "grant_type=authorization_code&code=bogus&redirect_uri=http://x&code_verifier=x",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn http_token_returns_400_for_unknown_grant() {
        let router = build_test_router();
        let resp = router
            .oneshot(token_form_request("test", "grant_type=invalid"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn http_token_returns_404_for_unknown_realm() {
        let router = build_test_router();
        let resp = router
            .oneshot(token_form_request(
                "nonexistent",
                "grant_type=authorization_code&code=x&redirect_uri=x&code_verifier=x",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
