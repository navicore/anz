use axum::extract::{Path, State};
use axum::Form;
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::error::AppError;
use super::AppState;
use crate::crypto::{keys, pkce, token as jwt};
use crate::db;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    pub refresh_token: Option<String>,
}

pub async fn token(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Form(form): Form<TokenRequest>,
) -> Result<Json<Value>, AppError> {
    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    match form.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code(&conn, &state, &realm, &realm_obj.id, &form)
        }
        "refresh_token" => handle_refresh_token(&conn, &state, &realm, &realm_obj.id, &form),
        _ => Err(AppError::BadRequest("unsupported grant_type".to_string())),
    }
}

fn handle_authorization_code(
    conn: &rusqlite::Connection,
    state: &AppState,
    realm: &str,
    realm_id: &str,
    form: &TokenRequest,
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
    let code_hash = hex_encode(&Sha256::digest(raw_code.as_bytes()));
    let auth_code = db::auth_code::consume_auth_code(conn, &code_hash)?
        .ok_or_else(|| AppError::BadRequest("invalid or expired authorization code".to_string()))?;

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

    // Get signing key
    let signing_key = db::signing_key::get_active_signing_key(conn, realm_id)?
        .ok_or_else(|| AppError::Internal("no signing key found".to_string()))?;

    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);
    let encoding_key = keys::encoding_key_from_pem(&signing_key.private_key_pem)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Build ID token
    let id_claims = jwt::build_id_token_claims(
        &issuer,
        &user.id,
        &auth_code.client_id,
        state.config.id_token_lifetime_secs,
        &user.username,
        &user.email,
        None, // nonce is not stored in auth_code in this implementation
    );
    let id_token = jwt::encode_jwt(&id_claims, &signing_key.kid, &encoding_key)
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
    let access_token = jwt::encode_jwt(&access_claims, &signing_key.kid, &encoding_key)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Issue refresh token
    let raw_refresh = generate_random_token();
    let refresh_hash = hex_encode(&Sha256::digest(raw_refresh.as_bytes()));
    let refresh_lifetime = Duration::seconds(state.config.refresh_token_lifetime_secs as i64);
    let refresh_expires = Utc::now() + refresh_lifetime;
    db::refresh_token::insert_refresh_token(
        conn,
        realm_id,
        &auth_code.client_id,
        &user.id,
        &refresh_hash,
        &auth_code.scopes,
        refresh_expires,
    )?;

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
) -> Result<Json<Value>, AppError> {
    let raw_token = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("refresh_token is required".to_string()))?;

    let token_hash = hex_encode(&Sha256::digest(raw_token.as_bytes()));
    let old_token = db::refresh_token::consume_refresh_token(conn, &token_hash)?
        .ok_or_else(|| AppError::BadRequest("invalid or expired refresh token".to_string()))?;

    // Look up user
    let user = db::user::get_user_by_id(conn, &old_token.user_id)?
        .ok_or_else(|| AppError::Internal("user not found".to_string()))?;

    // Get signing key
    let signing_key = db::signing_key::get_active_signing_key(conn, realm_id)?
        .ok_or_else(|| AppError::Internal("no signing key found".to_string()))?;

    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);
    let encoding_key = keys::encoding_key_from_pem(&signing_key.private_key_pem)
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
    let access_token = jwt::encode_jwt(&access_claims, &signing_key.kid, &encoding_key)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // New ID token
    let id_claims = jwt::build_id_token_claims(
        &issuer,
        &user.id,
        &old_token.client_id,
        state.config.id_token_lifetime_secs,
        &user.username,
        &user.email,
        None,
    );
    let id_token = jwt::encode_jwt(&id_claims, &signing_key.kid, &encoding_key)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // New refresh token (rotation)
    let new_raw_refresh = generate_random_token();
    let new_refresh_hash = hex_encode(&Sha256::digest(new_raw_refresh.as_bytes()));
    let refresh_lifetime = Duration::seconds(state.config.refresh_token_lifetime_secs as i64);
    let refresh_expires = Utc::now() + refresh_lifetime;
    db::refresh_token::insert_refresh_token(
        conn,
        realm_id,
        &old_token.client_id,
        &user.id,
        &new_refresh_hash,
        &old_token.scopes,
        refresh_expires,
    )?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_lifetime_secs,
        "id_token": id_token,
        "refresh_token": new_raw_refresh,
    })))
}

fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
