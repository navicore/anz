use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::error::AppError;
use super::AppState;
use crate::crypto::{keys, password as pw, token as jwt};
use crate::db;

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, AppError> {
    // Validate bearer token
    let bearer = extract_bearer(&headers)?;

    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    let signing_key = db::signing_key::get_active_signing_key(&conn, &realm_obj.id)?
        .ok_or_else(|| AppError::Internal("no signing key found".to_string()))?;

    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);
    let decoding_key = keys::decoding_key_from_pem(&signing_key.public_key_pem)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let claims = jwt::decode_access_token(&bearer, &decoding_key, &issuer)
        .map_err(|_| AppError::Unauthorized("invalid access token".to_string()))?;

    let user = db::user::get_user_by_id(&conn, &claims.sub)?
        .ok_or_else(|| AppError::Internal("user not found".to_string()))?;

    // Verify current password
    if !pw::verify_password(&body.current_password, &user.password_hash) {
        return Err(AppError::BadRequest(
            "current password is incorrect".to_string(),
        ));
    }

    // Hash and update new password
    let new_hash =
        pw::hash_password(&body.new_password).map_err(|e| AppError::Internal(e.to_string()))?;
    db::user::update_password(&conn, &user.id, &new_hash)?;

    Ok(Json(json!({ "status": "password updated" })))
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, AppError> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("expected Bearer token".to_string()))?;

    Ok(token.to_string())
}
