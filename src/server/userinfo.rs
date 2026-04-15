use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

use super::error::AppError;
use super::AppState;
use crate::crypto::token as jwt;
use crate::db;

pub async fn userinfo(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let bearer = extract_bearer(&headers)?;

    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    // Pass every stored key (active + deactivated); decode_access_token dispatches on
    // the token's kid header so tokens signed before a rotation still verify.
    let verification_keys = db::signing_key::get_all_keys(&conn, &realm_obj.id)?;
    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);

    let claims = jwt::decode_access_token(&bearer, &verification_keys, &issuer)
        .map_err(|_| AppError::Unauthorized("invalid access token".to_string()))?;

    let user = db::user::get_user_by_id(&conn, &claims.sub)?
        .ok_or_else(|| AppError::Internal("user not found".to_string()))?;

    let mut response = json!({
        "sub": user.id,
        "preferred_username": user.username,
        "email": user.email,
    });
    let has_groups_scope = claims.scope.split_whitespace().any(|s| s == "groups");
    if has_groups_scope && !user.groups.is_empty() {
        response["groups"] = json!(user.groups);
    }

    Ok(Json(response))
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
