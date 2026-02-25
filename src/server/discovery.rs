use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use super::error::AppError;
use super::AppState;
use crate::db;

pub async fn openid_configuration(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> Result<Json<Value>, AppError> {
    // Verify realm exists
    let conn = state.db.lock().map_err(|e| AppError::Internal(e.to_string()))?;
    let _realm = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);

    Ok(Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "jwks_uri": format!("{}/jwks", issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
    })))
}
