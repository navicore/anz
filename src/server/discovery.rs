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
    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    // Derive the signing algorithms we advertise from the realm's actual active keys.
    // Deduplicate while preserving order (RS256 sorted before EdDSA by our convention).
    let active_keys = db::signing_key::get_all_active_keys(&conn, &realm_obj.id)?;
    let mut algs: Vec<&'static str> = Vec::new();
    for k in &active_keys {
        let s = k.algorithm.as_jwt_alg();
        if !algs.contains(&s) {
            algs.push(s);
        }
    }
    algs.sort_by_key(|s| match *s {
        "RS256" => 0,
        "EdDSA" => 1,
        _ => 99,
    });
    // Fallback for realms with no active keys — unusual but don't return an empty list.
    if algs.is_empty() {
        algs.push("RS256");
    }

    let issuer = format!("{}/realms/{}", state.config.issuer_base_url, realm);

    Ok(Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "jwks_uri": format!("{}/jwks", issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": algs,
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "preferred_username", "email", "groups"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "revocation_endpoint": format!("{}/revoke", issuer),
    })))
}
