use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use super::error::AppError;
use super::AppState;
use crate::crypto::keys::public_key_to_jwk;
use crate::db;

pub async fn jwks(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> Result<Json<Value>, AppError> {
    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    let keys = db::signing_key::get_all_active_keys(&conn, &realm_obj.id)?;
    let mut jwks = Vec::new();
    for k in keys {
        let jwk = public_key_to_jwk(&k.public_key_pem, &k.kid)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        jwks.push(jwk);
    }

    Ok(Json(json!({ "keys": jwks })))
}
