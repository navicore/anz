use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Form;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::error::AppError;
use super::AppState;
use crate::audit::{AuditAction, LogEventParams};
use crate::crypto;
use crate::db;

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

/// POST /realms/{realm}/revoke — RFC 7009 token revocation
pub async fn revoke(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Form(form): Form<RevokeRequest>,
) -> Result<impl IntoResponse, AppError> {
    let conn = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Verify realm exists
    let _realm_obj = db::realm::get_realm_by_name(&conn, &realm)?
        .ok_or_else(|| AppError::NotFound(format!("realm '{realm}' not found")))?;

    let hint = form.token_type_hint.as_deref().unwrap_or("refresh_token");

    match hint {
        "access_token" => {
            // Access tokens are short-lived JWTs — silently ignore per RFC 7009
        }
        _ => {
            // Treat as refresh_token (default per spec)
            let token_hash = crypto::hex_encode(&Sha256::digest(form.token.as_bytes()));
            let revoked = db::refresh_token::revoke_refresh_token_by_hash(&conn, &token_hash)?;
            if revoked {
                state.audit.log_event(LogEventParams {
                    realm: &realm,
                    action: AuditAction::TokenRevoked,
                    user_id: None,
                    client_id: None,
                    ip: None,
                    success: true,
                    detail: Some("type=refresh_token"),
                });
            }
        }
    }

    // Always return 200 per RFC 7009
    Ok(StatusCode::OK)
}
