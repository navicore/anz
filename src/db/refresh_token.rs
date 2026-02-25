use crate::models::RefreshToken;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

/// Insert a new refresh token (storing the SHA-256 hash).
pub fn insert_refresh_token(
    conn: &Connection,
    realm_id: &str,
    client_id: &str,
    user_id: &str,
    token_hash: &str,
    scopes: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO refresh_tokens (id, realm_id, client_id, user_id, token_hash, scopes, expires_at, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        params![
            id,
            realm_id,
            client_id,
            user_id,
            token_hash,
            scopes,
            expires_at.to_rfc3339(),
        ],
    )?;
    Ok(id)
}

/// Consume a refresh token: look it up by hash, revoke it, return it.
/// Returns None if not found, already revoked, or expired.
pub fn consume_refresh_token(
    conn: &Connection,
    token_hash: &str,
) -> Result<Option<RefreshToken>> {
    let now = Utc::now().to_rfc3339();

    let mut stmt = conn.prepare(
        "SELECT id, realm_id, client_id, user_id, token_hash, scopes, expires_at, revoked
         FROM refresh_tokens
         WHERE token_hash = ?1 AND revoked = 0 AND expires_at > ?2",
    )?;
    let mut rows = stmt.query_map(params![token_hash, now], |row| {
        let expires_str: String = row.get(6)?;
        Ok(RefreshToken {
            id: row.get(0)?,
            realm_id: row.get(1)?,
            client_id: row.get(2)?,
            user_id: row.get(3)?,
            token_hash: row.get(4)?,
            scopes: row.get(5)?,
            expires_at: chrono::DateTime::parse_from_rfc3339(&expires_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            revoked: false,
        })
    })?;

    match rows.next() {
        Some(r) => {
            let token = r?;
            // Revoke on use (rotation)
            conn.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1",
                params![token.id],
            )?;
            Ok(Some(token))
        }
        None => Ok(None),
    }
}
