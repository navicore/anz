use crate::models::AuthorizationCode;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

/// Insert a new authorization code (storing the SHA-256 hash, not the raw code).
pub fn insert_auth_code(
    conn: &Connection,
    realm_id: &str,
    client_id: &str,
    user_id: &str,
    code_hash: &str,
    redirect_uri: &str,
    scopes: &str,
    code_challenge: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO authorization_codes (id, realm_id, client_id, user_id, code_hash, redirect_uri, scopes, code_challenge, expires_at, used)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
        params![
            id,
            realm_id,
            client_id,
            user_id,
            code_hash,
            redirect_uri,
            scopes,
            code_challenge,
            expires_at.to_rfc3339(),
        ],
    )?;
    Ok(id)
}

/// Consume an authorization code: look it up by hash, mark as used, return it.
/// Returns None if not found, already used, or expired.
pub fn consume_auth_code(
    conn: &Connection,
    code_hash: &str,
) -> Result<Option<AuthorizationCode>> {
    let now = Utc::now().to_rfc3339();

    let mut stmt = conn.prepare(
        "SELECT id, realm_id, client_id, user_id, code_hash, redirect_uri, scopes, code_challenge, expires_at, used
         FROM authorization_codes
         WHERE code_hash = ?1 AND used = 0 AND expires_at > ?2",
    )?;
    let mut rows = stmt.query_map(params![code_hash, now], |row| {
        let expires_str: String = row.get(8)?;
        Ok(AuthorizationCode {
            id: row.get(0)?,
            realm_id: row.get(1)?,
            client_id: row.get(2)?,
            user_id: row.get(3)?,
            code_hash: row.get(4)?,
            redirect_uri: row.get(5)?,
            scopes: row.get(6)?,
            code_challenge: row.get(7)?,
            expires_at: chrono::DateTime::parse_from_rfc3339(&expires_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            used: false,
        })
    })?;

    match rows.next() {
        Some(r) => {
            let code = r?;
            // Mark as used
            conn.execute(
                "UPDATE authorization_codes SET used = 1 WHERE id = ?1",
                params![code.id],
            )?;
            Ok(Some(code))
        }
        None => Ok(None),
    }
}
