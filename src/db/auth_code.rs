use crate::models::AuthorizationCode;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

pub struct NewAuthCode<'a> {
    pub realm_id: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub code_hash: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a str,
    pub code_challenge: &'a str,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Insert a new authorization code (storing the SHA-256 hash, not the raw code).
pub fn insert_auth_code(conn: &Connection, code: &NewAuthCode) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO authorization_codes (id, realm_id, client_id, user_id, code_hash, redirect_uri, scopes, code_challenge, expires_at, used)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
        params![
            id,
            code.realm_id,
            code.client_id,
            code.user_id,
            code.code_hash,
            code.redirect_uri,
            code.scopes,
            code.code_challenge,
            code.expires_at.to_rfc3339(),
        ],
    )?;
    Ok(id)
}

/// Consume an authorization code: look it up by hash, mark as used, return it.
/// Returns None if not found, already used, or expired.
pub fn consume_auth_code(conn: &Connection, code_hash: &str) -> Result<Option<AuthorizationCode>> {
    let now = Utc::now().to_rfc3339();

    let mut stmt = conn.prepare(
        "SELECT id, client_id, user_id, redirect_uri, scopes, code_challenge
         FROM authorization_codes
         WHERE code_hash = ?1 AND used = 0 AND expires_at > ?2",
    )?;
    let mut rows = stmt.query_map(params![code_hash, now], |row| {
        Ok(AuthorizationCode {
            id: row.get(0)?,
            client_id: row.get(1)?,
            user_id: row.get(2)?,
            redirect_uri: row.get(3)?,
            scopes: row.get(4)?,
            code_challenge: row.get(5)?,
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
