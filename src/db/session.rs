use crate::models::Session;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

pub fn create_session(
    conn: &Connection,
    realm_id: &str,
    user_id: &str,
    session_token_hash: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<Session> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    conn.execute(
        "INSERT INTO sessions (id, realm_id, user_id, session_token_hash, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            id,
            realm_id,
            user_id,
            session_token_hash,
            expires_at.to_rfc3339(),
            now.to_rfc3339()
        ],
    )?;
    Ok(Session {
        user_id: user_id.to_string(),
    })
}

pub fn get_session_by_token_hash(
    conn: &Connection,
    realm_id: &str,
    token_hash: &str,
) -> Result<Option<Session>> {
    let now = Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT user_id
         FROM sessions
         WHERE realm_id = ?1 AND session_token_hash = ?2 AND expires_at > ?3",
    )?;
    let mut rows = stmt.query_map(params![realm_id, token_hash, now], |row| {
        Ok(Session {
            user_id: row.get(0)?,
        })
    })?;
    match rows.next() {
        Some(s) => Ok(Some(s?)),
        None => Ok(None),
    }
}
