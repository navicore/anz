use crate::models::{Session, SessionInfo};
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

pub fn cleanup_expired_sessions(conn: &Connection) -> Result<u64> {
    let now = Utc::now().to_rfc3339();
    let count = conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])?;
    Ok(count as u64)
}

pub fn list_sessions(conn: &Connection, realm_id: &str, user_id: &str) -> Result<Vec<SessionInfo>> {
    let now = Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT id, created_at, expires_at
         FROM sessions
         WHERE realm_id = ?1 AND user_id = ?2 AND expires_at > ?3
         ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![realm_id, user_id, now], |row| {
        Ok(SessionInfo {
            id: row.get(0)?,
            created_at: row.get(1)?,
            expires_at: row.get(2)?,
        })
    })?;
    let mut sessions = Vec::new();
    for row in rows {
        sessions.push(row?);
    }
    Ok(sessions)
}

pub fn revoke_user_sessions(conn: &Connection, realm_id: &str, user_id: &str) -> Result<u64> {
    let count = conn.execute(
        "DELETE FROM sessions WHERE realm_id = ?1 AND user_id = ?2",
        params![realm_id, user_id],
    )?;
    Ok(count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use chrono::Duration;

    fn setup() -> (Connection, String, String) {
        let conn = db::open_in_memory().unwrap();
        let realm =
            db::realm::create_realm(&conn, "test", crate::models::SigningAlgorithm::EdDsa).unwrap();
        let user =
            db::user::create_user(&conn, &realm.id, "alice", "a@b.com", "hash", &[]).unwrap();
        (conn, realm.id, user.id)
    }

    #[test]
    fn create_and_get_session() {
        let (conn, realm_id, user_id) = setup();
        let expires = Utc::now() + Duration::hours(24);
        create_session(&conn, &realm_id, &user_id, "sessionhash", expires).unwrap();

        let found = get_session_by_token_hash(&conn, &realm_id, "sessionhash")
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id, user_id);
    }

    #[test]
    fn expired_session_not_found() {
        let (conn, realm_id, user_id) = setup();
        let expires = Utc::now() - Duration::hours(1);
        create_session(&conn, &realm_id, &user_id, "oldhash", expires).unwrap();

        assert!(get_session_by_token_hash(&conn, &realm_id, "oldhash")
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_and_revoke_sessions() {
        let (conn, realm_id, user_id) = setup();
        let expires = Utc::now() + Duration::hours(24);
        create_session(&conn, &realm_id, &user_id, "s1", expires).unwrap();
        create_session(&conn, &realm_id, &user_id, "s2", expires).unwrap();

        let sessions = list_sessions(&conn, &realm_id, &user_id).unwrap();
        assert_eq!(sessions.len(), 2);

        let revoked = revoke_user_sessions(&conn, &realm_id, &user_id).unwrap();
        assert_eq!(revoked, 2);
        assert!(list_sessions(&conn, &realm_id, &user_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cleanup_removes_expired() {
        let (conn, realm_id, user_id) = setup();
        create_session(
            &conn,
            &realm_id,
            &user_id,
            "active",
            Utc::now() + Duration::hours(24),
        )
        .unwrap();
        create_session(
            &conn,
            &realm_id,
            &user_id,
            "dead",
            Utc::now() - Duration::hours(1),
        )
        .unwrap();

        let cleaned = cleanup_expired_sessions(&conn).unwrap();
        assert_eq!(cleaned, 1);
        assert_eq!(list_sessions(&conn, &realm_id, &user_id).unwrap().len(), 1);
    }
}
