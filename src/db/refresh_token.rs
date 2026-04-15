use crate::models::RefreshToken;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

pub struct NewRefreshToken<'a> {
    pub realm_id: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub token_hash: &'a str,
    pub scopes: &'a str,
    pub nonce: Option<&'a str>,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Insert a new refresh token (storing the SHA-256 hash).
pub fn insert_refresh_token(conn: &Connection, token: &NewRefreshToken) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO refresh_tokens (id, realm_id, client_id, user_id, token_hash, scopes, nonce, expires_at, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
        params![
            id,
            token.realm_id,
            token.client_id,
            token.user_id,
            token.token_hash,
            token.scopes,
            token.nonce,
            token.expires_at.to_rfc3339(),
        ],
    )?;
    Ok(id)
}

/// Consume a refresh token: look it up by hash, revoke it, return it.
/// Returns None if not found, already revoked, or expired.
pub fn consume_refresh_token(conn: &Connection, token_hash: &str) -> Result<Option<RefreshToken>> {
    let now = Utc::now().to_rfc3339();

    let mut stmt = conn.prepare(
        "SELECT id, client_id, user_id, scopes, nonce
         FROM refresh_tokens
         WHERE token_hash = ?1 AND revoked = 0 AND expires_at > ?2",
    )?;
    let mut rows = stmt.query_map(params![token_hash, now], |row| {
        Ok(RefreshToken {
            id: row.get(0)?,
            client_id: row.get(1)?,
            user_id: row.get(2)?,
            scopes: row.get(3)?,
            nonce: row.get(4)?,
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

/// Revoke a refresh token by its hash. Returns true if a token was revoked.
pub fn revoke_refresh_token_by_hash(conn: &Connection, token_hash: &str) -> Result<bool> {
    let count = conn.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?1 AND revoked = 0",
        params![token_hash],
    )?;
    Ok(count > 0)
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

    fn token(
        realm_id: &str,
        client_id: &str,
        user_id: &str,
        token_hash: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> NewRefreshToken<'static> {
        // Leak strings to get 'static lifetimes — test-only convenience.
        NewRefreshToken {
            realm_id: Box::leak(realm_id.to_string().into_boxed_str()),
            client_id: Box::leak(client_id.to_string().into_boxed_str()),
            user_id: Box::leak(user_id.to_string().into_boxed_str()),
            token_hash: Box::leak(token_hash.to_string().into_boxed_str()),
            scopes: "openid",
            nonce: None,
            expires_at,
        }
    }

    #[test]
    fn insert_and_consume_refresh_token() {
        let (conn, realm_id, user_id) = setup();
        let expires = Utc::now() + Duration::days(30);
        insert_refresh_token(
            &conn,
            &token(&realm_id, "myapp", &user_id, "tokenhash", expires),
        )
        .unwrap();

        let consumed = consume_refresh_token(&conn, "tokenhash").unwrap().unwrap();
        assert_eq!(consumed.user_id, user_id);
        assert_eq!(consumed.client_id, "myapp");
    }

    #[test]
    fn consumed_token_cannot_be_reused() {
        let (conn, realm_id, user_id) = setup();
        let expires = Utc::now() + Duration::days(30);
        insert_refresh_token(&conn, &token(&realm_id, "app", &user_id, "once", expires)).unwrap();

        consume_refresh_token(&conn, "once").unwrap().unwrap();
        assert!(consume_refresh_token(&conn, "once").unwrap().is_none());
    }

    #[test]
    fn revoke_by_hash() {
        let (conn, realm_id, user_id) = setup();
        let expires = Utc::now() + Duration::days(30);
        insert_refresh_token(&conn, &token(&realm_id, "app", &user_id, "rev", expires)).unwrap();

        assert!(revoke_refresh_token_by_hash(&conn, "rev").unwrap());
        assert!(!revoke_refresh_token_by_hash(&conn, "rev").unwrap());
        assert!(consume_refresh_token(&conn, "rev").unwrap().is_none());
    }
}
