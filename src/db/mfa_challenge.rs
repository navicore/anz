//! Pending second-step authentication challenges.
//!
//! Created after a successful password step when MFA is required, consumed when
//! the user submits a valid TOTP or recovery code. The challenge token issued to
//! the browser is high-entropy random; only its SHA-256 hash is stored — same
//! pattern as auth codes, refresh tokens, and session tokens.

use crate::models::MfaChallenge;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

pub fn create(
    conn: &Connection,
    challenge_token_hash: &str,
    user_id: &str,
    challenge_state: &str,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO mfa_challenges (challenge_token_hash, user_id, challenge_state, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            challenge_token_hash,
            user_id,
            challenge_state,
            expires_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Look up a challenge by its token hash. Does NOT consume — caller decides
/// whether to delete (success) or leave (allow retries within rate limits).
pub fn get(conn: &Connection, challenge_token_hash: &str) -> Result<Option<MfaChallenge>> {
    let now = Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT user_id, challenge_state
         FROM mfa_challenges
         WHERE challenge_token_hash = ?1 AND expires_at > ?2",
    )?;
    let mut rows = stmt.query_map(params![challenge_token_hash, now], |row| {
        Ok(MfaChallenge {
            user_id: row.get(0)?,
            challenge_state: row.get(1)?,
        })
    })?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

pub fn delete(conn: &Connection, challenge_token_hash: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM mfa_challenges WHERE challenge_token_hash = ?1",
        params![challenge_token_hash],
    )?;
    Ok(())
}

/// Best-effort cleanup of expired challenge rows. Safe to call periodically
/// (e.g. from `anz session cleanup`); not strictly required since `get` already
/// filters by expiry.
#[allow(dead_code)] // utility function — called from tests and available for future CLI wiring
pub fn cleanup_expired(conn: &Connection) -> Result<u64> {
    let now = Utc::now().to_rfc3339();
    let count = conn.execute(
        "DELETE FROM mfa_challenges WHERE expires_at <= ?1",
        params![now],
    )?;
    Ok(count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::models::SigningAlgorithm;
    use chrono::Duration;

    fn setup() -> (Connection, String) {
        let conn = db::open_in_memory().unwrap();
        let realm = db::realm::create_realm(&conn, "r", SigningAlgorithm::EdDsa).unwrap();
        let user = db::user::create_user(&conn, &realm.id, "u", "u@x", "h", &[]).unwrap();
        (conn, user.id)
    }

    #[test]
    fn create_get_delete() {
        let (conn, user_id) = setup();
        let exp = Utc::now() + Duration::minutes(5);
        create(&conn, "h1", &user_id, "params", exp).unwrap();

        let got = get(&conn, "h1").unwrap().unwrap();
        assert_eq!(got.user_id, user_id);
        assert_eq!(got.challenge_state, "params");

        delete(&conn, "h1").unwrap();
        assert!(get(&conn, "h1").unwrap().is_none());
    }

    #[test]
    fn expired_challenge_returns_none() {
        let (conn, user_id) = setup();
        let exp = Utc::now() - Duration::minutes(1);
        create(&conn, "old", &user_id, "p", exp).unwrap();
        assert!(get(&conn, "old").unwrap().is_none());
    }

    #[test]
    fn cleanup_removes_expired_only() {
        let (conn, user_id) = setup();
        create(
            &conn,
            "alive",
            &user_id,
            "p",
            Utc::now() + Duration::minutes(5),
        )
        .unwrap();
        create(
            &conn,
            "dead",
            &user_id,
            "p",
            Utc::now() - Duration::minutes(1),
        )
        .unwrap();

        let removed = cleanup_expired(&conn).unwrap();
        assert_eq!(removed, 1);
        assert!(get(&conn, "alive").unwrap().is_some());
    }
}
