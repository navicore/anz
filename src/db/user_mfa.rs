//! TOTP secret + recovery codes per user.
//!
//! Recovery codes are stored as SHA-256 hashes — same pattern as auth codes,
//! refresh tokens, and session tokens. The user only ever sees them once,
//! at enrollment time. Marked used (not deleted) so we keep an audit trail.

use crate::models::UserMfa;
use anyhow::Result;
use rusqlite::{params, Connection};
use uuid::Uuid;

/// Enroll a user in MFA. Replaces any existing enrollment for the user (caller
/// should check or call disable first if it wants to be strict). Recovery codes
/// are passed pre-hashed.
pub fn enroll(
    conn: &Connection,
    user_id: &str,
    secret_base32: &str,
    recovery_code_hashes: &[String],
) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    let result = enroll_inner(conn, user_id, secret_base32, recovery_code_hashes);
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn enroll_inner(
    conn: &Connection,
    user_id: &str,
    secret_base32: &str,
    recovery_code_hashes: &[String],
) -> Result<()> {
    conn.execute("DELETE FROM user_mfa WHERE user_id = ?1", params![user_id])?;
    conn.execute(
        "DELETE FROM user_mfa_recovery_codes WHERE user_id = ?1",
        params![user_id],
    )?;
    conn.execute(
        "INSERT INTO user_mfa (user_id, secret_base32) VALUES (?1, ?2)",
        params![user_id, secret_base32],
    )?;
    for hash in recovery_code_hashes {
        conn.execute(
            "INSERT INTO user_mfa_recovery_codes (id, user_id, code_hash) VALUES (?1, ?2, ?3)",
            params![Uuid::new_v4().to_string(), user_id, hash],
        )?;
    }
    Ok(())
}

pub fn get(conn: &Connection, user_id: &str) -> Result<Option<UserMfa>> {
    let mut stmt = conn.prepare(
        "SELECT user_id, secret_base32, last_used_step FROM user_mfa WHERE user_id = ?1",
    )?;
    let mut rows = stmt.query_map(params![user_id], |row| {
        Ok(UserMfa {
            user_id: row.get(0)?,
            secret_base32: row.get(1)?,
            last_used_step: row.get(2)?,
        })
    })?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

/// Disable MFA for a user — purges the secret and all recovery codes.
pub fn disable(conn: &Connection, user_id: &str) -> Result<bool> {
    conn.execute_batch("BEGIN")?;
    let result: Result<bool> = (|| {
        let mfa_rows = conn.execute("DELETE FROM user_mfa WHERE user_id = ?1", params![user_id])?;
        conn.execute(
            "DELETE FROM user_mfa_recovery_codes WHERE user_id = ?1",
            params![user_id],
        )?;
        Ok(mfa_rows > 0)
    })();
    match result {
        Ok(v) => {
            conn.execute_batch("COMMIT")?;
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Atomically advance `last_used_step` if `step` is strictly greater than the
/// currently-stored value. Returns true if the step was accepted (no replay),
/// false if the supplied step has already been used (replay — reject).
///
/// This is the server-side half of TOTP replay protection: a valid TOTP code
/// matches one specific step; once we've accepted step N, any subsequent
/// submission matching step ≤ N is a replay, even if the clock still considers
/// the code mathematically valid.
pub fn advance_step(conn: &Connection, user_id: &str, step: i64) -> Result<bool> {
    let rows = conn.execute(
        "UPDATE user_mfa SET last_used_step = ?2
         WHERE user_id = ?1 AND ?2 > last_used_step",
        params![user_id, step],
    )?;
    Ok(rows > 0)
}

/// Try to consume a recovery code by its hash. Returns true if a matching
/// unused code was found and marked used. Single-use semantics — once true is
/// returned for a given hash, future calls return false.
pub fn consume_recovery_code(conn: &Connection, user_id: &str, code_hash: &str) -> Result<bool> {
    let rows = conn.execute(
        "UPDATE user_mfa_recovery_codes SET used = 1
         WHERE user_id = ?1 AND code_hash = ?2 AND used = 0",
        params![user_id, code_hash],
    )?;
    Ok(rows > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::models::SigningAlgorithm;

    fn setup() -> (Connection, String) {
        let conn = db::open_in_memory().unwrap();
        let realm = db::realm::create_realm(&conn, "test", SigningAlgorithm::EdDsa).unwrap();
        let user =
            db::user::create_user(&conn, &realm.id, "alice", "a@b.com", "hash", &[]).unwrap();
        (conn, user.id)
    }

    #[test]
    fn enroll_and_get() {
        let (conn, user_id) = setup();
        enroll(
            &conn,
            &user_id,
            "JBSWY3DPEHPK3PXP",
            &["h1".into(), "h2".into()],
        )
        .unwrap();

        let got = get(&conn, &user_id).unwrap().unwrap();
        assert_eq!(got.user_id, user_id);
        assert_eq!(got.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(got.last_used_step, 0);
    }

    #[test]
    fn advance_step_rejects_replay() {
        let (conn, user_id) = setup();
        enroll(&conn, &user_id, "S", &[]).unwrap();

        assert!(advance_step(&conn, &user_id, 100).unwrap());
        assert_eq!(get(&conn, &user_id).unwrap().unwrap().last_used_step, 100);

        // Same step → replay, rejected.
        assert!(!advance_step(&conn, &user_id, 100).unwrap());
        // Earlier step → replay (skew neighbor already used), rejected.
        assert!(!advance_step(&conn, &user_id, 99).unwrap());
        // Later step → accepted.
        assert!(advance_step(&conn, &user_id, 101).unwrap());
        assert_eq!(get(&conn, &user_id).unwrap().unwrap().last_used_step, 101);
    }

    #[test]
    fn advance_step_noop_for_unknown_user() {
        let conn = db::open_in_memory().unwrap();
        assert!(!advance_step(&conn, "nobody", 1).unwrap());
    }

    #[test]
    fn disable_clears_everything() {
        let (conn, user_id) = setup();
        enroll(&conn, &user_id, "S", &["h1".into()]).unwrap();
        assert!(disable(&conn, &user_id).unwrap());
        assert!(get(&conn, &user_id).unwrap().is_none());
        // Recovery code is gone too.
        assert!(!consume_recovery_code(&conn, &user_id, "h1").unwrap());
    }

    #[test]
    fn recovery_code_single_use() {
        let (conn, user_id) = setup();
        enroll(&conn, &user_id, "S", &["h1".into(), "h2".into()]).unwrap();
        assert!(consume_recovery_code(&conn, &user_id, "h1").unwrap());
        // Second use of the same code fails.
        assert!(!consume_recovery_code(&conn, &user_id, "h1").unwrap());
        // Other code still works.
        assert!(consume_recovery_code(&conn, &user_id, "h2").unwrap());
    }

    #[test]
    fn enroll_replaces_prior_secret_and_codes() {
        let (conn, user_id) = setup();
        enroll(&conn, &user_id, "OLD", &["old1".into()]).unwrap();
        enroll(&conn, &user_id, "NEW", &["new1".into()]).unwrap();

        assert_eq!(get(&conn, &user_id).unwrap().unwrap().secret_base32, "NEW");
        assert!(!consume_recovery_code(&conn, &user_id, "old1").unwrap());
        assert!(consume_recovery_code(&conn, &user_id, "new1").unwrap());
    }
}
