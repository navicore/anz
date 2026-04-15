use crate::models::{SigningAlgorithm, SigningKeyRecord};
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, Row};
use uuid::Uuid;

fn parse_row(row: &Row) -> rusqlite::Result<SigningKeyRecord> {
    let alg_str: String = row.get(3)?;
    let algorithm = SigningAlgorithm::parse(&alg_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, e.into())
    })?;
    Ok(SigningKeyRecord {
        private_key_pem: row.get(0)?,
        public_key_pem: row.get(1)?,
        kid: row.get(2)?,
        algorithm,
    })
}

/// Return the active signing key with the preferred algorithm for token issuance.
///
/// Preference order when a realm has keys of multiple algorithms: RS256 wins over
/// EdDSA, because RS256 is the OIDC lowest common denominator (required by Kubernetes
/// and other consumers). If a realm has only EdDSA keys, we return that.
pub fn get_preferred_signing_key(
    conn: &Connection,
    realm_id: &str,
) -> Result<Option<SigningKeyRecord>> {
    // SQLite doesn't have ORDER BY with a CASE expression quite as ergonomic as
    // Postgres, so we just fetch all active keys and pick in Rust.
    let all = get_all_active_keys(conn, realm_id)?;
    let rs256 = all.iter().find(|k| k.algorithm == SigningAlgorithm::Rs256);
    if let Some(k) = rs256 {
        return Ok(Some(k.clone()));
    }
    Ok(all.into_iter().next())
}

pub fn get_all_active_keys(conn: &Connection, realm_id: &str) -> Result<Vec<SigningKeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT private_key_pem, public_key_pem, kid, algorithm
         FROM signing_keys WHERE realm_id = ?1 AND active = 1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![realm_id], parse_row)?;
    let mut keys = Vec::new();
    for r in rows {
        keys.push(r?);
    }
    Ok(keys)
}

pub struct NewSigningKey<'a> {
    pub realm_id: &'a str,
    pub private_key_pem: &'a str,
    pub public_key_pem: &'a str,
    pub kid: &'a str,
    pub algorithm: SigningAlgorithm,
}

pub fn insert_signing_key(conn: &Connection, key: &NewSigningKey) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    conn.execute(
        "INSERT INTO signing_keys (id, realm_id, private_key_pem, public_key_pem, kid, algorithm, created_at, active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
        params![
            id,
            key.realm_id,
            key.private_key_pem,
            key.public_key_pem,
            key.kid,
            key.algorithm.as_db_value(),
            now.to_rfc3339(),
        ],
    )?;
    Ok(id)
}

/// Mark a signing key inactive. It stays in the DB so JWKS can continue to serve its
/// public material (and old tokens keep verifying) until the operator deletes it.
pub fn deactivate_signing_key(conn: &Connection, realm_id: &str, kid: &str) -> Result<bool> {
    let rows = conn.execute(
        "UPDATE signing_keys SET active = 0 WHERE realm_id = ?1 AND kid = ?2 AND active = 1",
        params![realm_id, kid],
    )?;
    Ok(rows > 0)
}
