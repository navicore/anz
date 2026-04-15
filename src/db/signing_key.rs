use crate::models::{SigningAlgorithm, SigningKeyRecord};
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, Row};
use uuid::Uuid;

// Key lifecycle:
// - Active (active = 1): used both for signing new tokens and for serving/verifying
//   outstanding tokens. Appears in JWKS.
// - Deactivated (active = 0): no longer used for signing, but still served in JWKS and
//   still accepted for verification so outstanding tokens remain valid until they expire.
// - Deleted: hard-removed from the database via delete_signing_key. Gone from JWKS and
//   verification — any tokens signed with this key fail immediately.
//
// Operator flow for safe key rotation: rotate-key (adds new active key) → wait for clients
// to pick up new key from JWKS → deactivate-key (stop signing with old key; verification of
// outstanding tokens continues) → wait for all outstanding tokens to expire → delete-key.

fn parse_signing_key_row(row: &Row) -> rusqlite::Result<SigningKeyRecord> {
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

/// Return a signing-eligible (active) key with the preferred algorithm for token issuance.
///
/// Preference order when a realm has keys of multiple algorithms: RS256 wins over EdDSA,
/// because RS256 is the OIDC lowest common denominator (required by Kubernetes and other
/// consumers). If a realm has only EdDSA keys, we return that.
pub fn get_preferred_signing_key(
    conn: &Connection,
    realm_id: &str,
) -> Result<Option<SigningKeyRecord>> {
    let all = get_signing_keys(conn, realm_id)?;
    let rs256 = all.iter().find(|k| k.algorithm == SigningAlgorithm::Rs256);
    if let Some(k) = rs256 {
        return Ok(Some(k.clone()));
    }
    Ok(all.into_iter().next())
}

/// Return all keys eligible for signing new tokens (active = 1).
pub fn get_signing_keys(conn: &Connection, realm_id: &str) -> Result<Vec<SigningKeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT private_key_pem, public_key_pem, kid, algorithm
         FROM signing_keys WHERE realm_id = ?1 AND active = 1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![realm_id], parse_signing_key_row)?;
    let mut keys = Vec::new();
    for r in rows {
        keys.push(r?);
    }
    Ok(keys)
}

/// Return every signing key stored for the realm — active and deactivated alike.
/// Used by JWKS (so consumers can verify outstanding tokens) and by token verification
/// paths (so a deactivated kid still verifies until operators hard-delete it).
pub fn get_all_keys(conn: &Connection, realm_id: &str) -> Result<Vec<SigningKeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT private_key_pem, public_key_pem, kid, algorithm
         FROM signing_keys WHERE realm_id = ?1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![realm_id], parse_signing_key_row)?;
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

/// Mark a signing key inactive. It stays in the DB so JWKS keeps serving its public
/// material and verification keeps accepting it — important for clients that cache JWKS
/// and for outstanding tokens signed with it. Use `delete_signing_key` after those tokens
/// have expired to hard-remove it.
pub fn deactivate_signing_key(conn: &Connection, realm_id: &str, kid: &str) -> Result<bool> {
    let rows = conn.execute(
        "UPDATE signing_keys SET active = 0 WHERE realm_id = ?1 AND kid = ?2 AND active = 1",
        params![realm_id, kid],
    )?;
    Ok(rows > 0)
}

/// Hard-delete a signing key. The key is removed from JWKS and from verification. Any
/// outstanding tokens signed with this key will fail. Operators should run this only
/// after the longest outstanding token lifetime has passed.
pub fn delete_signing_key(conn: &Connection, realm_id: &str, kid: &str) -> Result<bool> {
    let rows = conn.execute(
        "DELETE FROM signing_keys WHERE realm_id = ?1 AND kid = ?2",
        params![realm_id, kid],
    )?;
    Ok(rows > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::models::SigningAlgorithm;

    #[test]
    fn create_realm_with_rs256_creates_active_rs256_key() {
        let conn = db::open_in_memory().unwrap();
        let realm = db::realm::create_realm(&conn, "rsrealm", SigningAlgorithm::Rs256).unwrap();

        let signing = get_signing_keys(&conn, &realm.id).unwrap();
        assert_eq!(signing.len(), 1);
        assert_eq!(signing[0].algorithm, SigningAlgorithm::Rs256);
        assert!(signing[0].private_key_pem.contains("PRIVATE KEY"));
        assert!(signing[0].public_key_pem.contains("PUBLIC KEY"));
    }

    #[test]
    fn deactivated_key_stays_in_all_keys_but_not_signing() {
        let conn = db::open_in_memory().unwrap();
        let realm = db::realm::create_realm(&conn, "r", SigningAlgorithm::EdDsa).unwrap();
        let kid = get_signing_keys(&conn, &realm.id).unwrap()[0].kid.clone();

        assert!(deactivate_signing_key(&conn, &realm.id, &kid).unwrap());

        // Signing pool no longer contains it.
        assert!(get_signing_keys(&conn, &realm.id).unwrap().is_empty());
        // But verification pool (JWKS) still does.
        let all = get_all_keys(&conn, &realm.id).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].kid, kid);
    }

    #[test]
    fn deleted_key_is_gone_from_everything() {
        let conn = db::open_in_memory().unwrap();
        let realm = db::realm::create_realm(&conn, "r", SigningAlgorithm::EdDsa).unwrap();
        let kid = get_signing_keys(&conn, &realm.id).unwrap()[0].kid.clone();

        // Must deactivate before delete per the usual flow, though delete works regardless.
        deactivate_signing_key(&conn, &realm.id, &kid).unwrap();
        assert!(delete_signing_key(&conn, &realm.id, &kid).unwrap());

        assert!(get_signing_keys(&conn, &realm.id).unwrap().is_empty());
        assert!(get_all_keys(&conn, &realm.id).unwrap().is_empty());
    }

    #[test]
    fn preferred_signing_key_picks_rs256_when_both_present() {
        let conn = db::open_in_memory().unwrap();
        let realm = db::realm::create_realm(&conn, "r", SigningAlgorithm::EdDsa).unwrap();

        // Add an RS256 key alongside the initial EdDSA key (simulates rotation).
        let (priv_pem, pub_pem, kid) =
            crate::crypto::keys::generate_keypair(SigningAlgorithm::Rs256).unwrap();
        insert_signing_key(
            &conn,
            &NewSigningKey {
                realm_id: &realm.id,
                private_key_pem: &priv_pem,
                public_key_pem: &pub_pem,
                kid: &kid,
                algorithm: SigningAlgorithm::Rs256,
            },
        )
        .unwrap();

        let preferred = get_preferred_signing_key(&conn, &realm.id)
            .unwrap()
            .unwrap();
        assert_eq!(preferred.algorithm, SigningAlgorithm::Rs256);
    }
}
