use crate::crypto::keys::generate_keypair;
use crate::db::signing_key::{insert_signing_key, NewSigningKey};
use crate::models::{Realm, SigningAlgorithm};
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

/// Create a realm and auto-generate a signing key using the given algorithm.
/// RS256 is the recommended default for broad OIDC client compatibility (Kubernetes, etc.).
pub fn create_realm(conn: &Connection, name: &str, alg: SigningAlgorithm) -> Result<Realm> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    conn.execute(
        "INSERT INTO realms (id, name, created_at) VALUES (?1, ?2, ?3)",
        params![id, name, now.to_rfc3339()],
    )?;

    let (private_pem, public_pem, kid) = generate_keypair(alg)?;
    insert_signing_key(
        conn,
        &NewSigningKey {
            realm_id: &id,
            private_key_pem: &private_pem,
            public_key_pem: &public_pem,
            kid: &kid,
            algorithm: alg,
        },
    )?;

    Ok(Realm {
        id,
        name: name.to_string(),
        created_at: now,
    })
}

pub fn list_realms(conn: &Connection) -> Result<Vec<Realm>> {
    let mut stmt = conn.prepare("SELECT id, name, created_at FROM realms ORDER BY name")?;
    let rows = stmt.query_map([], |row| {
        let created_str: String = row.get(2)?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
            .unwrap_or_default()
            .with_timezone(&Utc);
        Ok(Realm {
            id: row.get(0)?,
            name: row.get(1)?,
            created_at,
        })
    })?;
    let mut realms = Vec::new();
    for r in rows {
        realms.push(r?);
    }
    Ok(realms)
}

pub fn get_realm_by_name(conn: &Connection, name: &str) -> Result<Option<Realm>> {
    let mut stmt = conn.prepare("SELECT id, name, created_at FROM realms WHERE name = ?1")?;
    let mut rows = stmt.query_map(params![name], |row| {
        let created_str: String = row.get(2)?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
            .unwrap_or_default()
            .with_timezone(&Utc);
        Ok(Realm {
            id: row.get(0)?,
            name: row.get(1)?,
            created_at,
        })
    })?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

pub fn delete_realm(conn: &Connection, name: &str) -> Result<bool> {
    let rows = conn.execute("DELETE FROM realms WHERE name = ?1", params![name])?;
    Ok(rows > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn create_and_get_realm() {
        let conn = db::open_in_memory().unwrap();
        let realm =
            create_realm(&conn, "testrealm", crate::models::SigningAlgorithm::EdDsa).unwrap();
        assert_eq!(realm.name, "testrealm");

        let found = get_realm_by_name(&conn, "testrealm").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, realm.id);
    }

    #[test]
    fn list_realms_returns_created() {
        let conn = db::open_in_memory().unwrap();
        create_realm(&conn, "alpha", crate::models::SigningAlgorithm::EdDsa).unwrap();
        create_realm(&conn, "beta", crate::models::SigningAlgorithm::EdDsa).unwrap();

        let realms = list_realms(&conn).unwrap();
        assert_eq!(realms.len(), 2);
        assert_eq!(realms[0].name, "alpha");
        assert_eq!(realms[1].name, "beta");
    }

    #[test]
    fn delete_realm_cascades() {
        let conn = db::open_in_memory().unwrap();
        let realm = create_realm(&conn, "doomed", crate::models::SigningAlgorithm::EdDsa).unwrap();

        db::user::create_user(&conn, &realm.id, "alice", "a@b.com", "hash", &[]).unwrap();
        assert!(delete_realm(&conn, "doomed").unwrap());
        assert!(get_realm_by_name(&conn, "doomed").unwrap().is_none());
        assert!(db::user::list_users(&conn, &realm.id).unwrap().is_empty());
    }

    #[test]
    fn missing_realm_returns_none() {
        let conn = db::open_in_memory().unwrap();
        assert!(get_realm_by_name(&conn, "nope").unwrap().is_none());
    }
}
