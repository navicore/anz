use crate::crypto::keys::generate_ed25519_keypair;
use crate::models::Realm;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

/// Create a realm and auto-generate an Ed25519 signing key.
pub fn create_realm(conn: &Connection, name: &str) -> Result<Realm> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    conn.execute(
        "INSERT INTO realms (id, name, created_at) VALUES (?1, ?2, ?3)",
        params![id, name, now.to_rfc3339()],
    )?;

    // Auto-generate signing key for the realm
    let (private_pem, public_pem, kid) = generate_ed25519_keypair()?;
    let key_id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO signing_keys (id, realm_id, private_key_pem, public_key_pem, kid, created_at, active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        params![key_id, id, private_pem, public_pem, kid, now.to_rfc3339()],
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
