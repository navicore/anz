use crate::models::SigningKeyRecord;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};

pub fn get_active_signing_key(
    conn: &Connection,
    realm_id: &str,
) -> Result<Option<SigningKeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, realm_id, private_key_pem, public_key_pem, kid, created_at, active
         FROM signing_keys WHERE realm_id = ?1 AND active = 1 ORDER BY created_at DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![realm_id], |row| {
        let created_str: String = row.get(5)?;
        Ok(SigningKeyRecord {
            id: row.get(0)?,
            realm_id: row.get(1)?,
            private_key_pem: row.get(2)?,
            public_key_pem: row.get(3)?,
            kid: row.get(4)?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            active: row.get(6)?,
        })
    })?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

pub fn get_all_active_keys(conn: &Connection, realm_id: &str) -> Result<Vec<SigningKeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, realm_id, private_key_pem, public_key_pem, kid, created_at, active
         FROM signing_keys WHERE realm_id = ?1 AND active = 1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![realm_id], |row| {
        let created_str: String = row.get(5)?;
        Ok(SigningKeyRecord {
            id: row.get(0)?,
            realm_id: row.get(1)?,
            private_key_pem: row.get(2)?,
            public_key_pem: row.get(3)?,
            kid: row.get(4)?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            active: row.get(6)?,
        })
    })?;
    let mut keys = Vec::new();
    for r in rows {
        keys.push(r?);
    }
    Ok(keys)
}
