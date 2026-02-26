use crate::models::SigningKeyRecord;
use anyhow::Result;
use rusqlite::{params, Connection};

pub fn get_active_signing_key(
    conn: &Connection,
    realm_id: &str,
) -> Result<Option<SigningKeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT private_key_pem, public_key_pem, kid
         FROM signing_keys WHERE realm_id = ?1 AND active = 1 ORDER BY created_at DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![realm_id], |row| {
        Ok(SigningKeyRecord {
            private_key_pem: row.get(0)?,
            public_key_pem: row.get(1)?,
            kid: row.get(2)?,
        })
    })?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

pub fn get_all_active_keys(conn: &Connection, realm_id: &str) -> Result<Vec<SigningKeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT private_key_pem, public_key_pem, kid
         FROM signing_keys WHERE realm_id = ?1 AND active = 1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![realm_id], |row| {
        Ok(SigningKeyRecord {
            private_key_pem: row.get(0)?,
            public_key_pem: row.get(1)?,
            kid: row.get(2)?,
        })
    })?;
    let mut keys = Vec::new();
    for r in rows {
        keys.push(r?);
    }
    Ok(keys)
}
