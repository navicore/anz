use crate::models::Client;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

pub fn create_client(
    conn: &Connection,
    realm_id: &str,
    client_id: &str,
    redirect_uris: &[String],
) -> Result<Client> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let uris_json = serde_json::to_string(redirect_uris)?;
    let scopes_json = serde_json::to_string(&["openid", "profile", "email"])?;

    conn.execute(
        "INSERT INTO clients (id, realm_id, client_id, redirect_uris, allowed_scopes, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            id,
            realm_id,
            client_id,
            uris_json,
            scopes_json,
            now.to_rfc3339()
        ],
    )?;

    Ok(Client {
        id,
        realm_id: realm_id.to_string(),
        client_id: client_id.to_string(),
        redirect_uris: redirect_uris.to_vec(),
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        created_at: now,
    })
}

pub fn list_clients(conn: &Connection, realm_id: &str) -> Result<Vec<Client>> {
    let mut stmt = conn.prepare(
        "SELECT id, realm_id, client_id, redirect_uris, allowed_scopes, created_at
         FROM clients WHERE realm_id = ?1 ORDER BY client_id",
    )?;
    let rows = stmt.query_map(params![realm_id], |row| {
        let uris_json: String = row.get(3)?;
        let scopes_json: String = row.get(4)?;
        let created_str: String = row.get(5)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            uris_json,
            scopes_json,
            created_str,
        ))
    })?;
    let mut clients = Vec::new();
    for r in rows {
        let (id, realm_id, client_id, uris_json, scopes_json, created_str) = r?;
        let redirect_uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
        let allowed_scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
            .unwrap_or_default()
            .with_timezone(&Utc);
        clients.push(Client {
            id,
            realm_id,
            client_id,
            redirect_uris,
            allowed_scopes,
            created_at,
        });
    }
    Ok(clients)
}

pub fn get_client_by_client_id(
    conn: &Connection,
    realm_id: &str,
    client_id: &str,
) -> Result<Option<Client>> {
    let mut stmt = conn.prepare(
        "SELECT id, realm_id, client_id, redirect_uris, allowed_scopes, created_at
         FROM clients WHERE realm_id = ?1 AND client_id = ?2",
    )?;
    let mut rows = stmt.query_map(params![realm_id, client_id], |row| {
        let uris_json: String = row.get(3)?;
        let scopes_json: String = row.get(4)?;
        let created_str: String = row.get(5)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            uris_json,
            scopes_json,
            created_str,
        ))
    })?;
    match rows.next() {
        Some(r) => {
            let (id, realm_id, client_id, uris_json, scopes_json, created_str) = r?;
            let redirect_uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
            let allowed_scopes: Vec<String> =
                serde_json::from_str(&scopes_json).unwrap_or_default();
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc);
            Ok(Some(Client {
                id,
                realm_id,
                client_id,
                redirect_uris,
                allowed_scopes,
                created_at,
            }))
        }
        None => Ok(None),
    }
}

pub fn delete_client(conn: &Connection, realm_id: &str, client_id: &str) -> Result<bool> {
    let rows = conn.execute(
        "DELETE FROM clients WHERE realm_id = ?1 AND client_id = ?2",
        params![realm_id, client_id],
    )?;
    Ok(rows > 0)
}
