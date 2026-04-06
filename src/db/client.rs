use crate::models::Client;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, Row};
use uuid::Uuid;

fn parse_client_row(row: &Row) -> rusqlite::Result<Client> {
    let uris_json: String = row.get(3)?;
    let scopes_json: String = row.get(4)?;
    let secret_hash: Option<String> = row.get(5)?;
    let created_str: String = row.get(6)?;

    let redirect_uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
    let allowed_scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
        .unwrap_or_default()
        .with_timezone(&Utc);

    Ok(Client {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        client_id: row.get(2)?,
        redirect_uris,
        allowed_scopes,
        client_secret_hash: secret_hash,
        created_at,
    })
}

macro_rules! select_cols {
    () => {
        "id, realm_id, client_id, redirect_uris, allowed_scopes, client_secret_hash, created_at"
    };
}

pub fn create_client(
    conn: &Connection,
    realm_id: &str,
    client_id: &str,
    redirect_uris: &[String],
    client_secret_hash: Option<&str>,
) -> Result<Client> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let uris_json = serde_json::to_string(redirect_uris)?;
    let scopes_json = serde_json::to_string(&["openid", "profile", "email"])?;

    conn.execute(
        "INSERT INTO clients (id, realm_id, client_id, redirect_uris, allowed_scopes, client_secret_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            realm_id,
            client_id,
            uris_json,
            scopes_json,
            client_secret_hash,
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
        client_secret_hash: client_secret_hash.map(|s| s.to_string()),
        created_at: now,
    })
}

pub fn list_clients(conn: &Connection, realm_id: &str) -> Result<Vec<Client>> {
    let mut stmt = conn.prepare(concat!(
        "SELECT ",
        select_cols!(),
        " FROM clients WHERE realm_id = ?1 ORDER BY client_id"
    ))?;
    let rows = stmt.query_map(params![realm_id], parse_client_row)?;
    let mut clients = Vec::new();
    for r in rows {
        clients.push(r?);
    }
    Ok(clients)
}

pub fn get_client_by_client_id(
    conn: &Connection,
    realm_id: &str,
    client_id: &str,
) -> Result<Option<Client>> {
    let mut stmt = conn.prepare(concat!(
        "SELECT ",
        select_cols!(),
        " FROM clients WHERE realm_id = ?1 AND client_id = ?2"
    ))?;
    let mut rows = stmt.query_map(params![realm_id, client_id], parse_client_row)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn setup() -> (rusqlite::Connection, String) {
        let conn = db::open_in_memory().unwrap();
        let realm = db::realm::create_realm(&conn, "test").unwrap();
        (conn, realm.id)
    }

    #[test]
    fn create_and_get_client() {
        let (conn, realm_id) = setup();
        let uris = vec!["http://localhost/cb".to_string()];
        let client = create_client(&conn, &realm_id, "myapp", &uris, None).unwrap();
        assert_eq!(client.client_id, "myapp");
        assert_eq!(client.redirect_uris, uris);
        assert!(client.client_secret_hash.is_none());

        let found = get_client_by_client_id(&conn, &realm_id, "myapp")
            .unwrap()
            .unwrap();
        assert_eq!(found.client_id, "myapp");
    }

    #[test]
    fn create_client_with_secret() {
        let (conn, realm_id) = setup();
        let client = create_client(&conn, &realm_id, "secure", &[], Some("hashed_secret")).unwrap();
        assert_eq!(client.client_secret_hash.as_deref(), Some("hashed_secret"));

        let found = get_client_by_client_id(&conn, &realm_id, "secure")
            .unwrap()
            .unwrap();
        assert_eq!(found.client_secret_hash.as_deref(), Some("hashed_secret"));
    }

    #[test]
    fn list_and_delete_client() {
        let (conn, realm_id) = setup();
        create_client(&conn, &realm_id, "app1", &[], None).unwrap();
        create_client(&conn, &realm_id, "app2", &[], None).unwrap();
        assert_eq!(list_clients(&conn, &realm_id).unwrap().len(), 2);

        assert!(delete_client(&conn, &realm_id, "app1").unwrap());
        assert_eq!(list_clients(&conn, &realm_id).unwrap().len(), 1);
    }

    #[test]
    fn duplicate_client_id_fails() {
        let (conn, realm_id) = setup();
        create_client(&conn, &realm_id, "dup", &[], None).unwrap();
        assert!(create_client(&conn, &realm_id, "dup", &[], None).is_err());
    }
}
