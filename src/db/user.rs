use crate::models::User;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

pub fn create_user(
    conn: &Connection,
    realm_id: &str,
    username: &str,
    email: &str,
    password_hash: &str,
) -> Result<User> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    conn.execute(
        "INSERT INTO users (id, realm_id, username, email, password_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            realm_id,
            username,
            email,
            password_hash,
            now.to_rfc3339(),
            now.to_rfc3339()
        ],
    )?;
    Ok(User {
        id,
        realm_id: realm_id.to_string(),
        username: username.to_string(),
        email: email.to_string(),
        password_hash: password_hash.to_string(),
        created_at: now,
        updated_at: now,
    })
}

pub fn list_users(conn: &Connection, realm_id: &str) -> Result<Vec<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, realm_id, username, email, password_hash, created_at, updated_at
         FROM users WHERE realm_id = ?1 ORDER BY username",
    )?;
    let rows = stmt.query_map(params![realm_id], |row| {
        let created_str: String = row.get(5)?;
        let updated_str: String = row.get(6)?;
        Ok(User {
            id: row.get(0)?,
            realm_id: row.get(1)?,
            username: row.get(2)?,
            email: row.get(3)?,
            password_hash: row.get(4)?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&updated_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
        })
    })?;
    let mut users = Vec::new();
    for u in rows {
        users.push(u?);
    }
    Ok(users)
}

pub fn get_user_by_username(
    conn: &Connection,
    realm_id: &str,
    username: &str,
) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, realm_id, username, email, password_hash, created_at, updated_at
         FROM users WHERE realm_id = ?1 AND username = ?2",
    )?;
    let mut rows = stmt.query_map(params![realm_id, username], |row| {
        let created_str: String = row.get(5)?;
        let updated_str: String = row.get(6)?;
        Ok(User {
            id: row.get(0)?,
            realm_id: row.get(1)?,
            username: row.get(2)?,
            email: row.get(3)?,
            password_hash: row.get(4)?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&updated_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
        })
    })?;
    match rows.next() {
        Some(u) => Ok(Some(u?)),
        None => Ok(None),
    }
}

pub fn get_user_by_id(conn: &Connection, user_id: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, realm_id, username, email, password_hash, created_at, updated_at
         FROM users WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![user_id], |row| {
        let created_str: String = row.get(5)?;
        let updated_str: String = row.get(6)?;
        Ok(User {
            id: row.get(0)?,
            realm_id: row.get(1)?,
            username: row.get(2)?,
            email: row.get(3)?,
            password_hash: row.get(4)?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&updated_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
        })
    })?;
    match rows.next() {
        Some(u) => Ok(Some(u?)),
        None => Ok(None),
    }
}

pub fn delete_user(conn: &Connection, realm_id: &str, username: &str) -> Result<bool> {
    let rows = conn.execute(
        "DELETE FROM users WHERE realm_id = ?1 AND username = ?2",
        params![realm_id, username],
    )?;
    Ok(rows > 0)
}

pub fn update_password(conn: &Connection, user_id: &str, new_hash: &str) -> Result<()> {
    let now = Utc::now();
    conn.execute(
        "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
        params![new_hash, now.to_rfc3339(), user_id],
    )?;
    Ok(())
}
