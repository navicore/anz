use crate::models::User;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, Row};
use uuid::Uuid;

macro_rules! select_cols {
    () => {
        "id, realm_id, username, email, password_hash, groups, created_at, updated_at"
    };
}

fn parse_user_row(row: &Row) -> rusqlite::Result<User> {
    let groups_json: String = row.get(5)?;
    let created_str: String = row.get(6)?;
    let updated_str: String = row.get(7)?;
    Ok(User {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        username: row.get(2)?,
        email: row.get(3)?,
        password_hash: row.get(4)?,
        groups: serde_json::from_str(&groups_json).unwrap_or_default(),
        created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
            .unwrap_or_default()
            .with_timezone(&Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_str)
            .unwrap_or_default()
            .with_timezone(&Utc),
    })
}

pub fn create_user(
    conn: &Connection,
    realm_id: &str,
    username: &str,
    email: &str,
    password_hash: &str,
    groups: &[String],
) -> Result<User> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let groups_json = serde_json::to_string(groups)?;
    conn.execute(
        "INSERT INTO users (id, realm_id, username, email, password_hash, groups, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            realm_id,
            username,
            email,
            password_hash,
            groups_json,
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
        groups: groups.to_vec(),
        created_at: now,
        updated_at: now,
    })
}

pub fn list_users(conn: &Connection, realm_id: &str) -> Result<Vec<User>> {
    let mut stmt = conn.prepare(concat!(
        "SELECT ",
        select_cols!(),
        " FROM users WHERE realm_id = ?1 ORDER BY username"
    ))?;
    let rows = stmt.query_map(params![realm_id], parse_user_row)?;
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
    let mut stmt = conn.prepare(concat!(
        "SELECT ",
        select_cols!(),
        " FROM users WHERE realm_id = ?1 AND username = ?2"
    ))?;
    let mut rows = stmt.query_map(params![realm_id, username], parse_user_row)?;
    match rows.next() {
        Some(u) => Ok(Some(u?)),
        None => Ok(None),
    }
}

pub fn get_user_by_id(conn: &Connection, user_id: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(concat!(
        "SELECT ",
        select_cols!(),
        " FROM users WHERE id = ?1"
    ))?;
    let mut rows = stmt.query_map(params![user_id], parse_user_row)?;
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
    let rows = conn.execute(
        "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
        params![new_hash, now.to_rfc3339(), user_id],
    )?;
    anyhow::ensure!(rows > 0, "user '{user_id}' not found");
    Ok(())
}

pub fn update_groups(conn: &Connection, user_id: &str, groups: &[String]) -> Result<()> {
    let now = Utc::now();
    let groups_json = serde_json::to_string(groups)?;
    let rows = conn.execute(
        "UPDATE users SET groups = ?1, updated_at = ?2 WHERE id = ?3",
        params![groups_json, now.to_rfc3339(), user_id],
    )?;
    anyhow::ensure!(rows > 0, "user '{user_id}' not found");
    Ok(())
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
    fn create_and_lookup_user() {
        let (conn, realm_id) = setup();
        let user = create_user(&conn, &realm_id, "alice", "a@b.com", "hash123", &[]).unwrap();
        assert_eq!(user.username, "alice");
        assert!(user.groups.is_empty());

        let found = get_user_by_username(&conn, &realm_id, "alice")
            .unwrap()
            .unwrap();
        assert_eq!(found.id, user.id);
        assert_eq!(found.email, "a@b.com");

        let by_id = get_user_by_id(&conn, &user.id).unwrap().unwrap();
        assert_eq!(by_id.username, "alice");
    }

    #[test]
    fn create_user_with_groups() {
        let (conn, realm_id) = setup();
        let groups = vec!["admin".to_string(), "dev".to_string()];
        let user = create_user(&conn, &realm_id, "bob", "b@b.com", "h", &groups).unwrap();
        assert_eq!(user.groups, groups);

        let found = get_user_by_id(&conn, &user.id).unwrap().unwrap();
        assert_eq!(found.groups, groups);
    }

    #[test]
    fn update_groups_changes_groups() {
        let (conn, realm_id) = setup();
        let user = create_user(&conn, &realm_id, "carol", "c@b.com", "h", &[]).unwrap();
        assert!(user.groups.is_empty());

        let new_groups = vec!["ops".to_string()];
        update_groups(&conn, &user.id, &new_groups).unwrap();

        let updated = get_user_by_id(&conn, &user.id).unwrap().unwrap();
        assert_eq!(updated.groups, new_groups);
    }

    #[test]
    fn list_and_delete_user() {
        let (conn, realm_id) = setup();
        create_user(&conn, &realm_id, "bob", "b@b.com", "h", &[]).unwrap();
        create_user(&conn, &realm_id, "carol", "c@b.com", "h", &[]).unwrap();

        let users = list_users(&conn, &realm_id).unwrap();
        assert_eq!(users.len(), 2);

        assert!(delete_user(&conn, &realm_id, "bob").unwrap());
        assert_eq!(list_users(&conn, &realm_id).unwrap().len(), 1);
    }

    #[test]
    fn update_password_changes_hash() {
        let (conn, realm_id) = setup();
        let user = create_user(&conn, &realm_id, "dave", "d@b.com", "old_hash", &[]).unwrap();
        update_password(&conn, &user.id, "new_hash").unwrap();

        let updated = get_user_by_id(&conn, &user.id).unwrap().unwrap();
        assert_eq!(updated.password_hash, "new_hash");
    }

    #[test]
    fn duplicate_username_fails() {
        let (conn, realm_id) = setup();
        create_user(&conn, &realm_id, "alice", "a@b.com", "h", &[]).unwrap();
        assert!(create_user(&conn, &realm_id, "alice", "a2@b.com", "h", &[]).is_err());
    }
}
