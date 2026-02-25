pub mod auth_code;
pub mod client;
pub mod migrations;
pub mod realm;
pub mod refresh_token;
pub mod session;
pub mod signing_key;
pub mod user;

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub fn open_database(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;

    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    migrations::run_migrations(&conn)?;

    Ok(conn)
}
