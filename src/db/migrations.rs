use rusqlite::Connection;

pub fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS realms (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS signing_keys (
            id              TEXT PRIMARY KEY,
            realm_id        TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
            private_key_pem TEXT NOT NULL,
            public_key_pem  TEXT NOT NULL,
            kid             TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            active          INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            realm_id      TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
            username      TEXT NOT NULL,
            email         TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            UNIQUE(realm_id, username)
        );

        CREATE TABLE IF NOT EXISTS clients (
            id             TEXT PRIMARY KEY,
            realm_id       TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
            client_id      TEXT NOT NULL,
            redirect_uris  TEXT NOT NULL DEFAULT '[]',
            allowed_scopes TEXT NOT NULL DEFAULT '[\"openid\", \"profile\", \"email\"]',
            created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            UNIQUE(realm_id, client_id)
        );

        CREATE TABLE IF NOT EXISTS authorization_codes (
            id             TEXT PRIMARY KEY,
            realm_id       TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
            client_id      TEXT NOT NULL,
            user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash      TEXT NOT NULL UNIQUE,
            redirect_uri   TEXT NOT NULL,
            scopes         TEXT NOT NULL DEFAULT 'openid',
            code_challenge TEXT NOT NULL,
            expires_at     TEXT NOT NULL,
            used           INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id         TEXT PRIMARY KEY,
            realm_id   TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
            client_id  TEXT NOT NULL,
            user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            scopes     TEXT NOT NULL DEFAULT 'openid',
            expires_at TEXT NOT NULL,
            revoked    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id                 TEXT PRIMARY KEY,
            realm_id           TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
            user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            session_token_hash TEXT NOT NULL UNIQUE,
            expires_at         TEXT NOT NULL,
            created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        ",
    )?;

    // Additive migrations for SSO support
    // SQLite ignores ADD COLUMN if it already exists when using IF NOT EXISTS isn't available,
    // so we check the schema first.
    add_column_if_missing(conn, "clients", "client_secret_hash", "TEXT")?;
    add_column_if_missing(conn, "users", "groups", "TEXT NOT NULL DEFAULT '[]'")?;
    add_column_if_missing(conn, "authorization_codes", "nonce", "TEXT")?;
    add_column_if_missing(conn, "refresh_tokens", "nonce", "TEXT")?;
    // Existing keys were all Ed25519 (EdDSA); default new column accordingly so
    // existing realms keep working without manual backfill.
    add_column_if_missing(
        conn,
        "signing_keys",
        "algorithm",
        "TEXT NOT NULL DEFAULT 'EdDSA'",
    )?;

    Ok(())
}

/// Check that a string is a safe SQL identifier (alphanumeric and underscores only).
/// Table and column names cannot be parameterized in SQLite, so we must validate
/// before interpolating into SQL strings.
fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Add a column to a table if it doesn't already exist.
///
/// SAFETY: `table` and `column` are validated as safe identifiers. `column_def` is
/// interpolated directly into SQL and MUST be a hardcoded string literal — never
/// pass user-controlled or dynamic input as `column_def`.
fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    column_def: &str,
) -> rusqlite::Result<()> {
    if column_def.contains(';') || column_def.contains("--") {
        return Err(rusqlite::Error::InvalidParameterName(
            "column_def contains unsafe SQL characters".to_string(),
        ));
    }
    if !is_safe_identifier(table) || !is_safe_identifier(column) {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "unsafe identifier: table={table}, column={column}"
        )));
    }

    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql)?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    let has_column = columns.iter().any(|name| name == column);

    if !has_column {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {column_def};"
        ))?;
    }
    Ok(())
}
