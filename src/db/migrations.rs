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
    )
}
