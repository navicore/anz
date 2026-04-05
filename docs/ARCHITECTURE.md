# Architecture

## Context & Scope

anz is a minimal OIDC provider for personal web applications. It is a single Rust binary backed by an embedded SQLite database. It implements the OpenID Connect authorization code flow with PKCE so that small, self-hosted apps can authenticate users without depending on external identity services.

**System boundary:** anz runs behind a TLS-terminating reverse proxy (nginx, caddy). It has no outbound network dependencies — no federation, no external APIs, no remote databases. Client applications interact with it over standard OIDC endpoints; operators manage it through CLI commands.

**Actors:**
- **End users** — authenticate via a server-rendered login form
- **Client applications** — registered OAuth2 clients that redirect users to anz and exchange authorization codes for tokens
- **Operator** — single admin who manages realms, users, and clients via the CLI

**Bounded context:** There is one domain — identity and authentication. Realms provide tenant isolation within it (separate users, clients, keys, tokens).

## Solution Strategy

- **Rust + axum** — async HTTP server, single binary, no runtime dependencies
- **SQLite (rusqlite, bundled)** — single-file embedded database with WAL mode; no external DB to operate
- **Ed25519 (ed25519-dalek)** — per-realm signing keys for JWTs; compact, fast, no RSA complexity
- **Argon2id** — password hashing with timing-oracle prevention on unknown usernames
- **Askama** — compile-time HTML templates for the login form; no JavaScript frameworks
- **clap** — CLI for all admin operations; no admin web UI

These choices optimize for operational simplicity: one binary, one file, no external services.

## Building Blocks

### Modules

| Module | Responsibility |
|---|---|
| `cli/` | Parses commands (clap) and dispatches to `serve`, `realm`, `user`, `client`, `session` subcommands |
| `server/` | Axum router and handlers for all OIDC endpoints: authorize, token, jwks, discovery, userinfo, password, revoke, static_files |
| `db/` | SQLite schema (8 tables), migrations, and CRUD for realms, users, clients, auth codes, refresh tokens, sessions, signing keys |
| `crypto/` | Ed25519 key generation/JWK conversion, Argon2id hashing, PKCE S256 verification, CSRF tokens, JWT encoding/decoding |
| `config.rs` | TOML configuration loading with defaults |
| `models.rs` | Shared domain types (Realm, User, Client, AuthorizationCode, RefreshToken, Session, SigningKey) |
| `audit.rs` | JSON-line audit event logging to file |
| `branding.rs` | Per-realm login form theming (colors, logo, CSS) loaded from `{realms_dir}/{realm}/branding/branding.toml` |

### Domain Entities

**Realm** is the aggregate root for tenant isolation. Each realm owns its own set of users, clients, signing keys, authorization codes, refresh tokens, and sessions. Deleting a realm cascades to all its data.

- **User** — username + email + Argon2id password hash, unique per realm
- **Client** — client_id + redirect_uris (JSON) + allowed_scopes, unique per realm
- **SigningKey** — Ed25519 key pair (PEM-encoded), one active per realm, kid in JWT headers
- **AuthorizationCode** — single-use, 5-min TTL, stores PKCE code_challenge, stored as SHA-256 hash
- **RefreshToken** — 30-day TTL, supports rotation (revoked on use), stored as SHA-256 hash
- **Session** — 24-hour browser session, cookie-based, stored as SHA-256 hash

### Shared State

`AppState` holds the SQLite connection (`Arc<Mutex<Connection>>`), config, audit logger, and an in-memory login attempt tracker for rate limiting.

## Crosscutting Concepts

**Error handling:** `AppError` enum maps domain errors to HTTP status codes (400, 401, 404, 429, 500). Uses `thiserror` for the enum and `anyhow` for internal propagation. JSON `{"error": "..."}` responses.

**Token/code storage:** Authorization codes and refresh tokens are never stored in plaintext. The database holds SHA-256 hashes; lookup is by hash.

**Rate limiting:** Login attempts are tracked per IP address in memory. Default: 5 attempts per 5-minute window, returning 429 when exceeded.

**Logging:** Structured logging via `tracing`. Level controlled by `RUST_LOG` env var. Audit events are separate — JSON lines written to a configurable log file.

**Database access:** Synchronous rusqlite behind `Arc<Mutex<>>`. Foreign keys and WAL mode enabled at connection time. Schema migrations run on startup.

**CI:** The `justfile` is the single source of truth for build operations. `just ci` runs formatting checks, clippy (warnings are errors), tests, and a release build. GitHub Actions calls `just ci` — Linux on PRs, macOS on push to main.
