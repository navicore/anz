# anz — Personal Auth Service

## Overview

A minimal, personal OIDC provider written in Rust. Secures personal web
applications by providing standard OpenID Connect authentication. Not for
commercial or enterprise use — designed for a single operator managing a
small set of users and applications across multiple independent realms.

## Design Principles

- Use proven cryptographic libraries, never custom algorithms
- Keep scope small — fewer features means fewer bugs
- Standard protocols (OIDC/OAuth2) so any compliant app can integrate
- SQLite for persistence — single file, embedded, no network database
- TOML files for server and client configuration
- CLI-only for all admin operations — no admin web UI
- Auditable — small enough codebase to read end-to-end

## Multi-Realm Architecture

Realms are the top-level namespace. Everything is scoped to a realm.
Each realm is an independent identity domain — users, clients, tokens,
and branding are all isolated.

Examples:
- `auth.navicore.tech/realms/startup` — pre-funded startup project
- `auth.navicore.tech/realms/music` — experimental music society
- `auth.navicore.tech/realms/hiking` — local hiking meetup

A user in the `startup` realm has no relationship to a user in the
`music` realm, even if they share the same email address.

All OIDC endpoints are realm-scoped:
- `GET /realms/{realm}/.well-known/openid-configuration`
- `GET /realms/{realm}/jwks`
- `GET /realms/{realm}/authorize`
- `POST /realms/{realm}/token`
- `GET /realms/{realm}/userinfo`
- `POST /realms/{realm}/password`

Each realm's issuer claim is its full URL (e.g.,
`https://auth.navicore.tech/realms/startup`), so tokens from different
realms are cryptographically distinguishable.

## Apps to Secure (Initial)

- notes.navicore.tech
- code.navicore.tech
- list.navicore.tech
- Mix of custom-built and off-the-shelf applications

## Login Ceremony (First-Class)

The login/consent pages are part of anz — they are the authentication
ceremony, not an "app UI." This is core to the OIDC security model:
apps never see user credentials. The user authenticates directly with
anz, and the app receives only a token.

- Login pages are served by anz at the `/realms/{realm}/authorize`
  endpoint
- Per-realm customization: each realm can have its own branding,
  colors, messaging, and logo
- Customization is driven by per-realm TOML/static files on disk —
  no database-driven theming
- Minimal, clean HTML — small enough to audit, no JavaScript
  frameworks
- CSRF-protected forms

## Admin Operations (CLI Only)

All admin operations are performed via the `anz` CLI binary. No admin
web interface.

### Realm management
- `anz realm create <name>`
- `anz realm list`
- `anz realm delete <name>`

### User management (realm-scoped)
- `anz user add --realm <realm> --username <name> --email <email>`
- `anz user list --realm <realm>`
- `anz user remove --realm <realm> --username <name>`

### Client management (realm-scoped)
- `anz client add --realm <realm> --client-id <id> --redirect-uri <uri>`
- `anz client list --realm <realm>`
- `anz client remove --realm <realm> --client-id <id>`

## Token Details

- ID tokens: JWT, signed with EdDSA (Ed25519) — fast, simple, small keys
- Access tokens: JWT (same signing)
- Refresh tokens: opaque, stored in SQLite
- Token lifetimes configurable per-realm via config
- Issuer claim is the realm's full URL

## Persistence

### SQLite (single file, WAL mode)
- Realms (id, name, created_at)
- Users (id, realm_id, username, email, password_hash, created_at, updated_at)
- Clients (id, realm_id, client_id, client_secret_hash, redirect_uris, allowed_scopes)
- Refresh tokens (token_hash, user_id, client_id, realm_id, expires_at, revoked)
- Authorization codes (code_hash, user_id, client_id, realm_id, redirect_uri, scopes, code_challenge, expires_at, used)

### Filesystem
- Server configuration: `anz.toml` (bind address, issuer base URL, DB path, default token lifetimes)
- Per-realm branding: `realms/{realm}/branding/` directory with templates and static assets

## Security Requirements

- Passwords hashed with Argon2id
- Timing-safe comparisons for all secret values
- CSRF protection on login/consent forms
- Rate limiting on login attempts
- HTTPS enforced (behind reverse proxy — anz does not terminate TLS)
- Authorization codes: single-use, short-lived, PKCE required, bound to redirect_uri
- Refresh tokens: rotated on use, revocable

## Phased Delivery

### Phase 1 — Core OIDC Provider
- Multi-realm data model (SQLite)
- OIDC discovery + JWKS endpoints (per-realm)
- Authorization code flow with PKCE
- Token endpoint (issue + refresh)
- Login ceremony (minimal HTML, per-realm path)
- CLI: realm, user, and client management
- Password change API endpoint
- Server config via `anz.toml`
- Ed25519 signing key generation (per-realm or global)

### Phase 2 — Polish & Hardening
- Per-realm branding/theming (custom templates + static files)
- Rate limiting
- Session management improvements
- Token revocation endpoint
- Audit logging (append-only file)
- Refresh token rotation

### Phase 3 — Extended Features
- Self-signup (with optional invite codes, per-realm)
- OAuth2 consent screen for third-party app authorization
- Scope-based authorization (per-app permissions)
- TOTP/WebAuthn second factor (stretch goal)

## Tech Stack

- Language: Rust
- Web framework: axum
- SQLite: rusqlite (with WAL mode)
- Password hashing: argon2 crate
- JWT: jsonwebtoken crate
- Signing keys: ed25519-dalek or ring
- HTML: askama (compile-time templates, minimal — login form only)
- Config: toml + serde
- CLI: clap
