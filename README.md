# anz

A minimal, personal OIDC provider written in Rust. Secures personal web
applications with standard OpenID Connect authentication. Designed for a
single operator managing a small set of users and applications.

## Why

Keycloak is too much. Auth0 costs money. This is a single binary with a
SQLite database that implements the OIDC spec well enough to put behind
a reverse proxy and protect a handful of personal apps.

## Features

- **Multi-realm** — isolated identity domains (users, clients, tokens)
- **OIDC authorization code flow** with PKCE
- **Ed25519 signing** (per-realm keys)
- **Argon2id** password hashing
- **Refresh token rotation** with RFC 7009 revocation
- **Confidential clients** — optional client_secret for server-side apps (Forgejo, etc.)
- **Groups claim** — `groups` array in ID tokens and UserInfo for RBAC (Kubernetes, etc.)
- **Rate limiting** — per-IP login attempt throttling
- **Audit logging** — JSON-line event log for login, token, and session activity
- **Per-realm branding** — customizable login page (colors, logo, CSS)
- **Minimal login UI** — server-rendered HTML, no JavaScript frameworks
- **CLI admin** — no admin web UI, just `anz realm/user/client/session` commands
- **SQLite** — single file, embedded, no external database

## Quick Start

```sh
cp anz.toml.example anz.toml
# edit anz.toml with your issuer URL

anz realm create myapp
anz user add --realm myapp --username alice --email alice@example.com
anz client add --realm myapp --client-id myapp-web --redirect-uri http://localhost:3000/callback
anz serve
```

## Configuration

See `anz.toml.example`:

```toml
bind_address = "127.0.0.1:8080"
issuer_base_url = "https://auth.example.com"
database_path = "anz.db"
```

Deploy behind a TLS-terminating reverse proxy (nginx, caddy, etc.). Set `issuer_base_url` to your public HTTPS URL — Kubernetes and other OIDC consumers require HTTPS and will reject tokens from HTTP issuers.

Confidential clients authenticate via `client_secret_post` (secret in the POST body). `client_secret_basic` (HTTP Basic auth header) is not supported — configure clients like Forgejo to use `client_secret_post`.

## OIDC Endpoints

All endpoints are realm-scoped:

| Endpoint | Path |
|---|---|
| Discovery | `GET /realms/{realm}/.well-known/openid-configuration` |
| JWKS | `GET /realms/{realm}/jwks` |
| Authorize | `GET /realms/{realm}/authorize` |
| Token | `POST /realms/{realm}/token` |
| UserInfo | `GET /realms/{realm}/userinfo` |
| Password | `POST /realms/{realm}/password` |
| Revoke | `POST /realms/{realm}/revoke` |

## CLI

```
anz realm create <name>
anz realm list
anz realm delete <name>
anz user add --realm <r> --username <u> --email <e> [--groups admin,dev]
anz user update-groups --realm <r> --username <u> --groups <g1,g2>
anz user list --realm <r>
anz user remove --realm <r> --username <u>
anz client add --realm <r> --client-id <id> --redirect-uri <uri> [--secret]
anz client list --realm <r>
anz client remove --realm <r> --client-id <id>
anz session list --realm <r> --username <u>
anz session revoke --realm <r> --username <u>
anz session cleanup
anz serve
```

## Docker

```sh
docker pull ghcr.io/navicore/anz:latest
docker run -v ./anz.toml:/etc/anz/anz.toml -v ./data:/data -p 8080:8080 \
  ghcr.io/navicore/anz --config /etc/anz/anz.toml serve
```

## Releasing

Create a GitHub release with a tag like `v0.2.0`. The workflow automatically:
1. Runs CI checks
2. Bumps `Cargo.toml` version to match the tag and commits to main
3. Builds static binaries (Linux x86_64, macOS ARM64) and attaches them to the release
4. Builds and pushes a Docker image to GHCR

**Required repo secret:** `PAT` (GitHub token with `contents: write`).

## Development

```sh
# run the same checks as CI (format, clippy, tests, release build)
just ci

# format + build + test
just dev
```

CI runs `just ci` — the justfile is the single source of truth. Linux on PRs, macOS on merge to main.

Requires [just](https://github.com/casey/just) and a Rust toolchain.
