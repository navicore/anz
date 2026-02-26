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
- **Refresh token rotation**
- **Minimal login UI** — server-rendered HTML, no JavaScript frameworks
- **CLI admin** — no admin web UI, just `anz realm/user/client` commands
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

Deploy behind a TLS-terminating reverse proxy (nginx, caddy, etc.).

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

## CLI

```
anz realm create <name>
anz realm list
anz realm delete <name>
anz user add --realm <r> --username <u> --email <e>
anz user list --realm <r>
anz user remove --realm <r> --username <u>
anz client add --realm <r> --client-id <id> --redirect-uri <uri>
anz client list --realm <r>
anz client remove --realm <r> --client-id <id>
anz serve
```

## Docker

```sh
docker pull ghcr.io/navicore/anz:latest
docker run -v ./anz.toml:/etc/anz/anz.toml -v ./data:/data -p 8080:8080 \
  ghcr.io/navicore/anz --config /etc/anz/anz.toml serve
```

## Development

```sh
# run the same checks as CI
just ci

# format + build + test
just dev
```

Requires [just](https://github.com/casey/just) and a Rust toolchain.
