# Roadmap

## Current State

anz implements a complete OIDC authorization code flow with PKCE, including:

- Multi-realm identity isolation
- Ed25519 JWT signing (per-realm keys)
- Argon2id password hashing with timing-oracle prevention
- Refresh token rotation with RFC 7009 revocation
- Per-IP login rate limiting
- JSON-line audit logging for security events
- Per-realm branding (customizable login page)
- Session management CLI (list, revoke, cleanup)
- 53 unit tests covering crypto, DB, config, audit, branding, and rate limiting

## Known Gaps

- **Public clients only** — no client_secret support; all clients are treated as public
- **No client credentials grant** — only authorization_code and refresh_token grant types
- **No introspection endpoint** (RFC 7662)
- **No scope enforcement** — requested scopes are granted if the client lists them, but no resource-level enforcement exists
- **Single active signing key per realm** — key rotation creates a new key but there is no automated rollover period where both old and new keys sign
- **No MFA** — password-only authentication
- **No social login or federation** — no upstream identity provider support
