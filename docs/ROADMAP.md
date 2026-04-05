# Roadmap

## Current State

anz implements a working OIDC authorization code flow with PKCE, refresh token rotation, and RFC 7009 token revocation. Phase 2 work (currently in progress on the `phase-2` branch) adds session management, audit logging, per-realm branding, token revocation, and a static file server for branding assets.

## Known Gaps

- **Public clients only** — no client_secret support; all clients are treated as public
- **No client credentials grant** — only authorization_code and refresh_token grant types
- **No introspection endpoint** (RFC 7662)
- **No scope enforcement** — requested scopes are granted if the client lists them, but no resource-level enforcement exists
- **Single active signing key per realm** — key rotation creates a new key but there is no automated rollover period where both old and new keys sign
- **No MFA** — password-only authentication
- **No social login or federation** — no upstream identity provider support
