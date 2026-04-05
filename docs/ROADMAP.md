# Roadmap

## Current State

anz implements a complete OIDC authorization code flow with PKCE, including multi-realm isolation, Ed25519 JWT signing, Argon2id passwords, refresh token rotation with RFC 7009 revocation, per-IP rate limiting, audit logging, per-realm branding, and session management. 53 unit tests cover crypto, DB, config, audit, branding, and rate limiting.

## Target: SSO for Forgejo + Kubernetes + Headlamp

See [docs/design/sso-readiness.md](design/sso-readiness.md) for the full assessment.

### 1. Client secret support
Forgejo requires `client_secret` on token requests. anz currently only supports public clients. Add optional `client_secret_hash` to clients, validate on `/token`, and expose via `anz client add --secret`.

### 2. Groups claim in tokens
Kubernetes API server needs a `groups` array in ID tokens for RBAC mapping. Add `groups` column to users, include in ID token claims and UserInfo. Expose via `anz user add --groups`.

### 3. Document HTTPS / public issuer requirement
Kubernetes rejects non-HTTPS issuers. anz is designed for reverse proxy deployment but the README doesn't call this out clearly enough for the K8s use case.

## Known Gaps (not blocking SSO target)

- No client credentials grant (only authorization_code and refresh_token)
- No introspection endpoint (RFC 7662)
- No scope enforcement beyond client-level allowed_scopes
- Single active signing key per realm (no automated key rollover)
- No MFA
- No social login or federation
