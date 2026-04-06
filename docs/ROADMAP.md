# Roadmap

## Current State

anz implements a complete OIDC provider targeting SSO for Forgejo, Kubernetes, and Headlamp:

- Multi-realm identity isolation with Ed25519 JWT signing
- Authorization code flow with PKCE, refresh token rotation, RFC 7009 revocation
- Confidential client support (client_secret via `--secret` flag)
- Groups claim in ID tokens and UserInfo (for Kubernetes RBAC)
- Per-IP rate limiting, audit logging, per-realm branding
- 65 tests covering crypto, DB, config, audit, branding, rate limiting, client secret validation, and HTTP-level token endpoint behavior

See [docs/design/sso-readiness.md](design/sso-readiness.md) for the SSO integration design.

## Known Gaps

- No client secret rotation — operators must delete and recreate the client to rotate a compromised secret. An `anz client rotate-secret` command would avoid reconfiguring dependent services.
- No client credentials grant (only authorization_code and refresh_token)
- No introspection endpoint (RFC 7662)
- No scope enforcement beyond client-level allowed_scopes
- Single active signing key per realm (no automated key rollover)
- No MFA
- No social login or federation
