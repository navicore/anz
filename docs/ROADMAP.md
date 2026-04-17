# Roadmap

## Current State

anz implements a complete OIDC provider targeting SSO for Forgejo, Kubernetes, and Headlamp:

- Multi-realm identity isolation with RS256 or EdDSA JWT signing (per-realm, with concurrent keys during rotation)
- Authorization code flow with PKCE, refresh token rotation, RFC 7009 revocation
- TOTP multi-factor auth — per-realm enforced or per-user opt-in, with recovery codes and in-line enrollment during login
- Confidential client support (client_secret via `--secret` flag)
- Groups claim in ID tokens and UserInfo (for Kubernetes RBAC)
- Per-IP login + per-user MFA rate limiting, audit logging, per-realm branding
- 87 tests covering crypto, DB, config, audit, branding, rate limiting, MFA, and HTTP-level behavior

See [docs/design/done/sso-readiness.md](design/done/sso-readiness.md) for the SSO integration design.

## Known Gaps

- No client secret rotation — operators must delete and recreate the client to rotate a compromised secret. An `anz client rotate-secret` command would avoid reconfiguring dependent services.
- No client credentials grant (only authorization_code and refresh_token)
- No introspection endpoint (RFC 7662)
- No scope enforcement beyond client-level allowed_scopes
- No social login or federation
