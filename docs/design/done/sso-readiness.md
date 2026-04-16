# SSO Readiness: Forgejo + Kubernetes + Headlamp

## Intent

Assess what anz needs to serve as the SSO provider for three real consumers: Forgejo (git hosting), Kubernetes API server (cluster auth via kubelogin), and Headlamp (K8s web dashboard). The gaps found here become the new roadmap.

## Current State vs. Requirements

| Capability | anz today | Forgejo | K8s API | Headlamp / kubelogin |
|---|---|---|---|---|
| OIDC discovery | yes | needs | needs | needs |
| Auth code + PKCE | yes | needs | N/A | needs |
| ID token (sub, username, email) | yes | needs | needs | needs |
| Refresh tokens | yes | needs | N/A | needs |
| UserInfo | yes | needs | N/A | optional |
| Client secret | **no** | **needs** | N/A | best practice |
| Groups claim | **no** | useful | **needs** | useful |
| HTTPS issuer | config only | needs | **needs** | needs |

## Gaps (ordered by deployment impact)

### 1. Client secret support
Forgejo sends `client_secret` on every token request. anz only supports public clients (`token_endpoint_auth_methods_supported: ["none"]`). Without this, Forgejo's token exchange is unauthenticated.

**Scope:** Add optional `client_secret_hash` to clients table. Hash with SHA-256 (not Argon2 -- secrets are high-entropy, not passwords). Validate on `/token` POST when the client has a secret. Add `client_secret_post` to discovery's `token_endpoint_auth_methods_supported`. CLI: `anz client add --secret` generates and prints a secret once.

### 2. Groups claim in tokens
Kubernetes API server uses `--oidc-groups-claim` to map users to RBAC roles. Without a `groups` array in the ID token, every authenticated user gets identical permissions.

**Scope:** Add `groups` (JSON array, default `[]`) column to users table. Include `groups` in ID token claims and UserInfo response. CLI: `anz user add --groups admin,dev` and `anz user update-groups`.

### 3. HTTPS / public issuer (operational, not code)
Kubernetes rejects tokens from non-HTTPS issuers. anz runs behind a reverse proxy by design, so this is a deployment concern. But the README should be explicit: `issuer_base_url` must be an HTTPS URL reachable by all consumers (K8s nodes, user browsers, Forgejo server).

**Scope:** Document in README. No code change needed -- `issuer_base_url` already configurable.

## Constraints

- No TLS termination in anz itself -- stays behind a reverse proxy
- No breaking changes to existing DB schema (additive migrations only)
- Client secret is optional per-client (public clients remain valid for kubelogin/Headlamp)
- Groups are optional per-user (empty array is the default)
- No scope enforcement beyond what's already in place

## Checkpoints

1. **Client secret:** `anz client add --realm test --client-id forgejo --redirect-uri ... --secret` prints a secret. Token request without that secret returns 401.
2. **Groups claim:** `anz user add --realm test --username alice --email a@b.com --groups admin` then decode the issued ID token -- `groups: ["admin"]` is present.
3. **Forgejo integration:** Configure Forgejo with anz as OIDC provider, log in as a user, verify user is created in Forgejo with correct username/email.
4. **Kubernetes integration:** Configure `kube-apiserver --oidc-issuer-url --oidc-client-id --oidc-username-claim=preferred_username --oidc-groups-claim=groups`. Use kubelogin to authenticate. `kubectl get pods` succeeds with RBAC bound to the user's group.
5. **Headlamp:** Configure Headlamp OIDC, log in, verify dashboard loads with the authenticated user's permissions.
