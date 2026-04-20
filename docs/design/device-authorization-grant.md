# Device Authorization Grant (RFC 8628) in anz

## Intent

Let `kubectl` (and any future CLI) log in against anz from a text-only headless Linux shell where no local browser exists. Today anz only supports the authorization code flow, which assumes `localhost` redirect plus a browser. That breaks SSH-only workflows on homelab machines.

RFC 8628 solves exactly this: the CLI prints a URL and a short code, the user opens that URL on any device with a browser (phone, laptop, another workstation), logs into anz, confirms the device — the CLI's polling token request then succeeds. Every serious cloud CLI (`gcloud`, `aws`, `az`, `gh`) implements it. The homelab's OIDC should match.

Paired client-side work (a thin `kubectl-oidc_device` exec plugin) lives in the k8s-vcluster-homelab repo: `docs/design/cli-headless-and-desktop-login.md`. This doc is the anz half only.

## Constraints

- **No regressions to authorization_code flow.** Desktop users stay on the existing `kubelogin` path unchanged.
- **PKCE required for public clients.** Blanket policy applies here — device flow with PKCE (RFC 7636 + `code_challenge` on `device_authorization`) is supported and increasingly standard.
- **MFA stays enforced.** If the realm requires MFA, approving a device forces MFA the same way a web login does. There is no new bypass path.
- **Per-client opt-in.** Only clients explicitly flagged for device flow can hit `/device_authorization`. Existing clients are unaffected. Blast radius is minimal.
- **No plaintext codes in storage.** `device_code` and `user_code` are stored as SHA-256 hashes, same model as auth codes, refresh tokens, and session tokens.
- **No federation, no new IdPs, no external deps.** Same Rust + axum + rusqlite footprint.
- **Out of scope:** CIBA, backchannel auth, QR-code login, WebAuthn, rich device metadata (geolocation, device fingerprinting).

## Approach

Three new endpoints, one new table, one new client flag, two new discovery fields.

**New endpoints:**
- `POST /realms/{realm}/device_authorization` — client posts `client_id`, `scope`, `code_challenge`, `code_challenge_method=S256`. Server issues `device_code` (32 random bytes, base64url), `user_code` (8 chars from a 20-letter confusion-free alphabet, formatted `XXXX-XXXX`), `verification_uri`, `verification_uri_complete`, `expires_in` (600s), `interval` (5s). Stores SHA-256 hashes of both codes in `device_authorizations` with status `pending`.
- `GET /realms/{realm}/device/verify` (optionally `?user_code=...`) — renders an Askama page. If the user has no valid session, the existing login flow runs first (password → MFA if required). If they have a valid session, proceed directly. Page then shows the client name, requested scopes, and the `user_code` the user typed, with explicit **Approve** and **Deny** buttons. CSRF-protected like the login form.
- `POST /realms/{realm}/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` — polling endpoint. Validates `device_code` hash lookup, client binding, PKCE `code_verifier`, and device status. Returns one of:
  - `authorization_pending` — user hasn't approved yet
  - `slow_down` — polling faster than `interval`
  - `access_denied` — user clicked Deny
  - `expired_token` — past `expires_at`
  - success → same id_token + refresh_token + access_token payload as authorization_code flow (same claims, same signing key, same audience)

**New column on `clients`:** `device_flow_enabled` (bool, default false). CLI: `anz client add --enable-device-flow` / `anz client set-device-flow --enable|--disable`.

**New table `device_authorizations`:** `id`, `realm_id`, `client_id`, `device_code_hash`, `user_code_hash`, `scope`, `code_challenge`, `code_challenge_method`, `status` (`pending|approved|denied|expired`), `user_id` (nullable; set on approve), `expires_at`, `created_at`, `last_polled_at`. Indexed on `device_code_hash` and `user_code_hash`. Cascades on realm delete.

**Discovery document** gains `device_authorization_endpoint` and appends `urn:ietf:params:oauth:grant-type:device_code` to `grant_types_supported`.

**Rate limiting:**
- Token polling rate-limited per `device_code` via `last_polled_at` — polls inside `interval` return `slow_down`. No separate IP table for polling; device_code is the natural key.
- `user_code` entry on the verify page is limited per IP (reuse login rate limiter) to stop brute-forcing the 20^8 space down further.

**Cleanup:** A periodic task (or on-the-fly check at poll time) marks expired rows as `expired`. Final purge can piggyback on the existing auth code cleanup path.

## Domain Events

- **Device authorization requested** → row inserted with status `pending`, audit `device_authorization_requested` (client_id, realm, masked user_code).
- **User approves device** → status flips to `approved`, `user_id` set, audit `device_approved` (user, client, realm). Any prior MFA events for this session apply transitively — no duplicate MFA prompt.
- **User denies device** → status flips to `denied`, audit `device_denied`.
- **CLI polls before approval** → audit is *not* emitted per poll (too noisy); only first poll and terminal poll are audited.
- **CLI polls after approval, PKCE verifies** → id/refresh/access tokens issued exactly as authorization_code would, audit `device_token_exchanged`. Row marked `consumed` (or deleted) so the device_code can't be replayed.
- **Expiry reached without approval** → status flips to `expired`, audit `device_expired`.
- **user_code brute-force attempt** → per-IP rate limit hit on verify form, audit `device_verify_rate_limited`, reuse existing 429 path.
- **Token polling after denial / expiry / consumption** → returns the matching RFC 8628 error; no audit spam.

## Checkpoints

1. `curl -X POST https://anz/realms/homelab/device_authorization -d client_id=... -d scope=openid+groups -d code_challenge=... -d code_challenge_method=S256` returns a JSON body with `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in=600`, `interval=5`.
2. `/realms/homelab/.well-known/openid-configuration` advertises `device_authorization_endpoint` and lists the device_code grant type.
3. Visiting `verification_uri_complete` while logged in shows the Approve/Deny page with the client name and scopes pre-populated; clicking Approve returns a success page.
4. Visiting `verification_uri` (no user_code in URL) prompts for the code, accepts the formatted `XXXX-XXXX` input, then shows the same Approve/Deny page.
5. Visiting `verification_uri` with no session routes through the normal login flow (including TOTP if the realm requires it) before showing the Approve/Deny page.
6. `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` and the correct `code_verifier` after Approve returns an id_token whose `preferred_username`, `groups`, and signing key match what the authorization_code flow would produce for the same user.
7. Polling the token endpoint before approval returns `authorization_pending`; polling faster than `interval` returns `slow_down`; polling after Deny returns `access_denied`; polling after 10 min without approval returns `expired_token`.
8. A second `POST /token` with the same `device_code` after success returns an error — codes are single-use.
9. `anz client add --realm homelab --client-id kubectl-oidc-device --redirect-uri '' --enable-device-flow` registers a public (no secret) client. `POST /device_authorization` succeeds for it; the same request against a client without the flag returns `unauthorized_client`.
10. `KUBECONFIG=kubeconfig/homelab-headless.yaml kubectl get nodes` from a plain SSH session on a headless box completes end-to-end, reusing the kubectl-oidc_device exec plugin.
