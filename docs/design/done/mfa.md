# MFA in anz

## Intent

Add Time-based One-Time Password (TOTP, RFC 6238) multi-factor auth so that login to any anz-protected consumer (Forgejo, Kubernetes via kubelogin, Headlamp, future apps) requires both a password and a 6-digit code from an authenticator app. MFA at the anz layer means it's enforced once and benefits every consumer — important because kubelogin → kube-apiserver has no MFA layer of its own.

The Forgejo case the user noticed: Forgejo's MFA still prompts because Forgejo binds MFA to its local account, separately from the OIDC identity. That doesn't replace anz-level MFA — Forgejo's protection only covers Forgejo.

## Feasibility (the actual question)

**Yes, well within scope.** TOTP is a small, well-defined spec, has good Rust crates (`totp-rs` for the math, `qrcode` for enrollment), integrates with the existing Askama login template as a second step. Roughly the size of the multi-algorithm signing change — maybe 1-2 days.

What we'd intentionally **not** do:
- WebAuthn / passkeys — much larger scope (browser APIs, attestation handling, fallback flows)
- SMS codes — needs a gateway, costs money, less secure than TOTP
- Push notifications — needs a mobile app

TOTP covers the homelab threat model: attacker has the password but not the phone.

## Constraints

- **Must not break existing logins.** MFA is opt-in per user. Users without TOTP enrolled log in as today.
- **No new admin web UI.** Enrollment via `anz user enroll-mfa` CLI; login challenge extends the existing Askama login template — no SPA.
- **Recovery is mandatory.** Generate N single-use recovery codes at enrollment; user must save them once. Without recovery, a lost authenticator means manual operator intervention.
- **Forgejo's own MFA is untouched.** This is additive — we don't remove or interfere with anything any consumer does.
- **One new dependency limit.** `totp-rs` (or equivalent) plus `qrcode`. Both are small and well-maintained; that's the bar.

## Approach

New table `user_mfa` (one row per user with MFA): `user_id`, `secret_base32`, `created_at`. Recovery codes go in `user_mfa_recovery_codes` (`user_id`, `code_hash`, `used`) — separate so they can be consumed and tracked individually. New column on `realms`: `mfa_required` (bool, default false).

Login flow after step 1 (username + password) branches three ways:
1. **MFA enrolled** → render TOTP/recovery code page → step 2 verification → issue auth code.
2. **No MFA enrolled, realm requires it** → render enrollment page (QR + secret + recovery codes) → user enters a code from their newly-configured authenticator to confirm enrollment → issue auth code. The user_mfa row is committed only after the code verifies.
3. **No MFA enrolled, realm doesn't require it** → issue auth code directly (current behavior).

Auth code is only issued after MFA is satisfied (or skipped because the realm doesn't require it). Between steps, persist the partially-authenticated state (user_id + the original authorize parameters) in a new `mfa_challenges` table keyed by a one-time challenge token (5-min TTL, hashed like other tokens). The challenge token is the only thing in the cookie/form between steps — same security model as our existing CSRF and session tokens.

CLI:
- `anz user enroll-mfa --realm <r> --username <u>` — generates the TOTP secret, prints both the `otpauth://` URI and an ASCII QR code to the terminal, generates 10 recovery codes, prints them once with the standard "save these" warning.
- `anz user disable-mfa --realm <r> --username <u>` — operator escape hatch (a lost-phone recovery path).

## Domain Events

- **MFA enrolled** (CLI or forced web flow) → secret stored, recovery codes hashed and stored, audit `mfa_enrolled` with `source=cli|forced_login`.
- **Login intercepted by mfa_required realm with no enrollment** → enrollment page rendered, audit `mfa_enrollment_required`. No session yet.
- **Login step 1 success (MFA required)** → mfa_challenge row created, challenge page rendered. No session yet.
- **Login step 2 success (TOTP)** → challenge consumed, session + auth code created as today, audit `mfa_success`.
- **Login step 2 success (recovery code)** → recovery code marked used, session + auth code created, audit `mfa_recovery_used` (operator should be aware).
- **Login step 2 failure** → audit `mfa_failure`. Per-user rate limit (separate from per-IP login limit) to make brute-forcing six digits infeasible.
- **MFA disabled by operator** → secret + recovery codes purged, audit `mfa_disabled`.

## Checkpoints

1. `anz user enroll-mfa --realm homelab --username navicore` prints a QR code and 10 recovery codes; the QR scans into Google Authenticator / 1Password / Bitwarden.
2. Logging in: password page → 6-digit code page → success (issues auth code). Wrong code → error message; password is not re-prompted.
3. Recovery code works once; reusing it returns an error.
4. A user without enrolled MFA logs in with one step as before — no regression for current users.
5. Five wrong TOTP attempts returns `too_many_attempts` (separate counter from per-IP login limit).
6. `anz user disable-mfa` returns the user to single-step login; the previous TOTP secret and recovery codes are gone from the DB.
7. `anz realm set-mfa-required --realm homelab` flips the flag. A user without MFA logging in next is sent to the enrollment page after the password step; their auth code is issued only after they confirm a TOTP from their newly-configured authenticator.

## Decisions

- **Per-realm "MFA required" flag.** Realms set `mfa_required = true`. A user without enrolled MFA in such a realm cannot complete login — the post-password step renders an enrollment page (showing the QR + recovery codes) and only proceeds after they confirm a code from their authenticator. CLI: `anz realm set-mfa-required --realm <r>`.
- **Challenge state in DB**, not in a cookie. The cookie carries only the one-time challenge token (hashed in the DB, like our other tokens).
- **Enrollment output shows both QR and the otpauth URI** so users can paste the secret manually if the terminal QR code doesn't render cleanly.
