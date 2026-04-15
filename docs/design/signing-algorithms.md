# Multi-Algorithm Signing

## Intent

Support multiple JWT signing algorithms per realm, defaulting to RS256 for maximum OIDC consumer compatibility. Keep Ed25519 (EdDSA) available as an opt-in for modern clients. Immediate driver: Kubernetes' kube-apiserver OIDC client only accepts RS256 — EdDSA tokens from anz are rejected.

## Constraints

- **No realm data loss.** Existing `homelab` realm and its users must continue working through migration.
- **Existing Ed25519 keys remain valid** for clients that accept them. Do not force-rotate.
- **JWKS endpoint must serve both algorithms concurrently** when a realm has keys of different types (this is the normal state during rotation).
- **Discovery must advertise supported algorithms honestly** per realm — based on what signing keys the realm actually has.
- **No new runtime dependencies** beyond what's already in the tree. `jsonwebtoken` and `ed25519-dalek` cover what we need; RSA support needs an RSA key library (`rsa` crate or `ring`).
- **Default behavior changes**: `anz realm create` goes from Ed25519 to RS256. Document this clearly.
- **RSA key generation is slow** (2048-bit keys take ~1 second). Acceptable for a one-time realm-create operation.

## Approach

Algorithm becomes a property of each `SigningKey` row, not the realm. A realm can have active keys of different algorithms simultaneously — this is how rotation works without downtime.

**Schema:** add `algorithm` column to `signing_keys` (TEXT, `"EdDSA"` or `"RS256"` initially). Migration defaults existing rows to `"EdDSA"` so current keys keep working.

**Key selection for signing:** when issuing tokens, pick one active key per algorithm. For now, deterministic: pick the most recently created active key. If a realm has both RS256 and Ed25519 keys active, we sign with RS256 (the lowest common denominator wins by default). A future enhancement could let clients request a preferred algorithm.

**JWKS:** serve all active keys regardless of algorithm. RSA keys emit `kty=RSA` with `n` and `e`. Ed25519 stays `kty=OKP, crv=Ed25519, x=...`.

**Discovery:** `id_token_signing_alg_values_supported` is computed per-realm from the distinct algorithms of active keys in that realm.

**CLI:**
- `anz realm create <name>` — defaults to RS256 (changed). `--key-type ed25519` for opt-in.
- `anz realm rotate-key --realm <name> --alg <RS256|EdDSA>` — adds a new active key without deactivating old ones. Operator decides when to deactivate the old key after all clients have rotated.
- `anz realm deactivate-key --realm <name> --kid <kid>` — marks an old key inactive (no longer used for signing, but still in JWKS for verification of outstanding tokens until they expire).

**Storage:** RSA keys stored as PKCS#8 PEM in the same `private_key_pem` column. Ed25519 keys stay the same. The `algorithm` column tells the code which format to expect.

**Dependency choice:** use the `rsa` crate. It's already a transitive dependency (via the rust_crypto feature of jsonwebtoken). Making it direct costs nothing.

## Domain Events

- **`anz realm create --key-type rsa`** → generates 2048-bit RSA keypair → inserts signing_key row with algorithm=RS256, active=1.
- **`anz realm rotate-key`** → generates new keypair → inserts new active row. Existing key stays active (JWKS still serves it, token signing still picks one per algorithm).
- **Token endpoint** → selects signing key based on active keys in the realm. Default preference order when multiple algorithms present: RS256, then EdDSA.
- **JWKS endpoint** → returns every active key, correctly formatted per algorithm.
- **Discovery endpoint** → `id_token_signing_alg_values_supported` reflects the realm's actual active-key algorithms.

## Migration Path for Existing Realms

Your `homelab` realm currently has an Ed25519 key. After this change ships:

1. `anz realm rotate-key --realm homelab --alg RS256` — generates a new RS256 key alongside the Ed25519 one.
2. JWKS now serves both. Token issuance prefers RS256 (new K8s-compatible tokens).
3. Existing outstanding tokens (signed with Ed25519) keep verifying against the JWKS until they expire.
4. Optionally, `anz realm deactivate-key --realm homelab --kid <old-ed25519-kid>` after max token lifetime passes.

No downtime, no client reconfiguration, no user re-authentication.

## Checkpoints

1. `anz realm create <name>` with no flags creates a realm with RS256 key. `anz realm create <name> --key-type ed25519` still works for Ed25519.
2. `/.well-known/openid-configuration` lists only `RS256` in `id_token_signing_alg_values_supported` for RS256-only realms, `EdDSA` for Ed25519-only realms, both for realms mid-rotation.
3. `/jwks` endpoint returns correctly-shaped JWKs: RSA keys have `kty=RSA, n, e`; Ed25519 keys have `kty=OKP, crv=Ed25519, x`.
4. `cargo test` passes with new tests covering: RSA keypair generation, RSA PEM round-trip, JWKS serialization for both algorithms, algorithm selection priority when multiple active keys exist.
5. After rotating `homelab` to RS256 and restarting anz: `kubectl get nodes` via kubelogin succeeds. k3s logs no longer show `unsupported algorithm` errors.
6. Forgejo login continues to work through the rotation (it doesn't care which algorithm is used — jsonwebtoken libs in Go/Rust/Node all accept both).

## Decisions Deferred

- **Algorithm negotiation per-client.** Not needed yet. All current consumers either accept both or accept only RS256 — signing with RS256 when both are active is the safe default. If we later add a client that requires EdDSA specifically, we add per-client algorithm preference then.
- **ECDSA (ES256).** Not needed for current consumers. RS256 + EdDSA covers everything we know about. If a specific client requires ES256 in the future, the same pattern extends (add another `algorithm` value, another key generation path, another JWKS shape).
- **Key size for RSA.** 2048 is the standard minimum and what OIDC consumers expect. No reason to go bigger; 4096 just wastes cycles.
