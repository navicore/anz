# Signed SBOM for anz

## Intent

Produce a signed Software Bill of Materials for every anz release so that operators deploying the Docker image can verify exactly what's inside it and that it hasn't been tampered with. This is also a learning exercise in current SBOM best practices (April 2026).

## Constraints

- **No third-party SBOM GitHub Actions.** The tj-actions/changed-files supply chain attack (CVE-2025-30066, March 2025) demonstrated that popular Actions can be compromised via tag mutation, leaking pipeline secrets. SBOM generation must use locally-installed binaries, not third-party Actions.
- **Pin all GitHub Actions to commit SHA**, not version tags. Tags are mutable.
- **No long-lived signing keys in CI.** Use Cosign keyless signing via GitHub OIDC — short-lived certificates, no secrets to leak.
- **Do not modify the Rust source, build logic, or justfile.** SBOM is a release pipeline concern only.
- **CycloneDX format.** Compact, security-focused, widely supported by scanning tools and registries.

## Approach

Two complementary SBOMs, both signed:

1. **Cargo-level SBOM** — `cargo-cyclonedx` reads `Cargo.lock` and produces a CycloneDX JSON listing all Rust dependencies with versions and licenses. Installed via `cargo install` in the workflow, not via a GitHub Action.

2. **Container-level SBOM** — Docker BuildKit's `--attest type=sbom` scans the final image (OS packages, binary). Attached as an OCI attestation alongside the image manifest.

**Signing:** Cosign keyless signing via GitHub OIDC (Sigstore). The image is signed, and the Cargo SBOM is attached as a CycloneDX attestation. Both are logged to the Rekor transparency log automatically.

**Verification by operators** (flags verify the signature came from our release workflow, not just any signer):
```sh
cosign verify \
  --certificate-identity-regexp "https://github.com/navicore/anz/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/navicore/anz:0.3.0

cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp "https://github.com/navicore/anz/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/navicore/anz:0.3.0
```

Identity is matched via `refs/tags/.*` regex because release workflows are triggered by tag creation — GitHub's OIDC token records the tag ref in the signing certificate, not `main`.

## Domain Events

- **Release created** → triggers workflow
- **SBOM generated** → CycloneDX JSON from Cargo.lock (source dependencies) + BuildKit scan (runtime dependencies)
- **Image signed** → Cosign keyless signature logged to Rekor
- **SBOM attested** → attached to image in registry as CycloneDX attestation

No changes to anz's runtime behavior. No new endpoints, config, or database changes.

## Checkpoints

1. `cargo install cargo-cyclonedx && cargo cyclonedx` produces valid CycloneDX JSON locally
2. `docker buildx build --attest type=sbom` succeeds and the attestation is visible in the registry
3. `cosign verify ghcr.io/navicore/anz:<tag>` passes after a release
4. `cosign verify-attestation --type cyclonedx ghcr.io/navicore/anz:<tag>` returns the Cargo SBOM
5. All GitHub Actions in release.yml are pinned to commit SHA, not tags

## Decisions

- **Pin all Actions to SHA** as part of this work. Every `uses:` in every workflow gets pinned to full commit SHA with a version comment. No separate hardening pass — do it once, do it now.
- **SLSA provenance attestations:** Yes. BuildKit generates these with `provenance: true` at no additional cost. This produces SLSA Level 1 (builder-produced) provenance — not L2/L3. Provenance answers "who built this and from what source", SBOM answers "what's inside it". Both matter.
- **Claude Code Action workflows** (`claude.yml`, `claude-code-review.yml`) stay on version tags (`@v1`), not SHA pins. The Action validates that the workflow file on the PR branch matches main — SHA-pinning on a PR would break this validation until merged.
