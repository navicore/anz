use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Verify a PKCE S256 code challenge.
/// Returns true if SHA256(code_verifier) == code_challenge (both base64url-encoded).
pub fn verify_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);

    computed.as_bytes().ct_eq(code_challenge.as_bytes()).into()
}
