//! Shared helpers for generating random tokens and MFA recovery codes.
//!
//! Centralised here so the CLI enrollment path and the in-login enrollment path
//! produce identical token shapes (same length, same alphabet, same hashing).

use crate::crypto::hex_encode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// 32 random bytes, URL-safe base64 (no padding) — used for challenge tokens
/// and session tokens. The browser sees the raw token; only its SHA-256 hash
/// is stored.
pub fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate `n` recovery codes. Returns (plaintext, SHA-256 hex hashes) in
/// matching order. The caller shows plaintext to the user exactly once and
/// persists only the hashes.
pub fn generate_recovery_codes(n: usize) -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    for _ in 0..n {
        let mut bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut bytes);
        let code = URL_SAFE_NO_PAD.encode(bytes);
        let hash = hex_encode(&Sha256::digest(code.as_bytes()));
        plain.push(code);
        hashes.push(hash);
    }
    (plain, hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_differ() {
        assert_ne!(generate_random_token(), generate_random_token());
    }

    #[test]
    fn recovery_codes_produce_matching_hashes() {
        let (plain, hashes) = generate_recovery_codes(5);
        assert_eq!(plain.len(), 5);
        assert_eq!(hashes.len(), 5);
        for (p, h) in plain.iter().zip(hashes.iter()) {
            let expected = hex_encode(&Sha256::digest(p.as_bytes()));
            assert_eq!(*h, expected);
        }
    }
}
