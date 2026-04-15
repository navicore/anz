use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use subtle::ConstantTimeEq;

/// Generate a random CSRF token (32 bytes, base64url-encoded).
pub fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Timing-safe comparison of two CSRF tokens.
pub fn verify_csrf_token(token: &str, expected: &str) -> bool {
    token.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_is_nonempty() {
        let token = generate_csrf_token();
        assert!(!token.is_empty());
    }

    #[test]
    fn two_tokens_differ() {
        let a = generate_csrf_token();
        let b = generate_csrf_token();
        assert_ne!(a, b);
    }

    #[test]
    fn verify_matching_tokens() {
        let token = generate_csrf_token();
        assert!(verify_csrf_token(&token, &token));
    }

    #[test]
    fn verify_mismatched_tokens() {
        assert!(!verify_csrf_token("aaa", "bbb"));
    }
}
