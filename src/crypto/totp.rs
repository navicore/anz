//! TOTP (RFC 6238) helpers for MFA enrollment and verification.
//!
//! Wraps `totp-rs` with the project's defaults: SHA-1 (the only algorithm any
//! authenticator app guarantees), 30-second step, 6 digits, ±1 step skew.

use anyhow::{anyhow, Result};
use base32::Alphabet;
use totp_rs::{Algorithm, Secret, TOTP};

const DIGITS: usize = 6;
const STEP_SECS: u64 = 30;
/// Tolerate one step before and after — covers normal clock drift between the
/// user's device and our server. (totp-rs lets us pass a tolerance window when
/// verifying; we re-implement that here for clarity and to keep the dependency
/// surface small.)
const SKEW_STEPS: i64 = 1;

/// Generate a new TOTP secret. Returns the base32-encoded form (what authenticator
/// apps expect) and the raw bytes — we keep both so the caller can build an
/// `otpauth://` URI without re-decoding.
pub fn generate_secret() -> (String, Vec<u8>) {
    let secret = Secret::generate_secret();
    let raw = secret
        .to_bytes()
        .expect("Secret::to_bytes is infallible for generated secrets");
    let base32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &raw);
    (base32, raw)
}

/// Verify a 6-digit code against the stored base32 secret. Tolerates one
/// 30-second step in either direction (clock skew between the user's device
/// and our server).
pub fn verify_code(secret_base32: &str, code: &str) -> Result<bool> {
    let raw = base32::decode(Alphabet::Rfc4648 { padding: false }, secret_base32)
        .ok_or_else(|| anyhow!("stored TOTP secret is not valid base32"))?;
    let totp = TOTP::new(Algorithm::SHA1, DIGITS, 1, STEP_SECS, raw)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let current_step = now / STEP_SECS as i64;

    // Try current step plus skew window in both directions.
    for offset in -SKEW_STEPS..=SKEW_STEPS {
        let step = (current_step + offset) as u64;
        let expected = totp.generate(step * STEP_SECS);
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Build an `otpauth://` URI for QR/manual entry into the user's authenticator app.
/// Format per the de-facto Google Authenticator spec.
pub fn build_otpauth_uri(issuer: &str, account: &str, secret_base32: &str) -> String {
    // RFC 3986 percent-encoding for the path segment (issuer:account) and for
    // the issuer query parameter. Authenticator apps are forgiving but spaces
    // and colons must be escaped.
    let label = format!("{}:{}", percent_encode(issuer), percent_encode(account));
    format!(
        "otpauth://totp/{label}?secret={secret_base32}&issuer={issuer_param}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        issuer_param = percent_encode(issuer),
    )
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_is_base32_decodable() {
        let (b32, raw) = generate_secret();
        let decoded = base32::decode(Alphabet::Rfc4648 { padding: false }, &b32).unwrap();
        assert_eq!(decoded, raw);
        assert!(!raw.is_empty());
    }

    #[test]
    fn verify_accepts_currently_valid_code() {
        let (b32, raw) = generate_secret();
        let totp = TOTP::new(Algorithm::SHA1, DIGITS, 1, STEP_SECS, raw).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_code(&b32, &code).unwrap());
    }

    #[test]
    fn verify_rejects_bogus_code() {
        let (b32, _) = generate_secret();
        assert!(!verify_code(&b32, "000000").unwrap());
    }

    #[test]
    fn build_otpauth_uri_format() {
        let uri = build_otpauth_uri("anz", "alice@example.com", "JBSWY3DPEHPK3PXP");
        assert!(uri.starts_with("otpauth://totp/anz:alice%40example.com?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=anz"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }
}
