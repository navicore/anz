//! AES-256-GCM encryption at rest for TOTP secrets.
//!
//! Why: TOTP shared secrets are bearer credentials — anyone with the database
//! file and the secret can generate valid codes. Encrypting them with a key
//! held in the process (from config or `ANZ_MFA_SECRET_KEY`) raises the bar so
//! that stealing a backup/snapshot of the DB alone is insufficient.
//!
//! Storage format: values produced by `encrypt` are prefixed with `enc:v1:`
//! followed by standard base64 of `nonce(12) || ciphertext || tag(16)`. A fresh
//! random nonce is generated per write. `decrypt` transparently passes through
//! values that lack the prefix, so existing plaintext rows keep working until
//! they're rewritten (at which point they become ciphertext).
//!
//! If no key is configured, the cipher is a no-op: `encrypt` returns the
//! plaintext unchanged and `decrypt` accepts only legacy plaintext (a ciphertext
//! value with no key to decrypt it is a hard error — the secret is lost).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;

const PREFIX: &str = "enc:v1:";
const NONCE_LEN: usize = 12;

pub struct SecretCipher {
    cipher: Option<Aes256Gcm>,
}

impl SecretCipher {
    /// Build from an optional 64-char hex key (32 bytes). `None` → noop cipher.
    pub fn from_hex_key(key_hex: Option<&str>) -> Result<Self> {
        let Some(hex) = key_hex else {
            return Ok(Self { cipher: None });
        };
        let bytes = decode_hex(hex)?;
        let cipher = Aes256Gcm::new_from_slice(&bytes).map_err(|_| {
            anyhow!(
                "ANZ_MFA_SECRET_KEY must be 32 bytes (64 hex chars); got {}",
                bytes.len()
            )
        })?;
        Ok(Self {
            cipher: Some(cipher),
        })
    }

    /// Identity cipher for tests and for deployments without a configured key.
    #[cfg(test)]
    pub fn noop() -> Self {
        Self { cipher: None }
    }

    /// True if a key is configured and values will be encrypted on write.
    pub fn is_active(&self) -> bool {
        self.cipher.is_some()
    }

    /// Encrypt `plaintext` to `enc:v1:<b64>`. Pass-through if no key configured.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let Some(cipher) = &self.cipher else {
            return Ok(plaintext.to_string());
        };
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        // Deprecation is from aes-gcm's pending generic-array 1.x migration —
        // the call itself is correct.
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("aes-gcm encrypt failed: {e}"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(format!("{PREFIX}{}", STANDARD.encode(&out)))
    }

    /// Decrypt a value produced by `encrypt`, or pass through legacy plaintext
    /// (values with no `enc:v1:` prefix). Erroring if a prefixed value is found
    /// but no key is configured — that secret can't be recovered.
    pub fn decrypt(&self, stored: &str) -> Result<String> {
        let Some(rest) = stored.strip_prefix(PREFIX) else {
            return Ok(stored.to_string());
        };
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| anyhow!("encrypted TOTP secret present but no key configured"))?;
        let raw = STANDARD
            .decode(rest)
            .map_err(|e| anyhow!("invalid base64 in encrypted secret: {e}"))?;
        if raw.len() < NONCE_LEN {
            return Err(anyhow!("encrypted secret too short"));
        }
        let (nonce_bytes, ct) = raw.split_at(NONCE_LEN);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = cipher.decrypt(nonce, ct).map_err(|e| {
            anyhow!("aes-gcm decrypt failed (wrong key or corrupt ciphertext): {e}")
        })?;
        String::from_utf8(pt).map_err(|e| anyhow!("decrypted secret is not valid UTF-8: {e}"))
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("hex string has odd length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| anyhow!("invalid hex at position {i}: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn noop_roundtrip_is_identity() {
        let c = SecretCipher::noop();
        assert!(!c.is_active());
        let ct = c.encrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(ct, "JBSWY3DPEHPK3PXP");
        assert_eq!(c.decrypt(&ct).unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn active_roundtrip_produces_prefixed_value() {
        let c = SecretCipher::from_hex_key(Some(KEY_HEX)).unwrap();
        assert!(c.is_active());
        let ct = c.encrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert!(ct.starts_with("enc:v1:"));
        assert_eq!(c.decrypt(&ct).unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn each_encryption_uses_fresh_nonce() {
        let c = SecretCipher::from_hex_key(Some(KEY_HEX)).unwrap();
        let a = c.encrypt("same input").unwrap();
        let b = c.encrypt("same input").unwrap();
        assert_ne!(a, b);
        assert_eq!(c.decrypt(&a).unwrap(), "same input");
        assert_eq!(c.decrypt(&b).unwrap(), "same input");
    }

    #[test]
    fn active_cipher_passes_through_legacy_plaintext() {
        let c = SecretCipher::from_hex_key(Some(KEY_HEX)).unwrap();
        // Legacy row with no prefix — still readable.
        assert_eq!(c.decrypt("JBSWY3DPEHPK3PXP").unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn noop_rejects_encrypted_value() {
        let active = SecretCipher::from_hex_key(Some(KEY_HEX)).unwrap();
        let ct = active.encrypt("x").unwrap();
        let noop = SecretCipher::noop();
        assert!(noop.decrypt(&ct).is_err());
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let a = SecretCipher::from_hex_key(Some(KEY_HEX)).unwrap();
        let ct = a.encrypt("secret").unwrap();
        let other_key = "0202020202020202020202020202020202020202020202020202020202020202";
        let b = SecretCipher::from_hex_key(Some(other_key)).unwrap();
        assert!(b.decrypt(&ct).is_err());
    }

    #[test]
    fn short_or_invalid_key_is_rejected() {
        assert!(SecretCipher::from_hex_key(Some("abcd")).is_err());
        assert!(SecretCipher::from_hex_key(Some("zz")).is_err());
        // Correct length, non-hex char.
        let bad = "zz".repeat(32);
        assert!(SecretCipher::from_hex_key(Some(&bad)).is_err());
    }
}
