use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
// ed25519-dalek 2.x still depends on rand_core 0.6; the `rand` crate at 0.9 uses
// rand_core 0.9, which is a different trait family. We reach through
// `password_hash` (already in the tree via argon2) to get rand_core 0.6's OsRng,
// which satisfies ed25519-dalek's CryptoRngCore bound.
use password_hash::rand_core::OsRng;
use serde_json::{json, Value};

/// Generate a new Ed25519 keypair. Returns (private_key_pem, public_key_pem, kid).
pub fn generate_ed25519_keypair() -> Result<(String, String, String)> {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let private_pem = signing_key
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?
        .to_string();
    let public_pem =
        verifying_key.to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?;

    let kid = uuid::Uuid::new_v4().to_string();

    Ok((private_pem, public_pem, kid))
}

/// Build a JWK (JSON) from a public key PEM and kid.
pub fn public_key_to_jwk(public_key_pem: &str, kid: &str) -> Result<Value> {
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)?;
    let bytes = verifying_key.to_bytes();
    let x = URL_SAFE_NO_PAD.encode(bytes);

    Ok(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "kid": kid,
        "x": x,
    }))
}

/// Create a jsonwebtoken EncodingKey from a PKCS#8 PEM private key.
pub fn encoding_key_from_pem(private_key_pem: &str) -> Result<jsonwebtoken::EncodingKey> {
    let key = jsonwebtoken::EncodingKey::from_ed_pem(private_key_pem.as_bytes())?;
    Ok(key)
}

/// Create a jsonwebtoken DecodingKey from an SPKI PEM public key.
pub fn decoding_key_from_pem(public_key_pem: &str) -> Result<jsonwebtoken::DecodingKey> {
    let key = jsonwebtoken::DecodingKey::from_ed_pem(public_key_pem.as_bytes())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_pem() {
        let (priv_pem, pub_pem, kid) = generate_ed25519_keypair().unwrap();
        assert!(priv_pem.contains("PRIVATE KEY"));
        assert!(pub_pem.contains("PUBLIC KEY"));
        assert!(!kid.is_empty());
    }

    #[test]
    fn public_key_to_jwk_roundtrip() {
        let (_priv_pem, pub_pem, kid) = generate_ed25519_keypair().unwrap();
        let jwk = public_key_to_jwk(&pub_pem, &kid).unwrap();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["kid"], kid);
        assert!(jwk["x"].as_str().is_some());
    }

    #[test]
    fn encoding_decoding_keys_from_pem() {
        let (priv_pem, pub_pem, _kid) = generate_ed25519_keypair().unwrap();
        assert!(encoding_key_from_pem(&priv_pem).is_ok());
        assert!(decoding_key_from_pem(&pub_pem).is_ok());
    }
}
