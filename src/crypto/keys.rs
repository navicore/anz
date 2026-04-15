use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
// ed25519-dalek 2.x still depends on rand_core 0.6; the `rand` crate at 0.9 uses
// rand_core 0.9, which is a different trait family. We reach through
// `password_hash` (already in the tree via argon2) to get rand_core 0.6's OsRng,
// which satisfies ed25519-dalek's CryptoRngCore bound.
use password_hash::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use crate::models::SigningAlgorithm;

const RSA_KEY_BITS: usize = 2048;

/// Generate a new keypair for the given algorithm.
/// Returns (private_key_pem, public_key_pem, kid).
pub fn generate_keypair(alg: SigningAlgorithm) -> Result<(String, String, String)> {
    match alg {
        SigningAlgorithm::EdDsa => generate_ed25519_keypair(),
        SigningAlgorithm::Rs256 => generate_rsa_keypair(),
    }
}

fn generate_ed25519_keypair() -> Result<(String, String, String)> {
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

fn generate_rsa_keypair() -> Result<(String, String, String)> {
    // rsa crate uses its own rand wrapper; the default OsRng here is rand_core 0.6's.
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
        .to_string();
    let public_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

    let kid = uuid::Uuid::new_v4().to_string();
    Ok((private_pem, public_pem, kid))
}

/// Build a JWK (JSON) from a public key PEM and kid, dispatching on algorithm.
pub fn public_key_to_jwk(alg: SigningAlgorithm, public_key_pem: &str, kid: &str) -> Result<Value> {
    match alg {
        SigningAlgorithm::EdDsa => ed25519_public_key_to_jwk(public_key_pem, kid),
        SigningAlgorithm::Rs256 => rsa_public_key_to_jwk(public_key_pem, kid),
    }
}

fn ed25519_public_key_to_jwk(public_key_pem: &str, kid: &str) -> Result<Value> {
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)?;
    let bytes = verifying_key.to_bytes();
    let x = URL_SAFE_NO_PAD.encode(bytes);

    Ok(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "kid": kid,
        "x": x,
    }))
}

fn rsa_public_key_to_jwk(public_key_pem: &str, kid: &str) -> Result<Value> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| anyhow!("parsing RSA public key PEM: {e}"))?;
    // JWK RSA params: n (modulus) and e (exponent), both base64url, unpadded,
    // using big-endian unsigned byte representation with no leading zeros.
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    Ok(json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    }))
}

/// Create a jsonwebtoken EncodingKey from a PKCS#8 PEM private key, dispatching on algorithm.
pub fn encoding_key_from_pem(
    alg: SigningAlgorithm,
    private_key_pem: &str,
) -> Result<jsonwebtoken::EncodingKey> {
    let key = match alg {
        SigningAlgorithm::EdDsa => {
            jsonwebtoken::EncodingKey::from_ed_pem(private_key_pem.as_bytes())?
        }
        SigningAlgorithm::Rs256 => {
            jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?
        }
    };
    Ok(key)
}

/// Create a jsonwebtoken DecodingKey from an SPKI PEM public key, dispatching on algorithm.
pub fn decoding_key_from_pem(
    alg: SigningAlgorithm,
    public_key_pem: &str,
) -> Result<jsonwebtoken::DecodingKey> {
    let key = match alg {
        SigningAlgorithm::EdDsa => {
            jsonwebtoken::DecodingKey::from_ed_pem(public_key_pem.as_bytes())?
        }
        SigningAlgorithm::Rs256 => {
            jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?
        }
    };
    Ok(key)
}

/// Translate our SigningAlgorithm enum to jsonwebtoken's Algorithm enum.
pub fn jwt_algorithm(alg: SigningAlgorithm) -> jsonwebtoken::Algorithm {
    match alg {
        SigningAlgorithm::EdDsa => jsonwebtoken::Algorithm::EdDSA,
        SigningAlgorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ed25519_produces_valid_pem() {
        let (priv_pem, pub_pem, kid) = generate_keypair(SigningAlgorithm::EdDsa).unwrap();
        assert!(priv_pem.contains("PRIVATE KEY"));
        assert!(pub_pem.contains("PUBLIC KEY"));
        assert!(!kid.is_empty());
    }

    #[test]
    fn generate_rsa_produces_valid_pem() {
        let (priv_pem, pub_pem, kid) = generate_keypair(SigningAlgorithm::Rs256).unwrap();
        assert!(priv_pem.contains("PRIVATE KEY"));
        assert!(pub_pem.contains("PUBLIC KEY"));
        assert!(!kid.is_empty());
    }

    #[test]
    fn ed25519_jwk_has_okp_kty() {
        let (_, pub_pem, kid) = generate_keypair(SigningAlgorithm::EdDsa).unwrap();
        let jwk = public_key_to_jwk(SigningAlgorithm::EdDsa, &pub_pem, &kid).unwrap();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["kid"], kid);
        assert!(jwk["x"].as_str().is_some());
    }

    #[test]
    fn rsa_jwk_has_rsa_kty_with_n_and_e() {
        let (_, pub_pem, kid) = generate_keypair(SigningAlgorithm::Rs256).unwrap();
        let jwk = public_key_to_jwk(SigningAlgorithm::Rs256, &pub_pem, &kid).unwrap();
        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS256");
        assert_eq!(jwk["kid"], kid);
        assert!(jwk["n"].as_str().is_some());
        assert!(jwk["e"].as_str().is_some());
    }

    #[test]
    fn encoding_decoding_keys_rs256_roundtrip() {
        let (priv_pem, pub_pem, _kid) = generate_keypair(SigningAlgorithm::Rs256).unwrap();
        assert!(encoding_key_from_pem(SigningAlgorithm::Rs256, &priv_pem).is_ok());
        assert!(decoding_key_from_pem(SigningAlgorithm::Rs256, &pub_pem).is_ok());
    }

    #[test]
    fn encoding_decoding_keys_eddsa_roundtrip() {
        let (priv_pem, pub_pem, _kid) = generate_keypair(SigningAlgorithm::EdDsa).unwrap();
        assert!(encoding_key_from_pem(SigningAlgorithm::EdDsa, &priv_pem).is_ok());
        assert!(decoding_key_from_pem(SigningAlgorithm::EdDsa, &pub_pem).is_ok());
    }
}
