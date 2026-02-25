use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};

/// Generate a new Ed25519 keypair. Returns (private_key_pem, public_key_pem, kid).
pub fn generate_ed25519_keypair() -> Result<(String, String, String)> {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let private_pem = signing_key
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?
        .to_string();
    let public_pem = verifying_key
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?;

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

/// Load a signing key from PKCS#8 PEM. Used to verify the key is valid.
pub fn load_signing_key(private_key_pem: &str) -> Result<SigningKey> {
    let key = SigningKey::from_pkcs8_pem(private_key_pem)?;
    Ok(key)
}
