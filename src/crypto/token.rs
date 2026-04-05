use anyhow::Result;
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub preferred_username: String,
    pub email: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub scope: String,
    pub client_id: String,
}

pub fn encode_jwt(claims: &impl Serialize, kid: &str, key: &EncodingKey) -> Result<String> {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());

    let token = encode(&header, claims, key)?;
    Ok(token)
}

pub fn decode_access_token(
    token: &str,
    key: &DecodingKey,
    issuer: &str,
) -> Result<AccessTokenClaims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    validation.validate_aud = false;

    let data = decode::<AccessTokenClaims>(token, key, &validation)?;
    Ok(data.claims)
}

pub struct IdTokenParams<'a> {
    pub issuer: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub lifetime_secs: u64,
    pub username: &'a str,
    pub email: &'a str,
    pub nonce: Option<String>,
    pub groups: &'a [String],
}

pub fn build_id_token_claims(p: &IdTokenParams) -> IdTokenClaims {
    let now = Utc::now().timestamp();
    IdTokenClaims {
        iss: p.issuer.to_string(),
        sub: p.sub.to_string(),
        aud: p.aud.to_string(),
        exp: now + p.lifetime_secs as i64,
        iat: now,
        nonce: p.nonce.clone(),
        preferred_username: p.username.to_string(),
        email: p.email.to_string(),
        groups: p.groups.to_vec(),
    }
}

pub fn build_access_token_claims(
    issuer: &str,
    sub: &str,
    aud: &str,
    lifetime_secs: u64,
    scope: &str,
    client_id: &str,
) -> AccessTokenClaims {
    let now = Utc::now().timestamp();
    AccessTokenClaims {
        iss: issuer.to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: now + lifetime_secs as i64,
        iat: now,
        scope: scope.to_string(),
        client_id: client_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys;

    fn init_crypto() {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    }

    fn test_keypair() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey, String) {
        let (priv_pem, pub_pem, kid) = keys::generate_ed25519_keypair().unwrap();
        let enc = keys::encoding_key_from_pem(&priv_pem).unwrap();
        let dec = keys::decoding_key_from_pem(&pub_pem).unwrap();
        (enc, dec, kid)
    }

    #[test]
    fn encode_decode_access_token() {
        init_crypto();
        let (enc, dec, kid) = test_keypair();
        let issuer = "https://auth.example.com/realms/test";
        let claims = build_access_token_claims(issuer, "user1", issuer, 3600, "openid", "myapp");
        let token = encode_jwt(&claims, &kid, &enc).unwrap();
        let decoded = decode_access_token(&token, &dec, issuer).unwrap();
        assert_eq!(decoded.sub, "user1");
        assert_eq!(decoded.client_id, "myapp");
        assert_eq!(decoded.scope, "openid");
    }

    #[test]
    fn id_token_claims_have_correct_fields() {
        let groups = vec!["admin".to_string(), "dev".to_string()];
        let claims = build_id_token_claims(&IdTokenParams {
            issuer: "https://iss",
            sub: "sub1",
            aud: "aud1",
            lifetime_secs: 3600,
            username: "alice",
            email: "alice@example.com",
            nonce: Some("nonce123".to_string()),
            groups: &groups,
        });
        assert_eq!(claims.preferred_username, "alice");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.nonce, Some("nonce123".to_string()));
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn wrong_issuer_rejects_token() {
        init_crypto();
        let (enc, dec, kid) = test_keypair();
        let claims = build_access_token_claims(
            "https://issuer-a",
            "u",
            "https://issuer-a",
            3600,
            "openid",
            "c",
        );
        let token = encode_jwt(&claims, &kid, &enc).unwrap();
        assert!(decode_access_token(&token, &dec, "https://issuer-b").is_err());
    }
}
