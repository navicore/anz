use anyhow::{anyhow, Result};
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, encode, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::crypto::keys;
use crate::models::{SigningAlgorithm, SigningKeyRecord};

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

/// Encode a JWT signed with the given key and algorithm.
pub fn encode_jwt(
    claims: &impl Serialize,
    kid: &str,
    key: &EncodingKey,
    alg: SigningAlgorithm,
) -> Result<String> {
    let mut header = Header::new(keys::jwt_algorithm(alg));
    header.kid = Some(kid.to_string());

    let token = encode(&header, claims, key)?;
    Ok(token)
}

/// Decode and verify an access token by matching its `kid` header against the
/// realm's active signing keys. This supports rotation and multiple concurrent
/// algorithms — the key used to verify must match the key that signed.
pub fn decode_access_token(
    token: &str,
    active_keys: &[SigningKeyRecord],
    issuer: &str,
) -> Result<AccessTokenClaims> {
    let header = decode_header(token)?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| anyhow!("token header missing kid"))?;

    let key = active_keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| anyhow!("unknown kid in token: {kid}"))?;

    let decoding_key = keys::decoding_key_from_pem(key.algorithm, &key.public_key_pem)?;

    let mut validation = Validation::new(keys::jwt_algorithm(key.algorithm));
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    validation.validate_aud = false;

    let data = decode::<AccessTokenClaims>(token, &decoding_key, &validation)?;
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
    /// Space-separated scope string. Groups are only included when "groups" is in scope.
    pub scopes: &'a str,
}

pub fn build_id_token_claims(p: &IdTokenParams) -> IdTokenClaims {
    let now = Utc::now().timestamp();
    let has_groups_scope = p.scopes.split_whitespace().any(|s| s == "groups");
    IdTokenClaims {
        iss: p.issuer.to_string(),
        sub: p.sub.to_string(),
        aud: p.aud.to_string(),
        exp: now + p.lifetime_secs as i64,
        iat: now,
        nonce: p.nonce.clone(),
        preferred_username: p.username.to_string(),
        email: p.email.to_string(),
        groups: if has_groups_scope {
            p.groups.to_vec()
        } else {
            Vec::new()
        },
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

    fn init_crypto() {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    }

    fn keypair(alg: SigningAlgorithm) -> (EncodingKey, SigningKeyRecord) {
        let (priv_pem, pub_pem, kid) = keys::generate_keypair(alg).unwrap();
        let enc = keys::encoding_key_from_pem(alg, &priv_pem).unwrap();
        let record = SigningKeyRecord {
            private_key_pem: priv_pem,
            public_key_pem: pub_pem,
            kid,
            algorithm: alg,
        };
        (enc, record)
    }

    #[test]
    fn encode_decode_access_token_eddsa() {
        init_crypto();
        let (enc, record) = keypair(SigningAlgorithm::EdDsa);
        let issuer = "https://auth.example.com/realms/test";
        let claims = build_access_token_claims(issuer, "user1", issuer, 3600, "openid", "myapp");
        let token = encode_jwt(&claims, &record.kid, &enc, record.algorithm).unwrap();
        let decoded = decode_access_token(&token, &[record], issuer).unwrap();
        assert_eq!(decoded.sub, "user1");
        assert_eq!(decoded.client_id, "myapp");
    }

    #[test]
    fn encode_decode_access_token_rs256() {
        init_crypto();
        let (enc, record) = keypair(SigningAlgorithm::Rs256);
        let issuer = "https://auth.example.com/realms/test";
        let claims = build_access_token_claims(issuer, "user1", issuer, 3600, "openid", "myapp");
        let token = encode_jwt(&claims, &record.kid, &enc, record.algorithm).unwrap();
        let decoded = decode_access_token(&token, &[record], issuer).unwrap();
        assert_eq!(decoded.sub, "user1");
        assert_eq!(decoded.client_id, "myapp");
    }

    #[test]
    fn decode_picks_correct_key_from_multiple() {
        init_crypto();
        // Realm has both algorithms active. Token signed with one must decode against
        // the full set via kid matching.
        let (enc_ed, record_ed) = keypair(SigningAlgorithm::EdDsa);
        let (_enc_rs, record_rs) = keypair(SigningAlgorithm::Rs256);
        let issuer = "https://auth.example.com/realms/test";
        let claims = build_access_token_claims(issuer, "u", issuer, 3600, "openid", "c");
        let token = encode_jwt(&claims, &record_ed.kid, &enc_ed, record_ed.algorithm).unwrap();
        let all_keys = vec![record_rs, record_ed];
        let decoded = decode_access_token(&token, &all_keys, issuer).unwrap();
        assert_eq!(decoded.sub, "u");
    }

    #[test]
    fn id_token_claims_include_groups_when_scoped() {
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
            scopes: "openid groups",
        });
        assert_eq!(claims.preferred_username, "alice");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.nonce, Some("nonce123".to_string()));
        assert_eq!(claims.groups, vec!["admin", "dev"]);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn id_token_claims_omit_groups_without_scope() {
        let groups = vec!["admin".to_string()];
        let claims = build_id_token_claims(&IdTokenParams {
            issuer: "https://iss",
            sub: "sub1",
            aud: "aud1",
            lifetime_secs: 3600,
            username: "alice",
            email: "alice@example.com",
            nonce: None,
            groups: &groups,
            scopes: "openid profile email",
        });
        assert!(claims.groups.is_empty());
    }

    #[test]
    fn wrong_issuer_rejects_token() {
        init_crypto();
        let (enc, record) = keypair(SigningAlgorithm::Rs256);
        let claims = build_access_token_claims(
            "https://issuer-a",
            "u",
            "https://issuer-a",
            3600,
            "openid",
            "c",
        );
        let token = encode_jwt(&claims, &record.kid, &enc, record.algorithm).unwrap();
        assert!(decode_access_token(&token, &[record], "https://issuer-b").is_err());
    }

    #[test]
    fn unknown_kid_is_rejected() {
        init_crypto();
        let (enc, record) = keypair(SigningAlgorithm::Rs256);
        let issuer = "https://iss";
        let claims = build_access_token_claims(issuer, "u", issuer, 3600, "openid", "c");
        let token = encode_jwt(&claims, &record.kid, &enc, record.algorithm).unwrap();
        // Empty key list → no matching kid.
        assert!(decode_access_token(&token, &[], issuer).is_err());
    }
}
