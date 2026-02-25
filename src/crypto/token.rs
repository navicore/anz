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

    let data = decode::<AccessTokenClaims>(token, key, &validation)?;
    Ok(data.claims)
}

pub fn build_id_token_claims(
    issuer: &str,
    sub: &str,
    aud: &str,
    lifetime_secs: u64,
    username: &str,
    email: &str,
    nonce: Option<String>,
) -> IdTokenClaims {
    let now = Utc::now().timestamp();
    IdTokenClaims {
        iss: issuer.to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: now + lifetime_secs as i64,
        iat: now,
        nonce,
        preferred_username: username.to_string(),
        email: email.to_string(),
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
