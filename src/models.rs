use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub realm_id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    pub realm_id: String,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub id: String,
    pub realm_id: String,
    pub client_id: String,
    pub user_id: String,
    pub code_hash: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub id: String,
    pub realm_id: String,
    pub client_id: String,
    pub user_id: String,
    pub token_hash: String,
    pub scopes: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct SigningKeyRecord {
    pub id: String,
    pub realm_id: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub kid: String,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub session_token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
