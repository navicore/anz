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
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: String,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub id: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: String,
}

#[derive(Debug, Clone)]
pub struct SigningKeyRecord {
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub kid: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
}
