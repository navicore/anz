use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: String,
    pub name: String,
    pub mfa_required: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub realm_id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub groups: Vec<String>,
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
    pub client_secret_hash: Option<String>,
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
    pub nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub id: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// RSA with SHA-256 (RS256). OIDC Core spec requires this; required by Kubernetes.
    Rs256,
    /// EdDSA using Ed25519. Compact and fast but not supported by all OIDC clients.
    EdDsa,
}

impl SigningAlgorithm {
    /// JWT `alg` claim value as used in `id_token_signing_alg_values_supported`.
    pub fn as_jwt_alg(self) -> &'static str {
        match self {
            SigningAlgorithm::Rs256 => "RS256",
            SigningAlgorithm::EdDsa => "EdDSA",
        }
    }

    /// String stored in the `signing_keys.algorithm` column.
    pub fn as_db_value(self) -> &'static str {
        self.as_jwt_alg()
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "RS256" => Ok(SigningAlgorithm::Rs256),
            "EdDSA" => Ok(SigningAlgorithm::EdDsa),
            other => anyhow::bail!("unknown signing algorithm: {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigningKeyRecord {
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub kid: String,
    pub algorithm: SigningAlgorithm,
}

/// Metadata-only view of a signing key for listing commands. Excludes private key
/// material so we never accidentally leak it through CLI output.
#[derive(Debug, Clone)]
pub struct SigningKeyInfo {
    pub kid: String,
    pub algorithm: SigningAlgorithm,
    pub active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // constructed by db::user_mfa and used at runtime
pub struct UserMfa {
    pub user_id: String,
    pub secret_base32: String,
}

/// Pending second-step authentication state. Created after a successful password
/// step when MFA is required, consumed when the user submits a valid TOTP or
/// recovery code. Short-lived (5 minutes) — same hashing pattern as auth codes.
#[derive(Debug, Clone)]
#[allow(dead_code)] // constructed by db::mfa_challenge and used at runtime
pub struct MfaChallenge {
    pub user_id: String,
    pub authorize_params: String,
}
