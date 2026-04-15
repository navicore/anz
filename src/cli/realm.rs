use anyhow::{bail, Result};
use clap::{Subcommand, ValueEnum};
use rusqlite::Connection;

use crate::crypto::keys::generate_keypair;
use crate::db;
use crate::db::signing_key::{insert_signing_key, NewSigningKey};
use crate::models::SigningAlgorithm;

/// CLI-facing algorithm name. Kept separate from the domain enum so clap's value
/// parsing doesn't leak into the core types.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KeyType {
    /// RSA with SHA-256 (RS256). Required by Kubernetes and most older OIDC clients.
    Rs256,
    /// EdDSA using Ed25519. Compact and fast; not all OIDC clients accept it.
    Ed25519,
}

impl From<KeyType> for SigningAlgorithm {
    fn from(k: KeyType) -> Self {
        match k {
            KeyType::Rs256 => SigningAlgorithm::Rs256,
            KeyType::Ed25519 => SigningAlgorithm::EdDsa,
        }
    }
}

#[derive(Subcommand)]
pub enum RealmAction {
    /// Create a new realm (auto-generates a signing key)
    Create {
        /// Realm name
        name: String,
        /// Signing algorithm for the realm's initial key. Defaults to RS256 for broad
        /// OIDC client compatibility. Use ed25519 only if all consumers support EdDSA.
        #[arg(long, value_enum, default_value = "rs256")]
        key_type: KeyType,
    },
    /// List all realms
    List,
    /// Delete a realm
    Delete {
        /// Realm name
        name: String,
    },
    /// Add a new active signing key to a realm (does not deactivate existing keys).
    /// Use for key rotation: add new key, update clients if needed, later deactivate old key.
    RotateKey {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Signing algorithm for the new key
        #[arg(long, value_enum)]
        key_type: KeyType,
    },
    /// Mark an existing signing key inactive. Its public material stays in JWKS for
    /// as long as it remains in the database (for verifying outstanding tokens).
    DeactivateKey {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// The kid (key id) to deactivate
        #[arg(long)]
        kid: String,
    },
}

pub fn handle(action: RealmAction, conn: &Connection) -> Result<()> {
    match action {
        RealmAction::Create { name, key_type } => {
            let alg = SigningAlgorithm::from(key_type);
            let realm = db::realm::create_realm(conn, &name, alg)?;
            println!(
                "Created realm '{}' (id: {}, signing algorithm: {})",
                realm.name,
                realm.id,
                alg.as_jwt_alg()
            );
        }
        RealmAction::List => {
            let realms = db::realm::list_realms(conn)?;
            if realms.is_empty() {
                println!("No realms found.");
            } else {
                for r in realms {
                    println!("{:<20} {}", r.name, r.id);
                }
            }
        }
        RealmAction::Delete { name } => {
            if db::realm::delete_realm(conn, &name)? {
                println!("Deleted realm '{name}'");
            } else {
                println!("Realm '{name}' not found.");
            }
        }
        RealmAction::RotateKey { realm, key_type } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?
                .ok_or_else(|| anyhow::anyhow!("Realm '{realm}' not found"))?;
            let alg = SigningAlgorithm::from(key_type);
            let (private_pem, public_pem, kid) = generate_keypair(alg)?;
            insert_signing_key(
                conn,
                &NewSigningKey {
                    realm_id: &realm_obj.id,
                    private_key_pem: &private_pem,
                    public_key_pem: &public_pem,
                    kid: &kid,
                    algorithm: alg,
                },
            )?;
            println!(
                "Added new active signing key to realm '{}': algorithm={}, kid={}",
                realm,
                alg.as_jwt_alg(),
                kid
            );
            println!(
                "  Existing keys remain active. Use `anz realm deactivate-key` to remove them once clients have rotated."
            );
        }
        RealmAction::DeactivateKey { realm, kid } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?
                .ok_or_else(|| anyhow::anyhow!("Realm '{realm}' not found"))?;
            if db::signing_key::deactivate_signing_key(conn, &realm_obj.id, &kid)? {
                println!("Deactivated signing key '{kid}' in realm '{realm}'");
            } else {
                bail!("No active signing key with kid '{kid}' in realm '{realm}'");
            }
        }
    }
    Ok(())
}
