use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Subcommand;
use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::db;

#[derive(Subcommand)]
pub enum ClientAction {
    /// Register a client in a realm
    Add {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Client ID (application identifier)
        #[arg(long)]
        client_id: String,
        /// Redirect URI (can be specified multiple times)
        #[arg(long)]
        redirect_uri: Vec<String>,
        /// Generate a client secret (for confidential clients like Forgejo)
        #[arg(long)]
        secret: bool,
    },
    /// List clients in a realm
    List {
        /// Realm name
        #[arg(long)]
        realm: String,
    },
    /// Remove a client from a realm
    Remove {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Client ID
        #[arg(long)]
        client_id: String,
    },
}

pub fn handle(action: ClientAction, conn: &Connection) -> Result<()> {
    match action {
        ClientAction::Add {
            realm,
            client_id,
            redirect_uri,
            secret,
        } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let (raw_secret, secret_hash) = if secret {
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                let raw = URL_SAFE_NO_PAD.encode(bytes);
                let hash = crypto::hex_encode(&Sha256::digest(raw.as_bytes()));
                (Some(raw), Some(hash))
            } else {
                (None, None)
            };

            let client = db::client::create_client(
                conn,
                &realm_obj.id,
                &client_id,
                &redirect_uri,
                secret_hash.as_deref(),
            )?;
            println!(
                "Created client '{}' in realm '{}' (id: {})",
                client.client_id, realm, client.id
            );
            for uri in &client.redirect_uris {
                println!("  redirect_uri: {uri}");
            }
            if let Some(raw) = raw_secret {
                println!("  client_secret: {raw}");
                println!("  (save this — it cannot be retrieved again)");
            }
        }
        ClientAction::List { realm } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let clients = db::client::list_clients(conn, &realm_obj.id)?;
            if clients.is_empty() {
                println!("No clients in realm '{realm}'.");
            } else {
                for c in clients {
                    println!("{:<20} {}", c.client_id, c.id);
                    for uri in &c.redirect_uris {
                        println!("  redirect_uri: {uri}");
                    }
                }
            }
        }
        ClientAction::Remove { realm, client_id } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            if db::client::delete_client(conn, &realm_obj.id, &client_id)? {
                println!("Removed client '{client_id}' from realm '{realm}'");
            } else {
                println!("Client '{client_id}' not found in realm '{realm}'");
            }
        }
    }
    Ok(())
}
