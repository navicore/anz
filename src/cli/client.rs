use anyhow::{bail, Result};
use clap::Subcommand;
use rusqlite::Connection;

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
        } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let client =
                db::client::create_client(conn, &realm_obj.id, &client_id, &redirect_uri)?;
            println!(
                "Created client '{}' in realm '{}' (id: {})",
                client.client_id, realm, client.id
            );
            for uri in &client.redirect_uris {
                println!("  redirect_uri: {uri}");
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
