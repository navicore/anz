use anyhow::Result;
use clap::Subcommand;
use rusqlite::Connection;

use crate::db;

#[derive(Subcommand)]
pub enum RealmAction {
    /// Create a new realm
    Create {
        /// Realm name
        name: String,
    },
    /// List all realms
    List,
    /// Delete a realm
    Delete {
        /// Realm name
        name: String,
    },
}

pub fn handle(action: RealmAction, conn: &Connection) -> Result<()> {
    match action {
        RealmAction::Create { name } => {
            let realm = db::realm::create_realm(conn, &name)?;
            println!("Created realm '{}' (id: {})", realm.name, realm.id);
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
    }
    Ok(())
}
