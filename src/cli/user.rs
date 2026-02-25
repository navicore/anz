use anyhow::{bail, Result};
use clap::Subcommand;
use rusqlite::Connection;

use crate::crypto::password::hash_password;
use crate::db;

#[derive(Subcommand)]
pub enum UserAction {
    /// Add a user to a realm
    Add {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
        /// Email
        #[arg(long)]
        email: String,
    },
    /// List users in a realm
    List {
        /// Realm name
        #[arg(long)]
        realm: String,
    },
    /// Remove a user from a realm
    Remove {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
    },
}

pub fn handle(action: UserAction, conn: &Connection) -> Result<()> {
    match action {
        UserAction::Add {
            realm,
            username,
            email,
        } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            eprint!("Password: ");
            let password = rpassword::read_password()?;
            if password.is_empty() {
                bail!("Password cannot be empty");
            }
            eprint!("Confirm password: ");
            let confirm = rpassword::read_password()?;
            if password != confirm {
                bail!("Passwords do not match");
            }

            let pw_hash = hash_password(&password)?;
            let user = db::user::create_user(conn, &realm_obj.id, &username, &email, &pw_hash)?;
            println!("Created user '{}' in realm '{}' (id: {})", user.username, realm, user.id);
        }
        UserAction::List { realm } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let users = db::user::list_users(conn, &realm_obj.id)?;
            if users.is_empty() {
                println!("No users in realm '{realm}'.");
            } else {
                for u in users {
                    println!("{:<20} {:<30} {}", u.username, u.email, u.id);
                }
            }
        }
        UserAction::Remove { realm, username } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            if db::user::delete_user(conn, &realm_obj.id, &username)? {
                println!("Removed user '{username}' from realm '{realm}'");
            } else {
                println!("User '{username}' not found in realm '{realm}'");
            }
        }
    }
    Ok(())
}
