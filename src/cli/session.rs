use anyhow::{bail, Result};
use clap::Subcommand;
use rusqlite::Connection;

use crate::db;

#[derive(Subcommand)]
pub enum SessionAction {
    /// List active sessions for a user
    List {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
    },
    /// Revoke all sessions for a user
    Revoke {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
    },
    /// Clean up expired sessions across all realms
    Cleanup,
}

pub fn handle(action: SessionAction, conn: &Connection) -> Result<()> {
    match action {
        SessionAction::List { realm, username } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let user = db::user::get_user_by_username(conn, &realm_obj.id, &username)?;
            let user = match user {
                Some(u) => u,
                None => bail!("User '{username}' not found in realm '{realm}'"),
            };

            let sessions = db::session::list_sessions(conn, &realm_obj.id, &user.id)?;
            if sessions.is_empty() {
                println!("No active sessions for '{username}' in realm '{realm}'.");
            } else {
                let header = format!("{:<38} {:<26} EXPIRES", "SESSION ID", "CREATED");
                println!("{header}");
                for s in sessions {
                    println!("{:<38} {:<26} {}", s.id, s.created_at, s.expires_at);
                }
            }
        }
        SessionAction::Revoke { realm, username } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let user = db::user::get_user_by_username(conn, &realm_obj.id, &username)?;
            let user = match user {
                Some(u) => u,
                None => bail!("User '{username}' not found in realm '{realm}'"),
            };

            let count = db::session::revoke_user_sessions(conn, &realm_obj.id, &user.id)?;
            println!("Revoked {count} session(s) for '{username}' in realm '{realm}'");
        }
        SessionAction::Cleanup => {
            let count = db::session::cleanup_expired_sessions(conn)?;
            println!("Cleaned up {count} expired session(s)");
        }
    }
    Ok(())
}
