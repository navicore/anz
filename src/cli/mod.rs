pub mod client;
pub mod realm;
pub mod serve;
pub mod user;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "anz", about = "Personal OIDC provider")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "anz.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage realms
    Realm {
        #[command(subcommand)]
        action: realm::RealmAction,
    },
    /// Manage users
    User {
        #[command(subcommand)]
        action: user::UserAction,
    },
    /// Manage clients
    Client {
        #[command(subcommand)]
        action: client::ClientAction,
    },
    /// Start the HTTP server
    Serve,
}
