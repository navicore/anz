mod cli;
mod config;
mod crypto;
mod db;
mod models;
mod server;

use anyhow::Result;
use clap::Parser;
use std::path::Path;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = cli::Cli::parse();
    let config = config::Config::load_or_default(&cli.config);
    let conn = db::open_database(Path::new(&config.database_path))?;

    match cli.command {
        cli::Commands::Realm { action } => cli::realm::handle(action, &conn)?,
        cli::Commands::User { action } => cli::user::handle(action, &conn)?,
        cli::Commands::Client { action } => cli::client::handle(action, &conn)?,
        cli::Commands::Serve => cli::serve::run(config, conn)?,
    }

    Ok(())
}
