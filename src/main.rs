mod audit;
mod branding;
mod cli;
mod config;
mod crypto;
mod db;
mod models;
mod server;

use anyhow::Result;
use clap::Parser;
use std::path::Path;
use std::sync::Arc;

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

    // Env var wins over config, so operators can keep the key out of
    // config-on-disk if they prefer (e.g. inject via systemd/docker).
    let key_hex = std::env::var("ANZ_MFA_SECRET_KEY")
        .ok()
        .or_else(|| config.mfa_secret_key_hex.clone());
    let cipher = Arc::new(crypto::secret_cipher::SecretCipher::from_hex_key(
        key_hex.as_deref(),
    )?);
    if !cipher.is_active() {
        tracing::warn!(
            "ANZ_MFA_SECRET_KEY not set; TOTP secrets will be stored in plaintext. \
             Set the env var (or mfa_secret_key_hex in config) to a 64-char hex value \
             to enable encryption at rest."
        );
    }

    match cli.command {
        cli::Commands::Realm { action } => cli::realm::handle(action, &conn)?,
        cli::Commands::User { action } => cli::user::handle(action, &conn, &cipher)?,
        cli::Commands::Client { action } => cli::client::handle(action, &conn)?,
        cli::Commands::Session { action } => cli::session::handle(action, &conn)?,
        cli::Commands::Serve => cli::serve::run(config, conn, cipher)?,
    }

    Ok(())
}
