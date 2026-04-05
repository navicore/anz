use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_issuer_base_url")]
    pub issuer_base_url: String,

    #[serde(default = "default_database_path")]
    pub database_path: String,

    #[serde(default = "default_access_token_lifetime")]
    pub access_token_lifetime_secs: u64,

    #[serde(default = "default_id_token_lifetime")]
    pub id_token_lifetime_secs: u64,

    #[serde(default = "default_refresh_token_lifetime")]
    pub refresh_token_lifetime_secs: u64,

    #[serde(default = "default_auth_code_lifetime")]
    pub auth_code_lifetime_secs: u64,

    #[serde(default = "default_session_lifetime")]
    pub session_lifetime_secs: u64,

    #[serde(default = "default_audit_log_enabled")]
    pub audit_log_enabled: bool,

    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: String,

    #[serde(default = "default_login_rate_limit_max")]
    pub login_rate_limit_max: u32,

    #[serde(default = "default_login_rate_limit_window_secs")]
    pub login_rate_limit_window_secs: u64,

    #[serde(default = "default_realms_dir")]
    pub realms_dir: String,
}

fn default_bind_address() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_issuer_base_url() -> String {
    "http://localhost:8080".to_string()
}
fn default_database_path() -> String {
    "anz.db".to_string()
}
fn default_access_token_lifetime() -> u64 {
    3600
}
fn default_id_token_lifetime() -> u64 {
    3600
}
fn default_refresh_token_lifetime() -> u64 {
    2_592_000
}
fn default_auth_code_lifetime() -> u64 {
    300
}
fn default_session_lifetime() -> u64 {
    86400
}
fn default_audit_log_enabled() -> bool {
    true
}
fn default_audit_log_path() -> String {
    "audit.log".to_string()
}
fn default_login_rate_limit_max() -> u32 {
    5
}
fn default_login_rate_limit_window_secs() -> u64 {
    300
}
fn default_realms_dir() -> String {
    "realms".to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;
        Ok(config)
    }

    pub fn load_or_default(path: &Path) -> Self {
        match Self::load(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "Could not load config from {}: {e:#}; using defaults",
                    path.display()
                );
                Self::default()
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_address: default_bind_address(),
            issuer_base_url: default_issuer_base_url(),
            database_path: default_database_path(),
            access_token_lifetime_secs: default_access_token_lifetime(),
            id_token_lifetime_secs: default_id_token_lifetime(),
            refresh_token_lifetime_secs: default_refresh_token_lifetime(),
            auth_code_lifetime_secs: default_auth_code_lifetime(),
            session_lifetime_secs: default_session_lifetime(),
            audit_log_enabled: default_audit_log_enabled(),
            audit_log_path: default_audit_log_path(),
            login_rate_limit_max: default_login_rate_limit_max(),
            login_rate_limit_window_secs: default_login_rate_limit_window_secs(),
            realms_dir: default_realms_dir(),
        }
    }
}
