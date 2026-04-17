use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Deserialize)]
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

    /// 32-byte AES-256-GCM key (64 hex chars) for encrypting TOTP secrets at
    /// rest. `ANZ_MFA_SECRET_KEY` env var takes precedence. Absent → warning at
    /// startup and plaintext storage for backward compatibility.
    #[serde(default)]
    pub mfa_secret_key_hex: Option<String>,

    /// Append `Secure` to session and CSRF cookies so browsers only send them
    /// over HTTPS. Default true (auth server) — set false for plain-HTTP local
    /// dev, where browsers otherwise silently refuse to return the cookie and
    /// login appears to loop.
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
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
fn default_secure_cookies() -> bool {
    true
}

impl Config {
    /// Suffix to splice into `Set-Cookie` headers: either `"; Secure"` (prod /
    /// HTTPS) or `""` (local HTTP dev). Keeps all cookie build sites uniform.
    pub fn cookie_secure_attr(&self) -> &'static str {
        if self.secure_cookies {
            "; Secure"
        } else {
            ""
        }
    }

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
            mfa_secret_key_hex: None,
            secure_cookies: default_secure_cookies(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let c = Config::default();
        assert_eq!(c.bind_address, "127.0.0.1:8080");
        assert_eq!(c.access_token_lifetime_secs, 3600);
        assert_eq!(c.auth_code_lifetime_secs, 300);
        assert_eq!(c.session_lifetime_secs, 86400);
        assert!(c.audit_log_enabled);
        assert_eq!(c.login_rate_limit_max, 5);
    }

    #[test]
    fn parse_partial_toml_fills_defaults() {
        let toml_str = r#"bind_address = "0.0.0.0:9090""#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:9090");
        assert_eq!(config.database_path, "anz.db");
    }

    #[test]
    fn parse_empty_toml_uses_all_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config, Config::default());
    }
}
