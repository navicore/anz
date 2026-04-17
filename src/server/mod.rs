pub mod authorize;
pub mod discovery;
pub mod error;
pub mod jwks;
pub mod mfa;
pub mod password;
pub mod revoke;
pub mod static_files;
pub mod token;
pub mod userinfo;

use crate::audit::AuditLogger;
use crate::config::Config;
use crate::crypto::secret_cipher::SecretCipher;
use axum::routing::{get, post};
use axum::Router;
use rusqlite::Connection;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub config: Arc<Config>,
    pub audit: AuditLogger,
    pub login_attempts: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    /// Per-user MFA attempt tracker — keyed by user_id, separate from per-IP login limit.
    pub mfa_attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    /// Encrypts TOTP secrets (stored in `user_mfa` and in pending-enrollment
    /// challenge blobs). Noop if no key is configured.
    pub secret_cipher: Arc<SecretCipher>,
}

/// Atomic "check, prune, evict, record" for a sliding-window rate limiter. Under
/// a single lock: prune timestamps older than `window`, drop the entry if the
/// vec empties, reject if already at `max`, otherwise push `now` and return Ok.
/// Eliminates the TOCTOU window between a separate check and record, and keeps
/// the map from growing unbounded with stale entries.
fn consume_slot<K: std::hash::Hash + Eq>(
    attempts: &Mutex<HashMap<K, Vec<Instant>>>,
    key: K,
    window: std::time::Duration,
    max: usize,
    fallback_retry_after: u64,
) -> Result<(), u64> {
    let mut attempts = attempts.lock().map_err(|_| fallback_retry_after)?;
    let now = Instant::now();
    let cutoff = now - window;

    // Sweep the whole map so entries whose window has elapsed without a new
    // attempt don't accumulate — map stays bounded by concurrent active keys,
    // not all keys ever seen.
    attempts.retain(|_, v| {
        v.retain(|t| *t > cutoff);
        !v.is_empty()
    });

    let entry = attempts.entry(key).or_default();

    if entry.len() >= max {
        let oldest = entry.first().copied().unwrap_or(now);
        let retry_after = window
            .checked_sub(oldest.elapsed())
            .unwrap_or(window)
            .as_secs();
        return Err(retry_after);
    }
    entry.push(now);
    Ok(())
}

impl AppState {
    /// Atomically consume one login-rate-limit slot for the given IP.
    /// Returns Ok(()) if the request may proceed, Err(retry_after_secs) if blocked.
    pub fn consume_login_slot(&self, ip: IpAddr) -> Result<(), u64> {
        let window = std::time::Duration::from_secs(self.config.login_rate_limit_window_secs);
        consume_slot(
            &self.login_attempts,
            ip,
            window,
            self.config.login_rate_limit_max as usize,
            self.config.login_rate_limit_window_secs,
        )
    }

    /// Atomically consume one MFA-rate-limit slot for the given user. 5 attempts
    /// per 5-minute window — a 6-digit TOTP code has 1M possibilities; 5 guesses
    /// per window makes brute force infeasible within the 30-second TOTP step.
    pub fn consume_mfa_slot(&self, user_id: &str) -> Result<(), u64> {
        let window = std::time::Duration::from_secs(300);
        consume_slot(&self.mfa_attempts, user_id.to_string(), window, 5, 300)
    }
}

pub fn build_router(
    config: Config,
    conn: Connection,
    audit: AuditLogger,
    secret_cipher: Arc<SecretCipher>,
) -> Router {
    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        config: Arc::new(config),
        audit,
        login_attempts: Arc::new(Mutex::new(HashMap::new())),
        mfa_attempts: Arc::new(Mutex::new(HashMap::new())),
        secret_cipher,
    };

    Router::new()
        .route(
            "/realms/{realm}/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/realms/{realm}/jwks", get(jwks::jwks))
        .route(
            "/realms/{realm}/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route("/realms/{realm}/token", post(token::token))
        .route("/realms/{realm}/userinfo", get(userinfo::userinfo))
        .route("/realms/{realm}/password", post(password::change_password))
        .route("/realms/{realm}/revoke", post(revoke::revoke))
        .route("/realms/{realm}/mfa", post(mfa::submit))
        .route(
            "/realms/{realm}/static/{*path}",
            get(static_files::serve_static),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogger;

    fn test_state() -> AppState {
        let conn = crate::db::open_in_memory().unwrap();
        let config = Config {
            login_rate_limit_max: 3,
            login_rate_limit_window_secs: 300,
            ..Default::default()
        };
        AppState {
            db: Arc::new(Mutex::new(conn)),
            config: Arc::new(config),
            audit: AuditLogger::new(false, "/dev/null"),
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
            mfa_attempts: Arc::new(Mutex::new(HashMap::new())),
            secret_cipher: Arc::new(SecretCipher::noop()),
        }
    }

    #[test]
    fn rate_limit_allows_under_max() {
        let state = test_state();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(state.consume_login_slot(ip).is_ok());
        assert!(state.consume_login_slot(ip).is_ok());
        // A third call still succeeds — max is 3.
        assert!(state.consume_login_slot(ip).is_ok());
    }

    #[test]
    fn rate_limit_blocks_at_max() {
        let state = test_state();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        for _ in 0..3 {
            assert!(state.consume_login_slot(ip).is_ok());
        }
        assert!(state.consume_login_slot(ip).is_err());
    }

    #[test]
    fn rate_limit_separate_per_ip() {
        let state = test_state();
        let ip_a: IpAddr = "10.0.0.3".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.4".parse().unwrap();

        for _ in 0..3 {
            assert!(state.consume_login_slot(ip_a).is_ok());
        }
        assert!(state.consume_login_slot(ip_a).is_err());
        assert!(state.consume_login_slot(ip_b).is_ok());
    }

    #[test]
    fn mfa_rate_limit_blocks_at_5() {
        let state = test_state();
        for _ in 0..5 {
            assert!(state.consume_mfa_slot("user-1").is_ok());
        }
        assert!(state.consume_mfa_slot("user-1").is_err());
        assert!(state.consume_mfa_slot("user-2").is_ok());
    }
}
