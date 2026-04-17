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
}

impl AppState {
    /// Check whether the given IP has exceeded the login rate limit.
    /// Returns Ok(()) if allowed, Err(retry_after_secs) if rate-limited.
    pub fn check_login_rate_limit(&self, ip: IpAddr) -> Result<(), u64> {
        let window = std::time::Duration::from_secs(self.config.login_rate_limit_window_secs);
        let max = self.config.login_rate_limit_max;
        let cutoff = Instant::now() - window;

        let mut attempts = self
            .login_attempts
            .lock()
            .map_err(|_| self.config.login_rate_limit_window_secs)?;

        let entry = attempts.entry(ip).or_default();
        entry.retain(|t| *t > cutoff);

        if entry.len() >= max as usize {
            let oldest = entry.first().copied().unwrap_or_else(Instant::now);
            let retry_after = window
                .checked_sub(oldest.elapsed())
                .unwrap_or(window)
                .as_secs();
            Err(retry_after)
        } else {
            Ok(())
        }
    }

    pub fn record_login_attempt(&self, ip: IpAddr) {
        if let Ok(mut attempts) = self.login_attempts.lock() {
            attempts.entry(ip).or_default().push(Instant::now());
        }
    }

    /// Per-user MFA rate limit — 5 attempts per 5-minute window.
    /// A 6-digit TOTP code has 1,000,000 possibilities; 5 guesses per window
    /// renders brute force infeasible within the 30-second TOTP step.
    pub fn check_mfa_rate_limit(&self, user_id: &str) -> Result<(), u64> {
        let window = std::time::Duration::from_secs(300);
        let max: usize = 5;
        let cutoff = Instant::now() - window;

        let mut attempts = self.mfa_attempts.lock().map_err(|_| 300u64)?;
        let entry = attempts.entry(user_id.to_string()).or_default();
        entry.retain(|t| *t > cutoff);

        if entry.len() >= max {
            let oldest = entry.first().copied().unwrap_or_else(Instant::now);
            let retry_after = window
                .checked_sub(oldest.elapsed())
                .unwrap_or(window)
                .as_secs();
            Err(retry_after)
        } else {
            Ok(())
        }
    }

    pub fn record_mfa_attempt(&self, user_id: &str) {
        if let Ok(mut attempts) = self.mfa_attempts.lock() {
            attempts
                .entry(user_id.to_string())
                .or_default()
                .push(Instant::now());
        }
    }
}

pub fn build_router(config: Config, conn: Connection, audit: AuditLogger) -> Router {
    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        config: Arc::new(config),
        audit,
        login_attempts: Arc::new(Mutex::new(HashMap::new())),
        mfa_attempts: Arc::new(Mutex::new(HashMap::new())),
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
        }
    }

    #[test]
    fn rate_limit_allows_under_max() {
        let state = test_state();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        state.record_login_attempt(ip);
        state.record_login_attempt(ip);
        assert!(state.check_login_rate_limit(ip).is_ok());
    }

    #[test]
    fn rate_limit_blocks_at_max() {
        let state = test_state();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        for _ in 0..3 {
            state.record_login_attempt(ip);
        }
        assert!(state.check_login_rate_limit(ip).is_err());
    }

    #[test]
    fn rate_limit_separate_per_ip() {
        let state = test_state();
        let ip_a: IpAddr = "10.0.0.3".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.4".parse().unwrap();

        for _ in 0..3 {
            state.record_login_attempt(ip_a);
        }
        assert!(state.check_login_rate_limit(ip_a).is_err());
        assert!(state.check_login_rate_limit(ip_b).is_ok());
    }

    #[test]
    fn mfa_rate_limit_blocks_at_5() {
        let state = test_state();
        let uid = "user-1";
        for _ in 0..5 {
            state.record_mfa_attempt(uid);
        }
        assert!(state.check_mfa_rate_limit(uid).is_err());
        assert!(state.check_mfa_rate_limit("user-2").is_ok());
    }
}
