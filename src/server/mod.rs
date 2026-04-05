pub mod authorize;
pub mod discovery;
pub mod error;
pub mod jwks;
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
}

pub fn build_router(config: Config, conn: Connection, audit: AuditLogger) -> Router {
    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        config: Arc::new(config),
        audit,
        login_attempts: Arc::new(Mutex::new(HashMap::new())),
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
        .route(
            "/realms/{realm}/static/{*path}",
            get(static_files::serve_static),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
