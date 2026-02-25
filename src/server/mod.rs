pub mod authorize;
pub mod discovery;
pub mod error;
pub mod jwks;
pub mod password;
pub mod token;
pub mod userinfo;

use crate::config::Config;
use axum::routing::{get, post};
use axum::Router;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub config: Arc<Config>,
}

pub fn build_router(config: Config, conn: Connection) -> Router {
    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        config: Arc::new(config),
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
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
