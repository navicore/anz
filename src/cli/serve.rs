use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use rusqlite::Connection;

use crate::audit::AuditLogger;
use crate::config::Config;
use crate::crypto::secret_cipher::SecretCipher;
use crate::server;

pub fn run(
    config: Config,
    conn: Connection,
    secret_cipher: Arc<SecretCipher>,
    audit: AuditLogger,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let addr = config.bind_address.clone();
        let app = server::build_router(config, conn, audit, secret_cipher);

        tracing::info!("Listening on {addr}");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    })
}
