use std::net::SocketAddr;

use anyhow::Result;
use rusqlite::Connection;

use crate::audit::AuditLogger;
use crate::config::Config;
use crate::server;

pub fn run(config: Config, conn: Connection) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let addr = config.bind_address.clone();
        let audit = AuditLogger::new(config.audit_log_enabled, &config.audit_log_path);
        let app = server::build_router(config, conn, audit);

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
