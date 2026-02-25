use anyhow::Result;
use rusqlite::Connection;

use crate::config::Config;
use crate::server;

pub fn run(config: Config, conn: Connection) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let addr = config.bind_address.clone();
        let app = server::build_router(config, conn);

        tracing::info!("Listening on {addr}");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    })
}
