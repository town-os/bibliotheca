//! iCloud Drive interface (CloudKit Web Services-shaped).
//!
//! Apple's iCloud protocol is undocumented; this crate targets the
//! CloudKit Web Services surface that third-party tools use for
//! interoperability. It is the most experimental of the interface
//! crates and exists primarily so the daemon's interface enumeration
//! is complete — the protocol details will land incrementally.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::routing::any;
use axum::Router;
use bibliotheca_core::service::BibliothecaService;
use tracing::info;

#[derive(Clone)]
struct AppState {
    #[allow(dead_code)]
    svc: BibliothecaService,
}

#[derive(Debug, Clone)]
pub struct ICloudConfig {
    pub listen: SocketAddr,
    pub container: String,
}

pub async fn start(svc: BibliothecaService, cfg: ICloudConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState { svc });
    let app = Router::new()
        .route(
            "/database/1/:container/:env/public/records/query",
            any(records_query),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, container = %cfg.container, "bibliotheca-icloud listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn records_query() -> &'static str {
    "{}"
}
