//! Dropbox-compatible API surface.
//!
//! Implements the subset of the Dropbox v2 API needed to make official
//! Dropbox clients work against a bibliotheca subvolume. Each user gets a
//! per-token namespace that resolves to subvolumes they own or have ACL
//! access to.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::routing::post;
use axum::Router;
use bibliotheca_core::service::BibliothecaService;
use tracing::info;

#[derive(Clone)]
struct AppState {
    #[allow(dead_code)]
    svc: BibliothecaService,
}

#[derive(Debug, Clone)]
pub struct DropboxConfig {
    pub listen: SocketAddr,
}

pub async fn start(svc: BibliothecaService, cfg: DropboxConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState { svc });
    let app = Router::new()
        .route("/2/files/list_folder", post(list_folder))
        .route("/2/files/upload", post(upload))
        .route("/2/files/download", post(download))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-dropbox listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn list_folder() -> &'static str {
    // TODO(spec): https://www.dropbox.com/developers/documentation/http/documentation#files-list_folder
    "{}"
}
async fn upload() -> &'static str {
    "{}"
}
async fn download() -> &'static str {
    "{}"
}
