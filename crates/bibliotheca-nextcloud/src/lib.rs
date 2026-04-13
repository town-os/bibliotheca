//! Nextcloud-compatible WebDAV + OCS interface.
//!
//! Exposes `/remote.php/dav/files/<user>/...` and the OCS share API so
//! that the official Nextcloud desktop and mobile clients can sync
//! against a bibliotheca user's home subvolume.

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
pub struct NextcloudConfig {
    pub listen: SocketAddr,
}

pub async fn start(svc: BibliothecaService, cfg: NextcloudConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState { svc });
    let app = Router::new()
        .route("/remote.php/dav/files/:user/*path", any(dav_op))
        .route(
            "/ocs/v2.php/apps/files_sharing/api/v1/shares",
            any(shares_op),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-nextcloud listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn dav_op() -> &'static str {
    // TODO(spec): WebDAV verbs (PROPFIND, MKCOL, MOVE, COPY, etc.)
    ""
}

async fn shares_op() -> &'static str {
    // TODO(spec): OCS share API.
    ""
}
