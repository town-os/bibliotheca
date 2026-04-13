//! Solid (Social Linked Data) interface.
//!
//! Solid layers on top of LDP/WebDAV with WebID auth. The plan is to
//! treat one subvolume as one Pod, exposing the pod root at
//! `/pods/<subvolume_name>/`. ACL semantics map onto WAC documents
//! (`.acl` companion files) generated from the subvolume ACL.

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
pub struct SolidConfig {
    pub listen: SocketAddr,
    pub base_url: String,
}

pub async fn start(svc: BibliothecaService, cfg: SolidConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState { svc });
    let app = Router::new()
        .route("/pods/:pod/*path", any(pod_op))
        .route("/pods/:pod", any(pod_op))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, base_url = %cfg.base_url, "bibliotheca-solid listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn pod_op() -> &'static str {
    // TODO(spec): LDP verbs (GET/PUT/POST/PATCH/DELETE/HEAD/OPTIONS),
    // .acl handling, WebID-OIDC auth.
    ""
}
