//! Google Cloud Storage JSON API surface.
//!
//! Mirrors the v1 JSON API at https://storage.googleapis.com/storage/v1
//! so client libraries that point at a custom endpoint can talk to a
//! bibliotheca deployment. Bucket -> subvolume mapping matches the S3 crate.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::routing::{any, get};
use axum::Router;
use bibliotheca_core::service::BibliothecaService;
use tracing::info;

#[derive(Clone)]
struct AppState {
    #[allow(dead_code)]
    svc: BibliothecaService,
}

#[derive(Debug, Clone)]
pub struct GcsConfig {
    pub listen: SocketAddr,
}

pub async fn start(svc: BibliothecaService, cfg: GcsConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState { svc });
    let app = Router::new()
        .route("/storage/v1/b", get(list_buckets))
        .route("/storage/v1/b/:bucket", any(bucket_op))
        .route("/storage/v1/b/:bucket/o", any(list_objects))
        .route("/storage/v1/b/:bucket/o/*object", any(object_op))
        .route("/upload/storage/v1/b/:bucket/o", any(upload_object))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-gcs listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn list_buckets() -> &'static str {
    "{}"
}
async fn bucket_op() -> &'static str {
    "{}"
}
async fn list_objects() -> &'static str {
    "{}"
}
async fn object_op() -> &'static str {
    "{}"
}
async fn upload_object() -> &'static str {
    "{}"
}
