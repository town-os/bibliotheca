//! S3-compatible interface.
//!
//! Buckets correspond 1:1 to subvolumes; the bucket owner is the
//! subvolume owner. Authentication is AWS Signature V4 using per-user
//! access keys minted via the control plane (see
//! `bibliotheca-core::identity` — credential storage will live alongside
//! the password hash once the spec module lands).

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
pub struct S3Config {
    pub listen: SocketAddr,
    pub region: String,
}

pub async fn start(svc: BibliothecaService, cfg: S3Config) -> anyhow::Result<()> {
    let state = Arc::new(AppState { svc });
    let app = Router::new()
        .route("/", get(list_buckets))
        .route("/:bucket", any(bucket_op))
        .route("/:bucket/*key", any(object_op))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, region = %cfg.region, "bibliotheca-s3 listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn list_buckets() -> &'static str {
    // TODO(spec): emit ListAllMyBucketsResult XML scoped to the
    // authenticated principal's owned subvolumes.
    "<ListAllMyBucketsResult/>"
}

async fn bucket_op() -> &'static str {
    // TODO(spec): GET=ListObjects, PUT=CreateBucket, DELETE=DeleteBucket.
    ""
}

async fn object_op() -> &'static str {
    // TODO(spec): GET/HEAD/PUT/DELETE on objects, CopyObject, multipart.
    ""
}
