//! axum HTTP server for the anisette proxy.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use tracing::info;

use crate::provider::{AnisetteProvider, ProviderStatus};

/// Configuration for the embedded anisette server.
#[derive(Debug, Clone)]
pub struct AnisetteServerConfig {
    pub listen: SocketAddr,
}

type SharedProvider = Arc<dyn AnisetteProvider>;

#[derive(Clone)]
struct AppState {
    provider: SharedProvider,
}

/// Bind + serve forever. Used by both the standalone
/// `bibliotheca-anisetted` binary and the in-daemon spawn path.
pub async fn serve(provider: SharedProvider, cfg: AnisetteServerConfig) -> anyhow::Result<()> {
    let state = AppState { provider };
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/status", get(status))
        .route("/v3/get_anisette_data", post(get_anisette))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-anisette listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_anisette(State(state): State<AppState>) -> Response {
    match state.provider.get().await {
        Ok(headers) => Json(headers).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "anisette proxy failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

async fn status(State(state): State<AppState>) -> Json<ProviderStatus> {
    Json(state.provider.status())
}
