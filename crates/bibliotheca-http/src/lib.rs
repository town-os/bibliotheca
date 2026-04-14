//! Authenticated HTTP interface.
//!
//! HTTP is **disabled by default**. Operators must explicitly enable
//! this interface via the control plane (`Interfaces.Enable`). Anonymous
//! requests are only ever served when the requested subvolume's ACL has
//! an explicit `Public` entry **and** the interface was started with
//! `allow_public = true`. Even then, the interface as a whole has to
//! be enabled before any anonymous traffic is honoured — defense in
//! depth against accidental exposure.
//!
//! Object bytes live in the subvolume mount path and are moved through
//! `bibliotheca-core::data::DataStore`, which enforces path traversal
//! and ACL checks uniformly across transports.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::{User, UserId};
use bibliotheca_core::service::BibliothecaService;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    data: DataStore,
    svc: BibliothecaService,
    public_allowed: bool,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub listen: SocketAddr,
    /// Honour ACL entries with `Principal::Public`. Requires the
    /// interface to be enabled in the first place.
    pub allow_public: bool,
}

pub async fn start(svc: BibliothecaService, cfg: HttpConfig) -> anyhow::Result<()> {
    let state = AppState {
        data: DataStore::new(svc.clone()),
        svc,
        public_allowed: cfg.allow_public,
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/subvolumes/:sv/objects", get(list_root))
        .route("/v1/subvolumes/:sv/objects/", get(list_root))
        .route(
            "/v1/subvolumes/:sv/objects/*key",
            get(get_object)
                .put(put_object)
                .delete(delete_object)
                .head(head_object),
        )
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-http listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn list_root(
    State(state): State<Arc<AppState>>,
    Path(sv_name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = authenticate(&state, &headers);
    let uid = user.as_ref().map(|u| u.id);
    if user.is_none() && !state.public_allowed {
        return unauthorized();
    }
    list_impl(&state, &sv_name, "", uid)
}

async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((sv_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = authenticate(&state, &headers);
    let uid = user.as_ref().map(|u| u.id);
    if key.ends_with('/') || key.is_empty() {
        return list_impl(&state, &sv_name, key.trim_end_matches('/'), uid);
    }
    match state.svc.get_subvolume(&sv_name) {
        Ok(_) => {}
        Err(CoreError::NotFound(_)) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return server_error(e),
    }
    match state.data.get(&sv_name, &key, uid, state.public_allowed) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_LENGTH, &bytes.len().to_string()),
            ],
            bytes,
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(e) => server_error(e),
    }
}

async fn head_object(
    State(state): State<Arc<AppState>>,
    Path((sv_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = authenticate(&state, &headers);
    let uid = user.as_ref().map(|u| u.id);
    match state.data.head(&sv_name, &key, uid, state.public_allowed) {
        Ok(meta) => (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, meta.size.to_string()),
                (
                    header::LAST_MODIFIED,
                    meta.modified.unix_timestamp().to_string(),
                ),
            ],
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(e) => server_error(e),
    }
}

async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((sv_name, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = authenticate(&state, &headers);
    let uid = user.as_ref().map(|u| u.id);
    match state
        .data
        .put(&sv_name, &key, uid, state.public_allowed, body.as_ref())
    {
        Ok(meta) => (
            StatusCode::CREATED,
            [(header::CONTENT_LENGTH, meta.size.to_string())],
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(CoreError::InvalidArgument(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(e) => server_error(e),
    }
}

async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((sv_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = authenticate(&state, &headers);
    let uid = user.as_ref().map(|u| u.id);
    match state.data.delete(&sv_name, &key, uid, state.public_allowed) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(e) => server_error(e),
    }
}

fn list_impl(state: &AppState, sv: &str, prefix: &str, user: Option<UserId>) -> Response {
    match state.data.list(sv, prefix, user, state.public_allowed) {
        Ok(entries) => Json(serde_json::json!({
            "subvolume": sv,
            "prefix": prefix,
            "entries": entries,
        }))
        .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(e) => server_error(e),
    }
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let creds = auth.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(creds.trim())
        .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    state.svc.verify_user_password(user, pass).ok().flatten()
}

fn deny(anonymous: bool) -> Response {
    if anonymous {
        unauthorized()
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"bibliotheca\"")],
    )
        .into_response()
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "http interface error");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
