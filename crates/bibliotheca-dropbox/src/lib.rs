//! Dropbox-compatible API surface.
//!
//! Implements the subset of the Dropbox v2 API needed to make official
//! Dropbox clients work against a bibliotheca subvolume. Paths always
//! start with a leading slash whose first segment names the target
//! subvolume, i.e. `/photos/2024/IMG_0001.jpg` resolves to
//! `IMG_0001.jpg` inside the `photos` subvolume.
//!
//! Auth is `Authorization: Bearer <base64(user:password)>`. The base64
//! shape matches what the HTTP Basic flow on the other transports
//! expects, so a test client can reuse a single credential across all
//! of them.

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Json;
use axum::Router;
use base64::Engine as _;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    data: DataStore,
    svc: BibliothecaService,
}

#[derive(Debug, Clone)]
pub struct DropboxConfig {
    pub listen: SocketAddr,
}

pub async fn start(svc: BibliothecaService, cfg: DropboxConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        data: DataStore::new(svc.clone()),
        svc,
    });
    let app = Router::new()
        .route("/2/files/list_folder", post(list_folder))
        .route("/2/files/upload", post(upload))
        .route("/2/files/download", post(download))
        .route("/2/files/delete_v2", post(delete_v2))
        .route("/2/files/get_metadata", post(get_metadata))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-dropbox listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PathArg {
    path: String,
}

#[derive(Debug, Serialize)]
struct FileEntry {
    #[serde(rename = ".tag")]
    tag: &'static str,
    name: String,
    path_lower: String,
    path_display: String,
    size: u64,
}

#[derive(Debug, Serialize)]
struct ListFolderResult {
    entries: Vec<FileEntry>,
    cursor: String,
    has_more: bool,
}

async fn list_folder(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(arg): Json<PathArg>,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let (sv_name, rel) = match split_path(&arg.path) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.data.list(&sv_name, &rel, Some(user.id), false) {
        Ok(entries) => {
            let entries: Vec<FileEntry> = entries
                .into_iter()
                .map(|e| {
                    let display = if rel.is_empty() {
                        format!("/{sv_name}/{}", e.key)
                    } else {
                        format!("/{sv_name}/{rel}/{}", e.key)
                    };
                    FileEntry {
                        tag: if e.is_dir { "folder" } else { "file" },
                        name: basename(&e.key).to_string(),
                        path_lower: display.to_lowercase(),
                        path_display: display,
                        size: e.size,
                    }
                })
                .collect();
            Json(ListFolderResult {
                entries,
                cursor: String::new(),
                has_more: false,
            })
            .into_response()
        }
        Err(CoreError::NotFound(_)) => path_not_found(&arg.path),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

async fn upload(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let arg = match headers
        .get("dropbox-api-arg")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_str::<PathArg>(s).ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(error_summary("missing Dropbox-API-Arg")),
            )
                .into_response()
        }
    };
    let (sv_name, rel) = match split_path(&arg.path) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state
        .data
        .put(&sv_name, &rel, Some(user.id), false, body.as_ref())
    {
        Ok(meta) => Json(FileEntry {
            tag: "file",
            name: basename(&rel).to_string(),
            path_lower: arg.path.to_lowercase(),
            path_display: arg.path.clone(),
            size: meta.size,
        })
        .into_response(),
        Err(CoreError::NotFound(_)) => path_not_found(&arg.path),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(CoreError::InvalidArgument(msg)) => {
            (StatusCode::BAD_REQUEST, Json(error_summary(&msg))).into_response()
        }
        Err(e) => server_error(e),
    }
}

async fn download(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let arg = match headers
        .get("dropbox-api-arg")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_str::<PathArg>(s).ok())
    {
        Some(a) => a,
        None => return (StatusCode::BAD_REQUEST, "missing Dropbox-API-Arg").into_response(),
    };
    let (sv_name, rel) = match split_path(&arg.path) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.data.get(&sv_name, &rel, Some(user.id), false) {
        Ok(bytes) => {
            let meta = FileEntry {
                tag: "file",
                name: basename(&rel).to_string(),
                path_lower: arg.path.to_lowercase(),
                path_display: arg.path.clone(),
                size: bytes.len() as u64,
            };
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        header::HeaderName::from_static("dropbox-api-result"),
                        &serde_json::to_string(&meta).unwrap(),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Err(CoreError::NotFound(_)) => path_not_found(&arg.path),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

async fn delete_v2(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(arg): Json<PathArg>,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let (sv_name, rel) = match split_path(&arg.path) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.data.delete(&sv_name, &rel, Some(user.id), false) {
        Ok(()) => Json(serde_json::json!({
            "metadata": {
                ".tag": "file",
                "name": basename(&rel),
                "path_display": arg.path,
                "path_lower": arg.path.to_lowercase(),
            }
        }))
        .into_response(),
        Err(CoreError::NotFound(_)) => path_not_found(&arg.path),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

async fn get_metadata(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(arg): Json<PathArg>,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let (sv_name, rel) = match split_path(&arg.path) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.data.head(&sv_name, &rel, Some(user.id), false) {
        Ok(meta) => Json(FileEntry {
            tag: if meta.is_dir { "folder" } else { "file" },
            name: basename(&rel).to_string(),
            path_lower: arg.path.to_lowercase(),
            path_display: arg.path.clone(),
            size: meta.size,
        })
        .into_response(),
        Err(CoreError::NotFound(_)) => path_not_found(&arg.path),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

fn split_path(path: &str) -> Result<(String, String), Response> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(error_summary("path must reference a subvolume")),
        )
            .into_response());
    }
    let (sv, rest) = trimmed.split_once('/').unwrap_or((trimmed, ""));
    Ok((sv.to_string(), rest.to_string()))
}

fn basename(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

fn require_bearer(state: &AppState, headers: &HeaderMap) -> Result<User, Response> {
    let hdr = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(unauthorized)?;
    let token = hdr.strip_prefix("Bearer ").ok_or_else(unauthorized)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .map_err(|_| unauthorized())?;
    let s = String::from_utf8(decoded).map_err(|_| unauthorized())?;
    let (user, pass) = s.split_once(':').ok_or_else(unauthorized)?;
    state
        .svc
        .verify_user_password(user, pass)
        .ok()
        .flatten()
        .ok_or_else(unauthorized)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(error_summary("invalid_access_token")),
    )
        .into_response()
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, Json(error_summary("access_denied"))).into_response()
}

fn path_not_found(p: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error_summary": format!("path/not_found/...{}", p),
            "error": { ".tag": "path", "path": { ".tag": "not_found" } }
        })),
    )
        .into_response()
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "dropbox interface error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(error_summary("internal_error")),
    )
        .into_response()
}

fn error_summary(s: &str) -> serde_json::Value {
    serde_json::json!({ "error_summary": s })
}
