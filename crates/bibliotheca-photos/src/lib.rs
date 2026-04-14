//! Google Photos Library API surface.
//!
//! Targets a subset of the `photoslibrary.googleapis.com` v1 REST API
//! — enough for a third-party client pointed at a custom endpoint to
//! upload photos, organize them into albums, list and search by
//! album, fetch metadata, and download bytes.
//!
//! ## Route shape
//!
//! Google's REST convention uses `:verb` on collection resources
//! (e.g. `/v1/mediaItems:batchCreate`, `/v1/mediaItems:search`).
//! axum's router treats `:` mid-segment as a route-parameter marker,
//! which would either conflict with the `/mediaItems/:id` capture or
//! get mis-parsed. This interface therefore exposes the same verbs
//! at slash-separated paths — `/v1/mediaItems/batchCreate` and
//! `/v1/mediaItems/search`. Clients pointed at a custom endpoint
//! can substitute the colon for a slash; everything else in the
//! payload shape is wire-compatible.
//!
//! ## Data model
//!
//! A single subvolume acts as the "photos library" for this
//! interface; its name is supplied in [`PhotosConfig::library`] and
//! defaults to `photos`. Inside the library subvolume:
//!
//! - **Albums** are top-level directories.
//! - **Media items** are files inside an album directory, or files
//!   at the subvolume root (the `library` / "no album" bucket).
//!
//! Every read/write goes through `bibliotheca-core::data::DataStore`,
//! so the usual subvolume ACL rules apply: the caller must have
//! `Read`/`List` to inspect and `Write` to upload.
//!
//! ## Upload flow
//!
//! Matches the real Google Photos REST protocol:
//!
//! 1. `POST /v1/uploads` with raw bytes, `Content-Type:
//!    application/octet-stream`, `X-Goog-Upload-File-Name: <name>`
//!    and `X-Goog-Upload-Protocol: raw`. Response body is a plain
//!    text upload token.
//! 2. `POST /v1/mediaItems:batchCreate` with a JSON body of the form
//!    `{ "albumId": "<id>", "newMediaItems": [{ "simpleMediaItem":
//!    { "uploadToken": "<tok>", "fileName": "<name>" } }] }`. The
//!    server resolves the token, writes bytes into
//!    `<album>/<file>`, and returns a populated `mediaItem` record.
//!
//! Tokens live in a per-interface in-memory map (keyed by UUID) and
//! are consumed on `batchCreate`. Unused tokens are not persisted.
//!
//! ## IDs
//!
//! - `albumId` = `urlsafe_b64(album_name)`.
//! - `mediaItemId` = `urlsafe_b64(relative key inside the library,
//!   forward-slash separated)`. A file at `trip/a.jpg` and a file
//!   at `a.jpg` are distinct media items with distinct ids.
//!
//! ## Auth
//!
//! HTTP `Authorization: Bearer <base64(user:password)>` — same token
//! shape the Dropbox and GCS transports use, so test clients can
//! reuse a single credential across all three.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    svc: BibliothecaService,
    data: DataStore,
    library: String,
    pending: Arc<Mutex<HashMap<String, PendingUpload>>>,
}

struct PendingUpload {
    file_name: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PhotosConfig {
    pub listen: SocketAddr,
    /// Name of the subvolume acting as the photos library. The
    /// subvolume must already exist; the interface does not create
    /// it lazily.
    pub library: String,
}

pub async fn start(svc: BibliothecaService, cfg: PhotosConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        data: DataStore::new(svc.clone()),
        svc,
        library: cfg.library.clone(),
        pending: Arc::new(Mutex::new(HashMap::new())),
    });

    let app = Router::new()
        .route("/v1/uploads", post(upload_raw))
        .route("/v1/mediaItems", get(list_media))
        .route("/v1/mediaItems/batchCreate", post(batch_create))
        .route("/v1/mediaItems/search", post(search_media))
        .route("/v1/mediaItems/:id", get(get_media))
        .route("/v1/downloads/:id", get(download_media))
        .route("/v1/albums", get(list_albums).post(create_album))
        .route("/v1/albums/:id", get(get_album))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, library = %cfg.library, "bibliotheca-photos listening");
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- upload ----------

async fn upload_raw(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    // The user has to have Write on the library subvolume to have
    // any business minting upload tokens against it.
    let sv = match state.svc.get_subvolume(&state.library) {
        Ok(s) => s,
        Err(CoreError::NotFound(_)) => {
            return photos_error(StatusCode::NOT_FOUND, "library subvolume not found")
        }
        Err(e) => return server_error(e),
    };
    match state.svc.check_permission(
        sv.id,
        Some(user.id),
        bibliotheca_core::acl::Permission::Write,
        false,
    ) {
        Ok(true) => {}
        Ok(false) => return photos_error(StatusCode::FORBIDDEN, "permission denied"),
        Err(e) => return server_error(e),
    }

    let file_name = headers
        .get("x-goog-upload-file-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if file_name.is_empty() {
        return photos_error(StatusCode::BAD_REQUEST, "missing X-Goog-Upload-File-Name");
    }
    if body.is_empty() {
        return photos_error(StatusCode::BAD_REQUEST, "empty upload body");
    }
    let token = Uuid::new_v4().to_string();
    state.pending.lock().insert(
        token.clone(),
        PendingUpload {
            file_name,
            bytes: body.to_vec(),
        },
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        token,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct SimpleMediaItem {
    #[serde(rename = "uploadToken")]
    upload_token: String,
    #[serde(default, rename = "fileName")]
    file_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NewMediaItem {
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "simpleMediaItem")]
    simple: SimpleMediaItem,
}

#[derive(Debug, Deserialize)]
struct BatchCreateRequest {
    #[serde(default, rename = "albumId")]
    album_id: Option<String>,
    #[serde(rename = "newMediaItems")]
    new_media_items: Vec<NewMediaItem>,
}

async fn batch_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BatchCreateRequest>,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let album_dir = match &req.album_id {
        Some(id) => match decode_id(id) {
            Some(name) if !name.is_empty() => Some(name),
            _ => return photos_error(StatusCode::BAD_REQUEST, "invalid albumId"),
        },
        None => None,
    };

    let mut results = Vec::with_capacity(req.new_media_items.len());
    for item in req.new_media_items {
        let pending = state.pending.lock().remove(&item.simple.upload_token);
        let Some(pending) = pending else {
            results.push(json!({
                "status": {
                    "code": 3,
                    "message": "INVALID_ARGUMENT: upload token not found",
                }
            }));
            continue;
        };
        let file_name = item.simple.file_name.unwrap_or(pending.file_name.clone());
        let rel = match &album_dir {
            Some(a) => format!("{a}/{file_name}"),
            None => file_name.clone(),
        };
        match state
            .data
            .put(&state.library, &rel, Some(user.id), false, &pending.bytes)
        {
            Ok(meta) => {
                let id = encode_id(&rel);
                results.push(json!({
                    "mediaItem": {
                        "id": id,
                        "filename": file_name,
                        "description": item.description,
                        "mimeType": "application/octet-stream",
                        "baseUrl": format!("/v1/downloads/{id}"),
                        "mediaMetadata": {
                            "creationTime": meta.modified.unix_timestamp().to_string(),
                        },
                    },
                    "status": { "code": 0, "message": "Success" },
                }));
            }
            Err(CoreError::PermissionDenied) => {
                return photos_error(StatusCode::FORBIDDEN, "permission denied");
            }
            Err(CoreError::NotFound(_)) => {
                return photos_error(StatusCode::NOT_FOUND, "library subvolume not found");
            }
            Err(CoreError::InvalidArgument(msg)) => {
                return photos_error(StatusCode::BAD_REQUEST, &msg);
            }
            Err(e) => return server_error(e),
        }
    }
    Json(json!({ "newMediaItemResults": results })).into_response()
}

// ---------- list / search / get ----------

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, rename = "pageSize")]
    _page_size: Option<u32>,
    #[serde(default, rename = "albumId")]
    album_id: Option<String>,
}

async fn list_media(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match collect_media(&state, user.id, q.album_id.as_deref()) {
        Ok(items) => Json(json!({ "mediaItems": items })).into_response(),
        Err(r) => r,
    }
}

#[derive(Debug, Deserialize)]
struct SearchRequest {
    #[serde(default, rename = "albumId")]
    album_id: Option<String>,
    #[serde(default, rename = "pageSize")]
    _page_size: Option<u32>,
}

async fn search_media(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SearchRequest>,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match collect_media(&state, user.id, req.album_id.as_deref()) {
        Ok(items) => Json(json!({ "mediaItems": items })).into_response(),
        Err(r) => r,
    }
}

async fn get_media(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Some(key) = decode_id(&id) else {
        return photos_error(StatusCode::BAD_REQUEST, "invalid mediaItem id");
    };
    match state.data.head(&state.library, &key, Some(user.id), false) {
        Ok(meta) => Json(media_item_json(
            &id,
            &key,
            meta.size,
            meta.modified.unix_timestamp(),
        ))
        .into_response(),
        Err(CoreError::NotFound(_)) => photos_error(StatusCode::NOT_FOUND, "mediaItem not found"),
        Err(CoreError::PermissionDenied) => {
            photos_error(StatusCode::FORBIDDEN, "permission denied")
        }
        Err(e) => server_error(e),
    }
}

async fn download_media(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Some(key) = decode_id(&id) else {
        return photos_error(StatusCode::BAD_REQUEST, "invalid mediaItem id");
    };
    match state.data.get(&state.library, &key, Some(user.id), false) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => photos_error(StatusCode::NOT_FOUND, "mediaItem not found"),
        Err(CoreError::PermissionDenied) => {
            photos_error(StatusCode::FORBIDDEN, "permission denied")
        }
        Err(e) => server_error(e),
    }
}

// ---------- albums ----------

#[derive(Debug, Deserialize)]
struct CreateAlbumBody {
    album: CreateAlbumInner,
}

#[derive(Debug, Deserialize)]
struct CreateAlbumInner {
    title: String,
}

async fn list_albums(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let entries = match state.data.list(&state.library, "", Some(user.id), false) {
        Ok(e) => e,
        Err(CoreError::NotFound(_)) => {
            return photos_error(StatusCode::NOT_FOUND, "library subvolume not found")
        }
        Err(CoreError::PermissionDenied) => {
            return photos_error(StatusCode::FORBIDDEN, "permission denied")
        }
        Err(e) => return server_error(e),
    };
    let mut albums = Vec::new();
    for e in entries {
        if e.is_dir {
            albums.push(album_json(&e.key));
        }
    }
    Json(json!({ "albums": albums })).into_response()
}

async fn create_album(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateAlbumBody>,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if body.album.title.is_empty() || body.album.title.contains('/') {
        return photos_error(StatusCode::BAD_REQUEST, "invalid album title");
    }
    match state
        .data
        .mkdir(&state.library, &body.album.title, Some(user.id), false)
    {
        Ok(_) => Json(album_json(&body.album.title)).into_response(),
        Err(CoreError::AlreadyExists(_)) => Json(album_json(&body.album.title)).into_response(),
        Err(CoreError::PermissionDenied) => {
            photos_error(StatusCode::FORBIDDEN, "permission denied")
        }
        Err(CoreError::NotFound(_)) => {
            photos_error(StatusCode::NOT_FOUND, "library subvolume not found")
        }
        Err(e) => server_error(e),
    }
}

async fn get_album(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Some(name) = decode_id(&id) else {
        return photos_error(StatusCode::BAD_REQUEST, "invalid albumId");
    };
    match state.data.head(&state.library, &name, Some(user.id), false) {
        Ok(meta) if meta.is_dir => Json(album_json(&name)).into_response(),
        Ok(_) => photos_error(StatusCode::NOT_FOUND, "not an album"),
        Err(CoreError::NotFound(_)) => photos_error(StatusCode::NOT_FOUND, "album not found"),
        Err(CoreError::PermissionDenied) => {
            photos_error(StatusCode::FORBIDDEN, "permission denied")
        }
        Err(e) => server_error(e),
    }
}

// ---------- helpers ----------

fn collect_media(
    state: &AppState,
    user: bibliotheca_core::identity::UserId,
    album_id: Option<&str>,
) -> Result<Vec<Value>, Response> {
    let prefix = match album_id {
        Some(id) => match decode_id(id) {
            Some(name) if !name.is_empty() => name,
            _ => return Err(photos_error(StatusCode::BAD_REQUEST, "invalid albumId")),
        },
        None => String::new(),
    };
    let entries = match state
        .data
        .list_recursive(&state.library, &prefix, Some(user), false)
    {
        Ok(e) => e,
        Err(CoreError::NotFound(_)) => {
            return Err(photos_error(
                StatusCode::NOT_FOUND,
                "library subvolume not found",
            ))
        }
        Err(CoreError::PermissionDenied) => {
            return Err(photos_error(StatusCode::FORBIDDEN, "permission denied"))
        }
        Err(e) => return Err(server_error(e)),
    };
    let mut items = Vec::new();
    for e in entries {
        if e.is_dir {
            continue;
        }
        // When an album is specified, the recursive walk still
        // returns keys relative to the subvolume root; skip anything
        // that isn't actually underneath the requested album.
        if let Some(album) = album_id.and_then(decode_id) {
            let prefix = format!("{album}/");
            if !e.key.starts_with(&prefix) {
                continue;
            }
        }
        let id = encode_id(&e.key);
        items.push(media_item_json(
            &id,
            &e.key,
            e.size,
            e.modified.unix_timestamp(),
        ));
    }
    Ok(items)
}

fn media_item_json(id: &str, key: &str, size: u64, modified: i64) -> Value {
    let filename = key.rsplit('/').next().unwrap_or(key).to_string();
    json!({
        "id": id,
        "filename": filename,
        "mimeType": "application/octet-stream",
        "baseUrl": format!("/v1/downloads/{id}"),
        "mediaMetadata": {
            "creationTime": modified.to_string(),
            "width": "0",
            "height": "0",
        },
        "productUrl": format!("/v1/mediaItems/{id}"),
        "_size": size.to_string(),
    })
}

fn album_json(name: &str) -> Value {
    let id = encode_id(name);
    json!({
        "id": id,
        "title": name,
        "productUrl": format!("/v1/albums/{id}"),
        "isWriteable": true,
    })
}

fn encode_id(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn decode_id(s: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
    String::from_utf8(bytes).ok()
}

fn require_bearer(state: &AppState, headers: &HeaderMap) -> Result<User, Response> {
    let hdr = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| photos_error(StatusCode::UNAUTHORIZED, "missing Authorization"))?;
    let token = hdr
        .strip_prefix("Bearer ")
        .ok_or_else(|| photos_error(StatusCode::UNAUTHORIZED, "expected Bearer token"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .map_err(|_| photos_error(StatusCode::UNAUTHORIZED, "invalid token encoding"))?;
    let s = String::from_utf8(decoded)
        .map_err(|_| photos_error(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let (user, pass) = s
        .split_once(':')
        .ok_or_else(|| photos_error(StatusCode::UNAUTHORIZED, "malformed token"))?;
    state
        .svc
        .verify_user_password(user, pass)
        .ok()
        .flatten()
        .ok_or_else(|| photos_error(StatusCode::UNAUTHORIZED, "authentication failed"))
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: ApiErrorInner,
}

#[derive(Debug, Serialize)]
struct ApiErrorInner {
    code: u16,
    message: String,
    status: String,
}

fn photos_error(code: StatusCode, message: &str) -> Response {
    let status = match code {
        StatusCode::UNAUTHORIZED => "UNAUTHENTICATED",
        StatusCode::FORBIDDEN => "PERMISSION_DENIED",
        StatusCode::NOT_FOUND => "NOT_FOUND",
        StatusCode::BAD_REQUEST => "INVALID_ARGUMENT",
        _ => "INTERNAL",
    };
    (
        code,
        Json(ApiError {
            error: ApiErrorInner {
                code: code.as_u16(),
                message: message.to_string(),
                status: status.to_string(),
            },
        }),
    )
        .into_response()
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "photos interface error");
    photos_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}
