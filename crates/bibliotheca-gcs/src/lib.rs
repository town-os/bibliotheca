//! Google Cloud Storage JSON API surface.
//!
//! Mirrors the v1 JSON API at https://storage.googleapis.com/storage/v1
//! so client libraries that point at a custom endpoint can talk to a
//! bibliotheca deployment. Bucket -> subvolume mapping matches the S3
//! crate: creating a bucket creates a subvolume owned by the caller,
//! deleting a bucket (force-)deletes the subvolume, and objects live
//! directly under the mount path.
//!
//! Auth is `Authorization: Bearer <base64(user:password)>`. That's the
//! same token shape the Dropbox transport accepts, which keeps test
//! harnesses from having to juggle per-protocol credentials.

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use base64::Engine as _;
use bibliotheca_core::acl::Acl;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    data: DataStore,
    svc: BibliothecaService,
}

#[derive(Debug, Clone)]
pub struct GcsConfig {
    pub listen: SocketAddr,
}

pub async fn start(svc: BibliothecaService, cfg: GcsConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        data: DataStore::new(svc.clone()),
        svc,
    });
    let app = Router::new()
        .route("/storage/v1/b", get(list_buckets).post(create_bucket))
        .route(
            "/storage/v1/b/:bucket",
            get(get_bucket).delete(delete_bucket),
        )
        .route("/storage/v1/b/:bucket/o", get(list_objects))
        .route(
            "/storage/v1/b/:bucket/o/*object",
            get(get_object).delete(delete_object),
        )
        .route("/upload/storage/v1/b/:bucket/o", post(upload_object))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-gcs listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ListObjectsQuery {
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetObjectQuery {
    #[serde(default)]
    alt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UploadQuery {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    upload_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateBucketBody {
    name: String,
}

#[derive(Debug, Serialize)]
struct BucketResource {
    kind: &'static str,
    name: String,
    #[serde(rename = "timeCreated")]
    time_created: String,
    location: &'static str,
}

#[derive(Debug, Serialize)]
struct ObjectResource {
    kind: &'static str,
    name: String,
    bucket: String,
    size: String,
    #[serde(rename = "contentType")]
    content_type: &'static str,
    updated: String,
}

async fn list_buckets(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let subs = state.data.owned_subvolumes(user.id).unwrap_or_default();
    let items: Vec<BucketResource> = subs
        .into_iter()
        .map(|s| BucketResource {
            kind: "storage#bucket",
            name: s.name,
            time_created: s.created_at.unix_timestamp().to_string(),
            location: "bibliotheca",
        })
        .collect();
    Json(json!({ "kind": "storage#buckets", "items": items })).into_response()
}

async fn create_bucket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateBucketBody>,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state
        .svc
        .create_subvolume(&body.name, user.id, 0, Some(Acl::owner_only(user.id)))
        .await
    {
        Ok(sv) => Json(BucketResource {
            kind: "storage#bucket",
            name: sv.name,
            time_created: sv.created_at.unix_timestamp().to_string(),
            location: "bibliotheca",
        })
        .into_response(),
        Err(CoreError::AlreadyExists(_)) => gcs_error(StatusCode::CONFLICT, "conflict"),
        Err(e) => server_error(e),
    }
}

async fn get_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_bearer(&state, &headers) {
        return r;
    }
    match state.svc.get_subvolume(&bucket) {
        Ok(sv) => Json(BucketResource {
            kind: "storage#bucket",
            name: sv.name,
            time_created: sv.created_at.unix_timestamp().to_string(),
            location: "bibliotheca",
        })
        .into_response(),
        Err(CoreError::NotFound(_)) => gcs_error(StatusCode::NOT_FOUND, "notFound"),
        Err(e) => server_error(e),
    }
}

async fn delete_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let sv = match state.svc.get_subvolume(&bucket) {
        Ok(s) => s,
        Err(CoreError::NotFound(_)) => return gcs_error(StatusCode::NOT_FOUND, "notFound"),
        Err(e) => return server_error(e),
    };
    if sv.owner != user.id {
        return gcs_error(StatusCode::FORBIDDEN, "forbidden");
    }
    match state.svc.delete_subvolume(sv.id, true).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => server_error(e),
    }
}

async fn list_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<ListObjectsQuery>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let prefix = q.prefix.unwrap_or_default();
    match state
        .data
        .list_recursive(&bucket, &prefix, Some(user.id), false)
    {
        Ok(entries) => {
            let items: Vec<ObjectResource> = entries
                .into_iter()
                .map(|e| ObjectResource {
                    kind: "storage#object",
                    name: e.key,
                    bucket: bucket.clone(),
                    size: e.size.to_string(),
                    content_type: "application/octet-stream",
                    updated: e.modified.unix_timestamp().to_string(),
                })
                .collect();
            Json(json!({ "kind": "storage#objects", "items": items })).into_response()
        }
        Err(CoreError::NotFound(_)) => gcs_error(StatusCode::NOT_FOUND, "notFound"),
        Err(CoreError::PermissionDenied) => gcs_error(StatusCode::FORBIDDEN, "forbidden"),
        Err(e) => server_error(e),
    }
}

async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, object)): Path<(String, String)>,
    Query(q): Query<GetObjectQuery>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if q.alt.as_deref() == Some("media") {
        return match state.data.get(&bucket, &object, Some(user.id), false) {
            Ok(bytes) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                bytes,
            )
                .into_response(),
            Err(CoreError::NotFound(_)) => gcs_error(StatusCode::NOT_FOUND, "notFound"),
            Err(CoreError::PermissionDenied) => gcs_error(StatusCode::FORBIDDEN, "forbidden"),
            Err(e) => server_error(e),
        };
    }
    match state.data.head(&bucket, &object, Some(user.id), false) {
        Ok(meta) => Json(ObjectResource {
            kind: "storage#object",
            name: object.clone(),
            bucket: bucket.clone(),
            size: meta.size.to_string(),
            content_type: "application/octet-stream",
            updated: meta.modified.unix_timestamp().to_string(),
        })
        .into_response(),
        Err(CoreError::NotFound(_)) => gcs_error(StatusCode::NOT_FOUND, "notFound"),
        Err(CoreError::PermissionDenied) => gcs_error(StatusCode::FORBIDDEN, "forbidden"),
        Err(e) => server_error(e),
    }
}

async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, object)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.data.delete(&bucket, &object, Some(user.id), false) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(CoreError::NotFound(_)) => gcs_error(StatusCode::NOT_FOUND, "notFound"),
        Err(CoreError::PermissionDenied) => gcs_error(StatusCode::FORBIDDEN, "forbidden"),
        Err(e) => server_error(e),
    }
}

async fn upload_object(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<UploadQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match require_bearer(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let name = match q.name {
        Some(n) if !n.is_empty() => n,
        _ => return gcs_error(StatusCode::BAD_REQUEST, "required"),
    };
    match state
        .data
        .put(&bucket, &name, Some(user.id), false, body.as_ref())
    {
        Ok(meta) => Json(ObjectResource {
            kind: "storage#object",
            name: name.clone(),
            bucket: bucket.clone(),
            size: meta.size.to_string(),
            content_type: "application/octet-stream",
            updated: meta.modified.unix_timestamp().to_string(),
        })
        .into_response(),
        Err(CoreError::NotFound(_)) => gcs_error(StatusCode::NOT_FOUND, "notFound"),
        Err(CoreError::PermissionDenied) => gcs_error(StatusCode::FORBIDDEN, "forbidden"),
        Err(CoreError::InvalidArgument(msg)) => gcs_error(StatusCode::BAD_REQUEST, &msg),
        Err(e) => server_error(e),
    }
}

fn require_bearer(state: &AppState, headers: &HeaderMap) -> Result<User, Response> {
    let hdr = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| gcs_error(StatusCode::UNAUTHORIZED, "required"))?;
    let token = hdr
        .strip_prefix("Bearer ")
        .ok_or_else(|| gcs_error(StatusCode::UNAUTHORIZED, "required"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .map_err(|_| gcs_error(StatusCode::UNAUTHORIZED, "required"))?;
    let s =
        String::from_utf8(decoded).map_err(|_| gcs_error(StatusCode::UNAUTHORIZED, "required"))?;
    let (user, pass) = s
        .split_once(':')
        .ok_or_else(|| gcs_error(StatusCode::UNAUTHORIZED, "required"))?;
    state
        .svc
        .verify_user_password(user, pass)
        .ok()
        .flatten()
        .ok_or_else(|| gcs_error(StatusCode::UNAUTHORIZED, "required"))
}

fn gcs_error(code: StatusCode, reason: &str) -> Response {
    (
        code,
        Json(json!({
            "error": {
                "code": code.as_u16(),
                "message": reason,
                "errors": [ { "reason": reason } ],
            }
        })),
    )
        .into_response()
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "gcs interface error");
    gcs_error(StatusCode::INTERNAL_SERVER_ERROR, "internalError")
}
