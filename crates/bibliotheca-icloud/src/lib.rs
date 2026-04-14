//! iCloud Drive interface (CloudKit Web Services-shaped).
//!
//! Apple's iCloud protocol is undocumented; this crate targets the
//! CloudKit Web Services surface that third-party tools already use
//! for interoperability. The JSON envelopes are the real CloudKit
//! shape; the data model is deliberately flattened: the container is
//! fixed, records name subvolumes, and each record's `assets` field
//! holds (path, bytes) pairs inside that subvolume.
//!
//! Authentication is HTTP Basic, tunnelled through CloudKit's
//! `ckSession` header as `Basic <base64(user:pass)>` so that it doesn't
//! collide with real CloudKit `X-Apple-CloudKit-Request-KeyID`
//! signatures. A production deployment would replace this with proper
//! server-to-server key signing, but this keeps the test clients
//! simple and matches how we authenticate on the other transports.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    data: DataStore,
    svc: BibliothecaService,
    container: String,
}

#[derive(Debug, Clone)]
pub struct ICloudConfig {
    pub listen: SocketAddr,
    pub container: String,
}

pub async fn start(svc: BibliothecaService, cfg: ICloudConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        data: DataStore::new(svc.clone()),
        svc,
        container: cfg.container.clone(),
    });
    let app = Router::new()
        .route(
            "/database/1/:container/:env/public/records/query",
            post(records_query),
        )
        .route(
            "/database/1/:container/:env/public/records/lookup",
            post(records_lookup),
        )
        .route(
            "/database/1/:container/:env/public/records/modify",
            post(records_modify),
        )
        .route(
            "/database/1/:container/:env/public/assets/upload",
            post(assets_upload),
        )
        .route(
            "/database/1/:container/:env/public/assets/:subvolume/*key",
            get(asset_download),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, container = %cfg.container, "bibliotheca-icloud listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RecordRef {
    #[serde(rename = "recordName")]
    record_name: String,
}

#[derive(Debug, Deserialize)]
struct LookupRequest {
    records: Vec<RecordRef>,
}

#[derive(Debug, Deserialize)]
struct ModifyOperation {
    #[serde(rename = "operationType")]
    operation_type: String,
    record: ModifyRecord,
}

#[derive(Debug, Deserialize)]
struct ModifyRecord {
    #[serde(rename = "recordName")]
    record_name: String,
    #[serde(default)]
    fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ModifyRequest {
    operations: Vec<ModifyOperation>,
}

#[derive(Debug, Deserialize)]
struct AssetUploadQuery {
    subvolume: String,
    key: String,
}

async fn records_query(
    State(state): State<Arc<AppState>>,
    Path((container, _env)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if container != state.container {
        return error_response(StatusCode::NOT_FOUND, "CONTAINER_NOT_FOUND");
    }
    let user = match authenticate(&state, &headers) {
        Some(u) => u,
        None => return error_response(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED"),
    };
    let subs = state.data.owned_subvolumes(user.id).unwrap_or_default();
    let records: Vec<Value> = subs
        .into_iter()
        .map(|s| {
            json!({
                "recordName": s.name,
                "recordType": "Subvolume",
                "fields": {},
            })
        })
        .collect();
    Json(json!({ "records": records })).into_response()
}

async fn records_lookup(
    State(state): State<Arc<AppState>>,
    Path((container, _env)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<LookupRequest>,
) -> Response {
    if container != state.container {
        return error_response(StatusCode::NOT_FOUND, "CONTAINER_NOT_FOUND");
    }
    let user = match authenticate(&state, &headers) {
        Some(u) => u,
        None => return error_response(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED"),
    };
    let mut records = Vec::with_capacity(body.records.len());
    for r in body.records {
        match state.data.list(&r.record_name, "", Some(user.id), false) {
            Ok(entries) => {
                let assets: Vec<Value> = entries
                    .into_iter()
                    .map(|e| {
                        json!({
                            "recordName": e.key,
                            "size": e.size,
                            "isDir": e.is_dir,
                        })
                    })
                    .collect();
                records.push(json!({
                    "recordName": r.record_name,
                    "recordType": "Subvolume",
                    "fields": {
                        "assets": {
                            "value": assets,
                        }
                    }
                }));
            }
            Err(CoreError::NotFound(_)) => records.push(json!({
                "recordName": r.record_name,
                "reason": "RECORD_NOT_FOUND",
                "serverErrorCode": "RECORD_NOT_FOUND",
            })),
            Err(CoreError::PermissionDenied) => records.push(json!({
                "recordName": r.record_name,
                "reason": "ACCESS_DENIED",
                "serverErrorCode": "ACCESS_DENIED",
            })),
            Err(e) => return server_error(e),
        }
    }
    Json(json!({ "records": records })).into_response()
}

async fn records_modify(
    State(state): State<Arc<AppState>>,
    Path((container, _env)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ModifyRequest>,
) -> Response {
    if container != state.container {
        return error_response(StatusCode::NOT_FOUND, "CONTAINER_NOT_FOUND");
    }
    let user = match authenticate(&state, &headers) {
        Some(u) => u,
        None => return error_response(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED"),
    };
    let mut results = Vec::new();
    for op in body.operations {
        match op.operation_type.as_str() {
            "create" => {
                match state
                    .svc
                    .create_subvolume(
                        &op.record.record_name,
                        user.id,
                        0,
                        Some(bibliotheca_core::acl::Acl::owner_only(user.id)),
                    )
                    .await
                {
                    Ok(sv) => results.push(json!({
                        "recordName": sv.name,
                        "recordType": "Subvolume",
                        "fields": op.record.fields,
                    })),
                    Err(CoreError::AlreadyExists(_)) => results.push(json!({
                        "recordName": op.record.record_name,
                        "serverErrorCode": "UNIQUE_FIELD_VIOLATION",
                    })),
                    Err(e) => return server_error(e),
                }
            }
            "forceDelete" | "delete" => {
                let sv = match state.svc.get_subvolume(&op.record.record_name) {
                    Ok(sv) => sv,
                    Err(CoreError::NotFound(_)) => {
                        results.push(json!({
                            "recordName": op.record.record_name,
                            "serverErrorCode": "RECORD_NOT_FOUND",
                        }));
                        continue;
                    }
                    Err(e) => return server_error(e),
                };
                if sv.owner != user.id {
                    results.push(json!({
                        "recordName": op.record.record_name,
                        "serverErrorCode": "ACCESS_DENIED",
                    }));
                    continue;
                }
                match state.svc.delete_subvolume(sv.id, true).await {
                    Ok(()) => results.push(json!({
                        "recordName": op.record.record_name,
                        "deleted": true,
                    })),
                    Err(e) => return server_error(e),
                }
            }
            other => {
                results.push(json!({
                    "recordName": op.record.record_name,
                    "serverErrorCode": format!("UNSUPPORTED_OPERATION:{other}"),
                }));
            }
        }
    }
    Json(json!({ "records": results })).into_response()
}

async fn assets_upload(
    State(state): State<Arc<AppState>>,
    Path((container, _env)): Path<(String, String)>,
    Query(q): Query<AssetUploadQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if container != state.container {
        return error_response(StatusCode::NOT_FOUND, "CONTAINER_NOT_FOUND");
    }
    let user = match authenticate(&state, &headers) {
        Some(u) => u,
        None => return error_response(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED"),
    };
    match state
        .data
        .put(&q.subvolume, &q.key, Some(user.id), false, body.as_ref())
    {
        Ok(meta) => Json(json!({
            "recordName": q.key,
            "size": meta.size,
            "subvolume": q.subvolume,
        }))
        .into_response(),
        Err(CoreError::NotFound(_)) => error_response(StatusCode::NOT_FOUND, "CONTAINER_NOT_FOUND"),
        Err(CoreError::PermissionDenied) => error_response(StatusCode::FORBIDDEN, "ACCESS_DENIED"),
        Err(CoreError::InvalidArgument(msg)) => error_response(StatusCode::BAD_REQUEST, &msg),
        Err(e) => server_error(e),
    }
}

async fn asset_download(
    State(state): State<Arc<AppState>>,
    Path((container, _env, subvolume, key)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if container != state.container {
        return error_response(StatusCode::NOT_FOUND, "CONTAINER_NOT_FOUND");
    }
    let user = match authenticate(&state, &headers) {
        Some(u) => u,
        None => return error_response(StatusCode::UNAUTHORIZED, "AUTHENTICATION_FAILED"),
    };
    match state.data.get(&subvolume, &key, Some(user.id), false) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => {
            error_response(StatusCode::NOT_FOUND, "ASSET_FILE_NOT_FOUND")
        }
        Err(CoreError::PermissionDenied) => error_response(StatusCode::FORBIDDEN, "ACCESS_DENIED"),
        Err(e) => server_error(e),
    }
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let raw = headers.get("cksession").and_then(|v| v.to_str().ok())?;
    let creds = raw.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(creds.trim())
        .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    state.svc.verify_user_password(user, pass).ok().flatten()
}

fn error_response(code: StatusCode, reason: &str) -> Response {
    (
        code,
        Json(json!({
            "serverErrorCode": reason,
            "reason": reason,
        })),
    )
        .into_response()
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "icloud interface error");
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
}
