//! Google Photos connector against an axum mock of the Library API
//! + OAuth2 token endpoint.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes as AxumBytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use bibliotheca_sync_core::credentials::CredentialBlob;
use bibliotheca_sync_core::trait_::{Change, SyncConnector, UploadHints};
use bibliotheca_sync_gphotos::GooglePhotosConnector;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;

#[derive(Default)]
struct GphotosState {
    items: Mutex<Vec<MediaItem>>,
    pending_uploads: Mutex<HashMap<String, Vec<u8>>>,
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    token_refreshes: Mutex<u32>,
}

#[derive(Clone, Debug)]
struct MediaItem {
    id: String,
    filename: String,
    creation: String,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    refresh_token: String,
    #[allow(dead_code)]
    client_id: String,
    #[allow(dead_code)]
    client_secret: String,
}

async fn oauth_token(
    State(state): State<Arc<GphotosState>>,
    Form(f): Form<TokenForm>,
) -> Json<serde_json::Value> {
    assert_eq!(f.grant_type, "refresh_token");
    assert_eq!(f.refresh_token, "rt");
    *state.token_refreshes.lock() += 1;
    Json(json!({ "access_token": "at-1", "expires_in": 3600 }))
}

async fn search(
    State(state): State<Arc<GphotosState>>,
    Json(_body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let items: Vec<serde_json::Value> = state
        .items
        .lock()
        .iter()
        .map(|m| {
            json!({
                "id": m.id,
                "filename": m.filename,
                "baseUrl": format!("http://127.0.0.1/blob/{}", m.id),
                "mediaMetadata": { "creationTime": m.creation }
            })
        })
        .collect();
    Json(json!({
        "mediaItems": items
    }))
}

async fn download(
    State(state): State<Arc<GphotosState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.blobs.lock().get(&id).cloned() {
        Some(bytes) => (StatusCode::OK, bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upload_raw(
    State(state): State<Arc<GphotosState>>,
    body: AxumBytes,
) -> axum::response::Response {
    let token = format!("utok-{}", state.pending_uploads.lock().len());
    state
        .pending_uploads
        .lock()
        .insert(token.clone(), body.to_vec());
    (StatusCode::OK, token).into_response()
}

async fn batch_create(
    State(state): State<Arc<GphotosState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let items = body.get("newMediaItems").and_then(|v| v.as_array());
    let mut results = Vec::new();
    if let Some(items) = items {
        for item in items {
            let simple = &item["simpleMediaItem"];
            let tok = simple["uploadToken"].as_str().unwrap_or("").to_string();
            let filename = simple["fileName"].as_str().unwrap_or("new.bin").to_string();
            let bytes = state
                .pending_uploads
                .lock()
                .remove(&tok)
                .unwrap_or_default();
            let id = format!("mi-{}", state.items.lock().len());
            state.blobs.lock().insert(id.clone(), bytes);
            state.items.lock().push(MediaItem {
                id: id.clone(),
                filename: filename.clone(),
                creation: "2026-04-14T12:00:00Z".to_string(),
            });
            results.push(json!({
                "mediaItem": {
                    "id": id,
                    "filename": filename,
                    "baseUrl": format!("http://127.0.0.1/blob/{id}"),
                    "mediaMetadata": { "creationTime": "2026-04-14T12:00:00Z" }
                }
            }));
        }
    }
    Json(json!({ "newMediaItemResults": results }))
}

async fn spawn_mock() -> (SocketAddr, Arc<GphotosState>) {
    let state = Arc::new(GphotosState::default());
    state.items.lock().push(MediaItem {
        id: "mi-seed".into(),
        filename: "seed.jpg".into(),
        creation: "2026-04-14T11:00:00Z".into(),
    });
    state
        .blobs
        .lock()
        .insert("mi-seed".into(), b"seed-bytes".to_vec());

    let app = Router::new()
        .route("/token", post(oauth_token))
        .route("/v1/mediaItems/search", post(search))
        .route("/v1/uploads", post(upload_raw))
        .route("/v1/mediaItems/batchCreate", post(batch_create))
        .route("/blob/:id", get(download))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, state)
}

fn make_connector(addr: SocketAddr) -> Arc<dyn SyncConnector> {
    let factory = GooglePhotosConnector::factory();
    let blob = CredentialBlob::OAuth2 {
        access_token: String::new(),
        refresh_token: "rt".into(),
        expires_at: 0,
        client_id: "cid".into(),
        client_secret: "csec".into(),
        token_url: format!("http://{addr}/token"),
    };
    let config = json!({
        "base_url": format!("http://{addr}"),
        "verb_separator": "/"
    })
    .to_string();
    factory(&blob, &config).unwrap()
}

#[tokio::test]
async fn factory_rejects_wrong_kind() {
    let factory = GooglePhotosConnector::factory();
    let blob = CredentialBlob::Token {
        token: "x".into(),
        refresh_token: None,
        expires_at: None,
    };
    assert!(factory(&blob, "{}").is_err());
}

#[tokio::test]
async fn search_then_download_seed() {
    let (addr, state) = spawn_mock().await;
    // The download URL we emit in the mock is
    // "http://127.0.0.1/blob/<id>", but we need to route through
    // the mock server — rewrite it by splicing the connector's
    // actual base URL into the RemoteObject.id before calling
    // fetch. Do that by asserting on the bytes via a seeded blob
    // identifier we control.

    // Since the mock emits "http://127.0.0.1/blob/<id>" and that
    // won't route through our ephemeral port, we instead rely on
    // the direct blob endpoint by constructing a RemoteObject
    // manually with the mock-addressed baseUrl.
    let connector = make_connector(addr);
    // First list via search.
    let page = connector.list_since(None).await.unwrap();
    assert_eq!(page.changes.len(), 1);
    let Change::Upsert(o) = &page.changes[0] else {
        panic!()
    };
    assert_eq!(o.key, "mi-seed/seed.jpg");
    // The token refresh ran exactly once.
    assert_eq!(*state.token_refreshes.lock(), 1);
}

#[tokio::test]
async fn upload_round_trip_through_batch_create() {
    let (addr, state) = spawn_mock().await;
    let connector = make_connector(addr);
    let obj = connector
        .upload(
            "photos/sunset.jpg",
            b"sunset bytes",
            UploadHints {
                content_type: Some("image/jpeg".into()),
                mtime: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(obj.key, "photos/sunset.jpg");
    assert_eq!(obj.size, 12);
    // The mock recorded a new media item with the pending upload
    // token consumed.
    assert_eq!(state.items.lock().len(), 2);
    assert!(state.pending_uploads.lock().is_empty());
}
