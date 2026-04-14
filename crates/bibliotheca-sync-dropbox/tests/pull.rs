//! Dropbox connector integration test against an axum mock.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes as AxumBytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Form, Json, Router};
use bibliotheca_sync_core::credentials::CredentialBlob;
use bibliotheca_sync_core::trait_::{Change, SyncConnector, UploadHints};
use bibliotheca_sync_dropbox::DropboxConnector;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;

#[derive(Default)]
struct DropboxState {
    files: Mutex<HashMap<String, Vec<u8>>>,
    cursors: Mutex<Vec<String>>,
    token_refreshes: Mutex<u32>,
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
    State(state): State<Arc<DropboxState>>,
    Form(f): Form<TokenForm>,
) -> Json<serde_json::Value> {
    assert_eq!(f.grant_type, "refresh_token");
    assert_eq!(f.refresh_token, "fake-rt");
    *state.token_refreshes.lock() += 1;
    Json(json!({
        "access_token": "at-current",
        "expires_in": 14400
    }))
}

async fn list_folder(
    State(state): State<Arc<DropboxState>>,
    Json(_body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let files = state.files.lock().clone();
    let entries: Vec<serde_json::Value> = files
        .iter()
        .map(|(key, bytes)| {
            json!({
                ".tag": "file",
                "id": format!("id:{key}"),
                "name": key,
                "path_display": format!("/{key}"),
                "path_lower": format!("/{key}"),
                "size": bytes.len(),
                "content_hash": format!("h:{key}"),
                "server_modified": "2026-04-14T12:00:00Z"
            })
        })
        .collect();
    let cursor = format!("cursor-{}", files.len());
    state.cursors.lock().push(cursor.clone());
    Json(json!({
        "entries": entries,
        "cursor": cursor,
        "has_more": false
    }))
}

async fn list_folder_continue(
    State(_state): State<Arc<DropboxState>>,
    Json(_body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    Json(json!({
        "entries": [],
        "cursor": "cursor-continue",
        "has_more": false
    }))
}

async fn download(
    State(state): State<Arc<DropboxState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let arg = headers
        .get("dropbox-api-arg")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("{}");
    let v: serde_json::Value = serde_json::from_str(arg).unwrap_or(serde_json::Value::Null);
    let path = v
        .get("path")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    match state.files.lock().get(&path).cloned() {
        Some(bytes) => (StatusCode::OK, bytes).into_response(),
        None => (StatusCode::CONFLICT, "path/not_found").into_response(),
    }
}

async fn upload(
    State(state): State<Arc<DropboxState>>,
    headers: HeaderMap,
    body: AxumBytes,
) -> Json<serde_json::Value> {
    let arg = headers
        .get("dropbox-api-arg")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("{}");
    let v: serde_json::Value = serde_json::from_str(arg).unwrap_or(serde_json::Value::Null);
    let path = v
        .get("path")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    state.files.lock().insert(path.clone(), body.to_vec());
    Json(json!({
        "id": format!("id:{path}"),
        "name": path,
        "path_display": format!("/{path}"),
        "size": body.len(),
        "content_hash": format!("h:{path}"),
        "server_modified": "2026-04-14T12:00:00Z"
    }))
}

async fn delete_v2(
    State(state): State<Arc<DropboxState>>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    let mut files = state.files.lock();
    if files.remove(&path).is_some() {
        Json(json!({ "metadata": { "path_display": format!("/{path}") } })).into_response()
    } else {
        (
            StatusCode::CONFLICT,
            Json(json!({
                "error_summary": "path/not_found",
                "error": { ".tag": "path_lookup" }
            })),
        )
            .into_response()
    }
}

async fn spawn_mock() -> (SocketAddr, Arc<DropboxState>) {
    let state = Arc::new(DropboxState::default());
    state
        .files
        .lock()
        .insert("hello.txt".to_string(), b"hello dropbox sync".to_vec());
    state
        .files
        .lock()
        .insert("nested/one.bin".to_string(), b"nested".to_vec());

    let app = Router::new()
        .route("/oauth2/token", post(oauth_token))
        .route("/2/files/list_folder", post(list_folder))
        .route("/2/files/list_folder/continue", post(list_folder_continue))
        .route("/2/files/download", post(download))
        .route("/2/files/upload", post(upload))
        .route("/2/files/delete_v2", post(delete_v2))
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
    let factory = DropboxConnector::factory();
    let blob = CredentialBlob::OAuth2 {
        access_token: String::new(),
        refresh_token: "fake-rt".into(),
        expires_at: 0,
        client_id: "cid".into(),
        client_secret: "sec".into(),
        token_url: format!("http://{addr}/oauth2/token"),
    };
    let config = serde_json::json!({
        "base_url": format!("http://{addr}"),
        "content_url": format!("http://{addr}")
    })
    .to_string();
    factory(&blob, &config).unwrap()
}

#[tokio::test]
async fn factory_rejects_non_oauth2() {
    let factory = DropboxConnector::factory();
    let wrong = CredentialBlob::Basic {
        username: "u".into(),
        password: "p".into(),
    };
    assert!(factory(&wrong, "{}").is_err());
}

#[tokio::test]
async fn refreshes_token_then_lists_files() {
    let (addr, state) = spawn_mock().await;
    let connector = make_connector(addr);

    let page = connector.list_since(None).await.unwrap();
    assert_eq!(page.changes.len(), 2);
    assert!(page.next_cursor.is_some());
    // First list_since triggered a token refresh.
    assert_eq!(*state.token_refreshes.lock(), 1);

    // Second call reuses the cached token.
    let _ = connector
        .list_since(page.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(*state.token_refreshes.lock(), 1);
}

#[tokio::test]
async fn full_round_trip() {
    let (addr, _state) = spawn_mock().await;
    let connector = make_connector(addr);

    let page = connector.list_since(None).await.unwrap();
    let hello = page
        .changes
        .iter()
        .find_map(|c| match c {
            Change::Upsert(o) if o.key == "hello.txt" => Some(o.clone()),
            _ => None,
        })
        .expect("seeded hello.txt");
    let bytes = connector.fetch(&hello).await.unwrap();
    assert_eq!(bytes.as_ref(), b"hello dropbox sync");

    // Upload a new file.
    let uploaded = connector
        .upload("uploaded.bin", b"new bytes", UploadHints::default())
        .await
        .unwrap();
    assert_eq!(uploaded.key, "uploaded.bin");

    // Delete an existing file.
    connector.delete(&hello).await.unwrap();
    // Second delete should succeed thanks to the 409-is-fine path.
    connector.delete(&hello).await.unwrap();
}
