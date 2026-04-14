//! Nextcloud / WebDAV connector against an axum WebDAV mock.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes as AxumBytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use bibliotheca_sync_core::credentials::CredentialBlob;
use bibliotheca_sync_core::trait_::{Change, SyncConnector, UploadHints};
use bibliotheca_sync_nextcloud::NextcloudConnector;
use parking_lot::Mutex;

#[derive(Default)]
struct DavState {
    files: Mutex<HashMap<String, Vec<u8>>>,
    dirs: Mutex<Vec<String>>,
}

async fn dav_root(
    State(state): State<Arc<DavState>>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: AxumBytes,
) -> axum::response::Response {
    handle_dav(state, "".to_string(), headers, method, body).await
}

async fn dav_path(
    State(state): State<Arc<DavState>>,
    Path(rel): Path<String>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: AxumBytes,
) -> axum::response::Response {
    handle_dav(state, rel, headers, method, body).await
}

async fn handle_dav(
    state: Arc<DavState>,
    rel: String,
    headers: HeaderMap,
    method: axum::http::Method,
    body: AxumBytes,
) -> axum::response::Response {
    let authenticated = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.starts_with("Basic "))
        .unwrap_or(false);
    if !authenticated {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let rel = rel.trim_end_matches('/').to_string();
    match method.as_str() {
        "PROPFIND" => propfind_response(&state),
        "GET" => match state.files.lock().get(&rel).cloned() {
            Some(bytes) => (StatusCode::OK, bytes).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        "PUT" => {
            state.files.lock().insert(rel, body.to_vec());
            let mut headers = HeaderMap::new();
            headers.insert("etag", HeaderValue::from_static("\"abc\""));
            (StatusCode::CREATED, headers).into_response()
        }
        "DELETE" => {
            let removed = state.files.lock().remove(&rel).is_some();
            if removed {
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        "MKCOL" => {
            state.dirs.lock().push(rel);
            StatusCode::CREATED.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn propfind_response(state: &DavState) -> axum::response::Response {
    let files = state.files.lock().clone();
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/files/alice/</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype><d:collection/></d:resourcetype>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
"#,
    );
    for (key, bytes) in &files {
        body.push_str(&format!(
            r#"  <d:response>
    <d:href>/dav/files/alice/{key}</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype/>
        <d:getcontentlength>{len}</d:getcontentlength>
        <d:getetag>"etag-{key}"</d:getetag>
        <d:getlastmodified>Mon, 14 Apr 2026 12:00:00 GMT</d:getlastmodified>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
"#,
            key = key,
            len = bytes.len()
        ));
    }
    body.push_str("</d:multistatus>\n");
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/xml"));
    (StatusCode::from_u16(207).unwrap(), headers, body).into_response()
}

async fn spawn_dav() -> (SocketAddr, Arc<DavState>) {
    let state = Arc::new(DavState::default());
    state
        .files
        .lock()
        .insert("hello.txt".to_string(), b"hello webdav".to_vec());
    state
        .files
        .lock()
        .insert("nested/deep.bin".to_string(), vec![1, 2, 3, 4]);

    let app = Router::new()
        .route("/dav/files/alice/", any(dav_root))
        .route("/dav/files/alice", any(dav_root))
        .route("/dav/files/alice/*rel", any(dav_path))
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
    let factory = NextcloudConnector::factory();
    let blob = CredentialBlob::Basic {
        username: "alice".into(),
        password: "secret".into(),
    };
    let config = serde_json::json!({
        "base_url": format!("http://{addr}/dav/files/alice")
    })
    .to_string();
    factory(&blob, &config).unwrap()
}

#[tokio::test]
async fn factory_rejects_oauth_creds() {
    let factory = NextcloudConnector::factory();
    let blob = CredentialBlob::OAuth2 {
        access_token: String::new(),
        refresh_token: "".into(),
        expires_at: 0,
        client_id: "".into(),
        client_secret: "".into(),
        token_url: "".into(),
    };
    let config = serde_json::json!({ "base_url": "http://x" }).to_string();
    assert!(factory(&blob, &config).is_err());
}

#[tokio::test]
async fn list_fetch_upload_delete_round_trip() {
    let (addr, _state) = spawn_dav().await;
    let connector = make_connector(addr);

    let page = connector.list_since(None).await.unwrap();
    assert_eq!(
        page.changes.len(),
        2,
        "expected 2 files from propfind, got {:?}",
        page.changes
    );

    let hello = page
        .changes
        .iter()
        .find_map(|c| match c {
            Change::Upsert(o) if o.key == "hello.txt" => Some(o.clone()),
            _ => None,
        })
        .expect("hello.txt upserted");
    let bytes = connector.fetch(&hello).await.unwrap();
    assert_eq!(bytes.as_ref(), b"hello webdav");

    let uploaded = connector
        .upload("new/file.bin", b"fresh bytes", UploadHints::default())
        .await
        .unwrap();
    assert_eq!(uploaded.key, "new/file.bin");

    connector.delete(&hello).await.unwrap();
    // Idempotent: second delete → 404 in mock, absorbed.
    connector.delete(&hello).await.unwrap();
}
