//! Solid / LDP connector against an axum mock pod.

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
use bibliotheca_sync_solid::SolidConnector;
use parking_lot::Mutex;

#[derive(Default)]
struct PodState {
    files: Mutex<HashMap<String, Vec<u8>>>,
}

async fn pod_root(
    State(state): State<Arc<PodState>>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: AxumBytes,
) -> axum::response::Response {
    handle(state, "".to_string(), headers, method, body).await
}

async fn pod_path(
    State(state): State<Arc<PodState>>,
    Path(rel): Path<String>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: AxumBytes,
) -> axum::response::Response {
    handle(state, rel, headers, method, body).await
}

async fn handle(
    state: Arc<PodState>,
    rel: String,
    headers: HeaderMap,
    method: axum::http::Method,
    body: AxumBytes,
) -> axum::response::Response {
    if !headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|h| h == "Bearer fake-token")
        .unwrap_or(false)
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let rel = rel.trim_end_matches('/').to_string();
    match method.as_str() {
        "GET" => {
            if rel.is_empty() || rel.ends_with('/') {
                return container_turtle(&state, &rel).into_response();
            }
            // File?
            if let Some(bytes) = state.files.lock().get(&rel).cloned() {
                return (StatusCode::OK, bytes).into_response();
            }
            // Container fallback.
            container_turtle(&state, &rel).into_response()
        }
        "PUT" => {
            state.files.lock().insert(rel, body.to_vec());
            StatusCode::CREATED.into_response()
        }
        "DELETE" => {
            let removed = state.files.lock().remove(&rel).is_some();
            if removed {
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn container_turtle(state: &PodState, prefix: &str) -> axum::response::Response {
    // Produce Turtle listing files whose key has the requested
    // prefix. We only support one level of nesting in this mock.
    let files = state.files.lock().clone();
    let mut contains = Vec::new();
    for key in files.keys() {
        if prefix.is_empty() {
            if !key.contains('/') {
                contains.push(format!("<{key}>"));
            } else {
                // Top-level container reference to the first
                // component, ending with `/`.
                let first = key.split('/').next().unwrap().to_string();
                let iri = format!("<{first}/>");
                if !contains.contains(&iri) {
                    contains.push(iri);
                }
            }
        } else if let Some(rest) = key.strip_prefix(&format!("{prefix}/")) {
            if !rest.contains('/') {
                contains.push(format!("<{rest}>"));
            }
        }
    }
    let body = format!(
        "@prefix ldp: <http://www.w3.org/ns/ldp#> .\n\
         <> a ldp:Container ;\n\
            ldp:contains {} .\n",
        contains.join(", ")
    );
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/turtle"));
    (StatusCode::OK, headers, body).into_response()
}

async fn spawn_pod() -> (SocketAddr, Arc<PodState>) {
    let state = Arc::new(PodState::default());
    state
        .files
        .lock()
        .insert("profile".to_string(), b"card contents".to_vec());
    state
        .files
        .lock()
        .insert("photos/one.jpg".to_string(), vec![0xAA; 16]);

    let app = Router::new()
        .route("/pod/", any(pod_root))
        .route("/pod", any(pod_root))
        .route("/pod/*rel", any(pod_path))
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
    let factory = SolidConnector::factory();
    let blob = CredentialBlob::Token {
        token: "fake-token".into(),
        refresh_token: None,
        expires_at: None,
    };
    let config = serde_json::json!({
        "pod_url": format!("http://{addr}/pod"),
        "content_type": "application/octet-stream"
    })
    .to_string();
    factory(&blob, &config).unwrap()
}

#[tokio::test]
async fn factory_rejects_non_token() {
    let factory = SolidConnector::factory();
    let blob = CredentialBlob::Basic {
        username: "u".into(),
        password: "p".into(),
    };
    let config = serde_json::json!({ "pod_url": "http://x" }).to_string();
    assert!(factory(&blob, &config).is_err());
}

#[tokio::test]
async fn list_walks_container_and_fetches_file() {
    let (addr, _state) = spawn_pod().await;
    let connector = make_connector(addr);
    let page = connector.list_since(None).await.unwrap();
    // We expect at least the "profile" non-container; the nested
    // "photos/one.jpg" is discovered via container recursion.
    let keys: Vec<String> = page
        .changes
        .iter()
        .filter_map(|c| match c {
            Change::Upsert(o) => Some(o.key.clone()),
            _ => None,
        })
        .collect();
    assert!(keys.contains(&"profile".to_string()), "keys: {keys:?}");

    // Pick any file (profile) and fetch.
    let profile = page
        .changes
        .iter()
        .find_map(|c| match c {
            Change::Upsert(o) if o.key == "profile" => Some(o.clone()),
            _ => None,
        })
        .unwrap();
    let bytes = connector.fetch(&profile).await.unwrap();
    assert_eq!(bytes.as_ref(), b"card contents");
}

#[tokio::test]
async fn upload_and_delete_round_trip() {
    let (addr, _state) = spawn_pod().await;
    let connector = make_connector(addr);
    let obj = connector
        .upload("newfile.bin", b"new", UploadHints::default())
        .await
        .unwrap();
    assert_eq!(obj.key, "newfile.bin");
    connector.delete(&obj).await.unwrap();
    // Idempotent delete.
    connector.delete(&obj).await.unwrap();
}
