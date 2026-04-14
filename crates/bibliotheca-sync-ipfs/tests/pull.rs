//! Integration test for IpfsSyncConnector against an axum-mocked
//! Kubo RPC. The mock replays the subset of `/api/v0/*` endpoints
//! the connector actually calls: `pin/ls`, `pin/add`, `pin/rm`,
//! `cat`, `add`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes as AxumBytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use bibliotheca_sync_core::credentials::CredentialBlob;
use bibliotheca_sync_core::scheduler::ConnectorRegistry;
use bibliotheca_sync_core::trait_::{Change, UploadHints};
use bibliotheca_sync_ipfs::IpfsSyncConnector;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;

#[derive(Default)]
struct KuboState {
    pins: Mutex<Vec<String>>,
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

#[derive(Debug, Deserialize)]
struct ArgQuery {
    arg: String,
}

async fn pin_add(
    State(state): State<Arc<KuboState>>,
    Query(q): Query<ArgQuery>,
) -> Json<serde_json::Value> {
    let mut pins = state.pins.lock();
    if !pins.iter().any(|c| c == &q.arg) {
        pins.push(q.arg.clone());
    }
    Json(json!({ "Pins": [q.arg] }))
}

async fn pin_rm(
    State(state): State<Arc<KuboState>>,
    Query(q): Query<ArgQuery>,
) -> Json<serde_json::Value> {
    state.pins.lock().retain(|c| c != &q.arg);
    Json(json!({ "Pins": [q.arg] }))
}

async fn pin_ls(State(state): State<Arc<KuboState>>) -> Json<serde_json::Value> {
    let pins = state.pins.lock().clone();
    let keys: serde_json::Map<String, serde_json::Value> = pins
        .into_iter()
        .map(|cid| (cid, json!({ "Type": "recursive" })))
        .collect();
    Json(json!({ "Keys": keys }))
}

async fn cat(
    State(state): State<Arc<KuboState>>,
    Query(q): Query<ArgQuery>,
) -> axum::response::Response {
    match state.blobs.lock().get(&q.arg).cloned() {
        Some(bytes) => (StatusCode::OK, bytes).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn add(State(state): State<Arc<KuboState>>, body: AxumBytes) -> Json<serde_json::Value> {
    // We fake Kubo's multipart parsing by hashing the whole
    // request body and using that as the CID. The real /add
    // endpoint unwraps multipart/form-data first, which reqwest's
    // multipart encoding wraps around the inner bytes; the test
    // doesn't care about that layer.
    let cid = format!("Qm{:0>44x}", body.len());
    state.blobs.lock().insert(cid.clone(), body.to_vec());
    Json(json!({ "Name": "blob", "Hash": cid, "Size": body.len().to_string() }))
}

async fn spawn_kubo() -> (SocketAddr, Arc<KuboState>) {
    let state = Arc::new(KuboState::default());
    let app = Router::new()
        .route("/api/v0/pin/add", post(pin_add))
        .route("/api/v0/pin/rm", post(pin_rm))
        .route("/api/v0/pin/ls", post(pin_ls))
        .route("/api/v0/cat", post(cat))
        .route("/api/v0/add", post(add))
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

#[tokio::test]
async fn factory_registers_connector() {
    let registry = ConnectorRegistry::new();
    IpfsSyncConnector::register(&registry);
    assert!(registry.has(bibliotheca_sync_core::mount::ConnectorKind::Ipfs));
}

#[tokio::test]
async fn factory_rejects_wrong_credential_kind() {
    let factory = IpfsSyncConnector::factory();
    let wrong = CredentialBlob::Basic {
        username: "u".into(),
        password: "p".into(),
    };
    assert!(factory(&wrong, "{}").is_err());
}

#[tokio::test]
async fn upload_then_list_then_fetch_then_delete() {
    let (addr, _state) = spawn_kubo().await;
    let factory = IpfsSyncConnector::factory();
    let blob = CredentialBlob::Ipfs {
        api_url: format!("http://{addr}/"),
        auth_header: None,
    };
    let connector = factory(&blob, "{}").unwrap();

    // Seed an object via upload.
    let obj = connector
        .upload("hello.txt", b"hello ipfs sync", UploadHints::default())
        .await
        .unwrap();
    assert!(obj.id.starts_with("Qm"));

    // list_since returns the pinned cid.
    let page = connector.list_since(None).await.unwrap();
    assert_eq!(page.changes.len(), 1);
    let Change::Upsert(listed) = &page.changes[0] else {
        panic!("expected Upsert");
    };
    assert_eq!(listed.id, obj.id);

    // fetch returns the bytes.
    let bytes = connector.fetch(listed).await.unwrap();
    assert!(!bytes.is_empty());

    // delete → pin_rm.
    connector.delete(listed).await.unwrap();
    let after = connector.list_since(None).await.unwrap();
    assert!(after.changes.is_empty());
}
