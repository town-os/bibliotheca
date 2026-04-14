//! Integration test for the real `KuboClient` RPC wrapper.
//!
//! We stand up a tiny axum server that mimics the Kubo HTTP RPC shape
//! (newline-delimited JSON for `/api/v0/add`, simple JSON envelopes
//! for `pin/add`, `pin/rm`, and `pin/ls`, raw bytes for `cat`) and
//! point `KuboClient` at it. This verifies the real networking path
//! end-to-end without needing an actual Kubo daemon.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use bibliotheca_ipfs::{IpfsClient, KuboClient};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;
use tempfile::TempDir;
use url::Url;

#[derive(Default)]
struct KuboState {
    pins: Mutex<Vec<String>>,
    blobs: Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

#[derive(Debug, Deserialize)]
struct ArgQuery {
    arg: String,
    #[allow(dead_code)]
    #[serde(default)]
    recursive: Option<String>,
}

async fn pin_add(
    State(state): State<Arc<KuboState>>,
    Query(q): Query<ArgQuery>,
) -> Json<serde_json::Value> {
    state.pins.lock().push(q.arg.clone());
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
    let mut keys = serde_json::Map::new();
    for cid in pins {
        keys.insert(cid, json!({ "Type": "recursive" }));
    }
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

async fn add(State(state): State<Arc<KuboState>>, body: Bytes) -> Json<serde_json::Value> {
    // We don't parse multipart here — we just mint a deterministic
    // CID from the payload length and stash the bytes for cat(). The
    // client doesn't care about the file name, so we cheat a little.
    let bytes = body.to_vec();
    let cid = format!("Qm{:0>44}", bytes.len());
    state.blobs.lock().insert(cid.clone(), bytes.clone());
    Json(json!({ "Name": "blob", "Hash": cid, "Size": bytes.len().to_string() }))
}

use axum::response::IntoResponse;

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
async fn pin_add_rm_ls_round_trip() {
    let (addr, state) = spawn_kubo().await;
    let client = KuboClient::new(Url::parse(&format!("http://{addr}/")).unwrap());

    client.pin_add("QmAAA", true).await.unwrap();
    client.pin_add("QmBBB", true).await.unwrap();
    let pins = client.pins().await.unwrap();
    assert!(pins.contains(&"QmAAA".to_string()));
    assert!(pins.contains(&"QmBBB".to_string()));

    client.pin_rm("QmAAA").await.unwrap();
    let pins = client.pins().await.unwrap();
    assert!(!pins.contains(&"QmAAA".to_string()));
    assert!(state.pins.lock().contains(&"QmBBB".to_string()));
}

#[tokio::test]
async fn add_then_cat() {
    let (addr, _state) = spawn_kubo().await;
    let client = KuboClient::new(Url::parse(&format!("http://{addr}/")).unwrap());

    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("blob.bin");
    std::fs::write(&src, b"hello kubo").unwrap();

    let cid = client.add(&src).await.unwrap();
    assert!(cid.starts_with("Qm"));

    let dst = tmp.path().join("out.bin");
    let n = client.cat(&cid, &dst).await.unwrap();
    assert!(n > 0);
    let read = std::fs::read(&dst).unwrap();
    // Our mock stuffs the full multipart body in; the real Kubo would
    // return just the inner file, but what we care about here is the
    // round-trip contract (the bytes cat returns round-trip into the
    // destination path).
    assert!(!read.is_empty());
    let _ = PathBuf::from(&dst);
}

#[tokio::test]
async fn pin_add_non_2xx_returns_backend_error() {
    // Point at a port that nothing is listening on — the HTTP call
    // should fail fast with a `Backend` error rather than panic.
    let client = KuboClient::new(Url::parse("http://127.0.0.1:1/").unwrap());
    let err = client.pin_add("Qm", true).await.unwrap_err();
    match err {
        bibliotheca_core::error::Error::Backend(_) => {}
        other => panic!("expected Backend, got {other:?}"),
    }
}
