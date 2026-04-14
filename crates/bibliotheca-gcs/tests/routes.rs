//! End-to-end tests for the Google Cloud Storage JSON API.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_gcs::{start, GcsConfig};
use tempfile::TempDir;

struct Harness {
    _tmp: TempDir,
    addr: SocketAddr,
    svc: BibliothecaService,
}

async fn spawn() -> Harness {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let svc_spawn = svc.clone();
    tokio::spawn(async move {
        let _ = start(svc_spawn, GcsConfig { listen: addr }).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Harness {
        _tmp: tmp,
        addr,
        svc,
    }
}

fn bearer(user: &str, pw: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"));
    format!("Bearer {b64}")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn unauth_is_rejected() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/storage/v1/b", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn bucket_create_get_delete() {
    let h = spawn().await;
    let _alice = h.svc.create_user("alice", "Alice", "pw").unwrap();

    let resp = client()
        .post(format!("http://{}/storage/v1/b", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .json(&serde_json::json!({ "name": "photos" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["name"], "photos");

    let resp = client()
        .get(format!("http://{}/storage/v1/b/photos", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client()
        .delete(format!("http://{}/storage/v1/b/photos", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(h.svc.get_subvolume("photos").is_err());
}

#[tokio::test]
async fn object_upload_list_download_delete() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();

    // Upload
    let resp = client()
        .post(format!(
            "http://{}/upload/storage/v1/b/photos/o?name=a.bin&uploadType=media",
            h.addr
        ))
        .header("authorization", bearer("alice", "pw"))
        .body(Vec::from(&b"payload"[..]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["name"], "a.bin");
    assert_eq!(v["size"], "7");

    // List
    let resp = client()
        .get(format!("http://{}/storage/v1/b/photos/o", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "a.bin");

    // Get metadata
    let resp = client()
        .get(format!("http://{}/storage/v1/b/photos/o/a.bin", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["size"], "7");

    // Download media
    let resp = client()
        .get(format!(
            "http://{}/storage/v1/b/photos/o/a.bin?alt=media",
            h.addr
        ))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"payload");

    // Delete
    let resp = client()
        .delete(format!("http://{}/storage/v1/b/photos/o/a.bin", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn other_user_cannot_delete_bucket() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let _bob = h.svc.create_user("bob", "Bob", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    let resp = client()
        .delete(format!("http://{}/storage/v1/b/photos", h.addr))
        .header("authorization", bearer("bob", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
