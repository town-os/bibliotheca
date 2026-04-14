//! End-to-end tests for the Dropbox API surface.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_dropbox::{start, DropboxConfig};
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
        let _ = start(svc_spawn, DropboxConfig { listen: addr }).await;
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
async fn missing_auth_returns_401() {
    let h = spawn().await;
    let resp = client()
        .post(format!("http://{}/2/files/list_folder", h.addr))
        .header("content-type", "application/json")
        .body(r#"{"path":"/photos"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn upload_download_list_round_trip() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();

    // Upload
    let resp = client()
        .post(format!("http://{}/2/files/upload", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .header("dropbox-api-arg", r#"{"path":"/photos/a.jpg"}"#)
        .header("content-type", "application/octet-stream")
        .body(Vec::from(&b"picture bytes"[..]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let meta: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(meta["size"], 13);

    // Download
    let resp = client()
        .post(format!("http://{}/2/files/download", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .header("dropbox-api-arg", r#"{"path":"/photos/a.jpg"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result_hdr = resp
        .headers()
        .get("dropbox-api-result")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), b"picture bytes");
    let v: serde_json::Value = serde_json::from_str(&result_hdr).unwrap();
    assert_eq!(v["size"], 13);

    // List folder
    let resp = client()
        .post(format!("http://{}/2/files/list_folder", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .header("content-type", "application/json")
        .body(r#"{"path":"/photos"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "a.jpg");
    assert_eq!(entries[0]["path_display"], "/photos/a.jpg");
}

#[tokio::test]
async fn delete_v2_removes_file() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    client()
        .post(format!("http://{}/2/files/upload", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .header("dropbox-api-arg", r#"{"path":"/photos/x.bin"}"#)
        .body("x")
        .send()
        .await
        .unwrap();
    let resp = client()
        .post(format!("http://{}/2/files/delete_v2", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .header("content-type", "application/json")
        .body(r#"{"path":"/photos/x.bin"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client()
        .post(format!("http://{}/2/files/get_metadata", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .header("content-type", "application/json")
        .body(r#"{"path":"/photos/x.bin"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn other_user_forbidden() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let _bob = h.svc.create_user("bob", "Bob", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    let resp = client()
        .post(format!("http://{}/2/files/upload", h.addr))
        .header("authorization", bearer("bob", "pw"))
        .header("dropbox-api-arg", r#"{"path":"/photos/evil.bin"}"#)
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
