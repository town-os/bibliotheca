//! Smoke tests for the Dropbox API surface router.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_dropbox::{start, DropboxConfig};
use tempfile::TempDir;

async fn spawn() -> (TempDir, SocketAddr) {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let _ = start(svc, DropboxConfig { listen: addr }).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (tmp, addr)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn list_folder_stub_returns_json() {
    let (_tmp, addr) = spawn().await;
    let resp = client()
        .post(format!("http://{addr}/2/files/list_folder"))
        .header("content-type", "application/json")
        .body(r#"{"path":"/foo"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "{}");
}

#[tokio::test]
async fn upload_stub_returns_json() {
    let (_tmp, addr) = spawn().await;
    let resp = client()
        .post(format!("http://{addr}/2/files/upload"))
        .body("data")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn download_stub_returns_json() {
    let (_tmp, addr) = spawn().await;
    let resp = client()
        .post(format!("http://{addr}/2/files/download"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
