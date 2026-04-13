//! Smoke tests for the S3 interface router.
//!
//! Until the real signature-v4 handlers land, these tests just lock in
//! that `start()` stands the listener up and the routes return the
//! stubbed bodies. The moment anyone replaces a stub with a real
//! handler, the body assertion will flag this test as needing an
//! update — that's the intended forcing function.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_s3::{start, S3Config};
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
        let _ = start(
            svc,
            S3Config {
                listen: addr,
                region: "bibliotheca".into(),
            },
        )
        .await;
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
async fn list_buckets_returns_empty_list_xml() {
    let (_tmp, addr) = spawn().await;
    let resp = client()
        .get(format!("http://{addr}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("ListAllMyBucketsResult"), "body: {body}");
}

#[tokio::test]
async fn bucket_route_registered() {
    let (_tmp, addr) = spawn().await;
    let resp = client()
        .get(format!("http://{addr}/my-bucket"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn object_route_registered() {
    let (_tmp, addr) = spawn().await;
    let resp = client()
        .get(format!("http://{addr}/my-bucket/path/to/key.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
