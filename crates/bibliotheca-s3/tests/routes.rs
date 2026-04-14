//! End-to-end tests for the S3 interface.
//!
//! Each test spawns the interface on an ephemeral port and drives it
//! with a real HTTP client. The service is backed by the in-process
//! `MemoryBackend` so we can create subvolumes with `BibliothecaService`
//! directly, then talk to them with bucket-shaped S3 requests over
//! TCP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_s3::{start, S3Config};
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
        let _ = start(
            svc_spawn,
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
    Harness {
        _tmp: tmp,
        addr,
        svc,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn unauthenticated_requests_are_rejected() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn list_buckets_returns_owned_subvolumes() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    h.svc
        .create_subvolume("docs", alice.id, 0, None)
        .await
        .unwrap();
    let resp = client()
        .get(format!("http://{}/", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Name>photos</Name>"));
    assert!(body.contains("<Name>docs</Name>"));
}

#[tokio::test]
async fn put_get_delete_object_round_trip() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    // PUT
    let resp = client()
        .put(format!("http://{}/photos/hello.bin", h.addr))
        .basic_auth("alice", Some("pw"))
        .body(Vec::from(&b"hello s3"[..]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // GET
    let resp = client()
        .get(format!("http://{}/photos/hello.bin", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"hello s3");
    // HEAD
    let resp = client()
        .head(format!("http://{}/photos/hello.bin", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("8")
    );
    // DELETE
    let resp = client()
        .delete(format!("http://{}/photos/hello.bin", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    // GET -> 404
    let resp = client()
        .get(format!("http://{}/photos/hello.bin", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn list_objects_returns_nested_keys() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    for (k, v) in [
        ("a.txt", "1"),
        ("nested/b.txt", "22"),
        ("nested/deep/c.txt", "333"),
    ] {
        client()
            .put(format!("http://{}/photos/{k}", h.addr))
            .basic_auth("alice", Some("pw"))
            .body(v.to_string())
            .send()
            .await
            .unwrap();
    }
    let resp = client()
        .get(format!("http://{}/photos", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>a.txt</Key>"), "body: {body}");
    assert!(body.contains("<Key>nested/b.txt</Key>"), "body: {body}");
    assert!(
        body.contains("<Key>nested/deep/c.txt</Key>"),
        "body: {body}"
    );
    assert!(body.contains("<KeyCount>3</KeyCount>"), "body: {body}");
}

#[tokio::test]
async fn create_bucket_creates_subvolume_owned_by_caller() {
    let h = spawn().await;
    let _alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let resp = client()
        .put(format!("http://{}/new-bucket", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let sv = h.svc.get_subvolume("new-bucket").unwrap();
    assert_eq!(sv.name, "new-bucket");
}

#[tokio::test]
async fn non_owner_cannot_delete_bucket() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let _bob = h.svc.create_user("bob", "Bob", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    let resp = client()
        .delete(format!("http://{}/photos", h.addr))
        .basic_auth("bob", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    // Subvolume still exists.
    assert!(h.svc.get_subvolume("photos").is_ok());
}

#[tokio::test]
async fn quota_is_enforced_on_put() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("tiny", alice.id, 4, None)
        .await
        .unwrap();
    let resp = client()
        .put(format!("http://{}/tiny/big.bin", h.addr))
        .basic_auth("alice", Some("pw"))
        .body(vec![0u8; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn sigv4_header_with_side_secret_authenticates() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    let auth = "AWS4-HMAC-SHA256 Credential=alice/20260414/bibliotheca/s3/aws4_request, \
                SignedHeaders=host, Signature=ignored";
    let resp = client()
        .get(format!("http://{}/photos", h.addr))
        .header("Authorization", auth)
        .header("X-Amz-Bibliotheca-Secret", "pw")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
