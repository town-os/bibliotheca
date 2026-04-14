//! End-to-end tests for the Nextcloud WebDAV + OCS interface.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_nextcloud::{start, NextcloudConfig};
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
        let _ = start(svc_spawn, NextcloudConfig { listen: addr }).await;
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

fn dav_path(addr: SocketAddr, user: &str, rest: &str) -> String {
    format!("http://{addr}/remote.php/dav/files/{user}/{rest}")
}

#[tokio::test]
async fn unauth_is_rejected() {
    let h = spawn().await;
    let resp = client()
        .get(dav_path(h.addr, "alice", "photos/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn user_path_must_match_authed_user() {
    let h = spawn().await;
    let _alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let _bob = h.svc.create_user("bob", "Bob", "pw").unwrap();
    let resp = client()
        .get(dav_path(h.addr, "alice", "photos/x.bin"))
        .basic_auth("bob", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn put_then_get_and_delete() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();

    let resp = client()
        .put(dav_path(h.addr, "alice", "photos/a.bin"))
        .basic_auth("alice", Some("pw"))
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let resp = client()
        .get(dav_path(h.addr, "alice", "photos/a.bin"))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");

    let resp = client()
        .delete(dav_path(h.addr, "alice", "photos/a.bin"))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn mkcol_creates_collection() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    let resp = client()
        .request(
            reqwest::Method::from_bytes(b"MKCOL").unwrap(),
            dav_path(h.addr, "alice", "photos/2024"),
        )
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn propfind_lists_collection_members() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    for k in ["photos/a.bin", "photos/b.bin"] {
        client()
            .put(dav_path(h.addr, "alice", k))
            .basic_auth("alice", Some("pw"))
            .body("x")
            .send()
            .await
            .unwrap();
    }
    let resp = client()
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            dav_path(h.addr, "alice", "photos/"),
        )
        .basic_auth("alice", Some("pw"))
        .header("depth", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert!(body.contains("a.bin"), "body: {body}");
    assert!(body.contains("b.bin"), "body: {body}");
}

#[tokio::test]
async fn shares_endpoint_returns_ocs_envelope() {
    let h = spawn().await;
    let resp = client()
        .get(format!(
            "http://{}/ocs/v2.php/apps/files_sharing/api/v1/shares",
            h.addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<ocs>"), "body: {body}");
    assert!(body.contains("<statuscode>200</statuscode>"));
}
