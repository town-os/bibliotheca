//! End-to-end tests for the Solid (LDP) interface.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::acl::{Acl, AclEntry, Permission, Principal};
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_solid::{start, SolidConfig};
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
            SolidConfig {
                listen: addr,
                base_url: format!("http://{addr}"),
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
async fn options_advertises_verbs() {
    let h = spawn().await;
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{}/pods/alice", h.addr),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let allow = resp.headers().get("allow").unwrap().to_str().unwrap();
    assert!(allow.contains("GET"));
    assert!(allow.contains("PUT"));
    assert!(allow.contains("DELETE"));
}

#[tokio::test]
async fn put_then_get_round_trip() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("alice", alice.id, 0, None)
        .await
        .unwrap();

    let resp = client()
        .put(format!("http://{}/pods/alice/profile/card", h.addr))
        .basic_auth("alice", Some("pw"))
        .body("hello solid")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let resp = client()
        .get(format!("http://{}/pods/alice/profile/card", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("link")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("ldp#Resource"));
    assert_eq!(resp.text().await.unwrap(), "hello solid");
}

#[tokio::test]
async fn container_listing_is_turtle() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("alice", alice.id, 0, None)
        .await
        .unwrap();
    client()
        .put(format!("http://{}/pods/alice/a.ttl", h.addr))
        .basic_auth("alice", Some("pw"))
        .body("foo")
        .send()
        .await
        .unwrap();
    client()
        .put(format!("http://{}/pods/alice/b.ttl", h.addr))
        .basic_auth("alice", Some("pw"))
        .body("bar")
        .send()
        .await
        .unwrap();

    let resp = client()
        .get(format!("http://{}/pods/alice/", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/turtle");
    let body = resp.text().await.unwrap();
    assert!(body.contains("ldp:Container"), "body: {body}");
    assert!(body.contains("a.ttl"), "body: {body}");
    assert!(body.contains("b.ttl"), "body: {body}");
}

#[tokio::test]
async fn post_uses_slug_header() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("alice", alice.id, 0, None)
        .await
        .unwrap();
    let resp = client()
        .post(format!("http://{}/pods/alice/inbox/", h.addr))
        .basic_auth("alice", Some("pw"))
        .header("slug", "msg-1")
        .body("first")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.ends_with("/pods/alice/inbox/msg-1"), "got {loc}");

    let resp = client()
        .get(format!("http://{}/pods/alice/inbox/msg-1", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "first");
}

#[tokio::test]
async fn delete_removes_resource() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("alice", alice.id, 0, None)
        .await
        .unwrap();
    client()
        .put(format!("http://{}/pods/alice/x", h.addr))
        .basic_auth("alice", Some("pw"))
        .body("x")
        .send()
        .await
        .unwrap();
    let resp = client()
        .delete(format!("http://{}/pods/alice/x", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = client()
        .get(format!("http://{}/pods/alice/x", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn anonymous_get_denied_without_public_acl() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("alice", alice.id, 0, None)
        .await
        .unwrap();
    let resp = client()
        .get(format!("http://{}/pods/alice/", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn public_read_allowed_with_explicit_acl() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::User(alice.id),
        permissions: [Permission::Admin].into_iter().collect(),
    });
    acl.entries.push(AclEntry {
        principal: Principal::Public,
        permissions: [Permission::Read, Permission::List].into_iter().collect(),
    });
    h.svc
        .create_subvolume("alice", alice.id, 0, Some(acl))
        .await
        .unwrap();
    client()
        .put(format!("http://{}/pods/alice/welcome.txt", h.addr))
        .basic_auth("alice", Some("pw"))
        .body("hi")
        .send()
        .await
        .unwrap();
    let resp = client()
        .get(format!("http://{}/pods/alice/welcome.txt", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hi");
}
