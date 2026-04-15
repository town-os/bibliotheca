//! End-to-end tests for the authenticated HTTP interface.
//!
//! Spawns the interface on an ephemeral port, creates users/subvolumes
//! through the in-process `BibliothecaService`, and then drives the
//! full auth + ACL + object CRUD matrix via a real HTTP client.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::acl::{Acl, AclEntry, Permission, Principal};
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_http::{start, HttpConfig};
use tempfile::TempDir;

struct Harness {
    _tmp: TempDir,
    addr: SocketAddr,
    svc: BibliothecaService,
}

async fn spawn(allow_public: bool) -> Harness {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let svc_for_server = svc.clone();
    tokio::spawn(async move {
        let _ = start(
            svc_for_server,
            HttpConfig {
                listen: addr,
                allow_public,
                share_enabled: false,
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
async fn health_ok() {
    let h = spawn(false).await;
    let resp = client()
        .get(format!("http://{}/health", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn unknown_subvolume_is_not_found() {
    let h = spawn(false).await;
    let _alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/missing/objects/foo",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn anonymous_gets_401_on_private_subvolume() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();

    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/foo",
            h.addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("www-authenticate"));
}

#[tokio::test]
async fn authenticated_user_without_acl_gets_403() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    let _bob = h.svc.create_user("bob", "Bob", "pw").unwrap();

    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/foo",
            h.addr
        ))
        .basic_auth("bob", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn owner_put_get_delete_round_trip() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();

    // PUT
    let resp = client()
        .put(format!(
            "http://{}/v1/subvolumes/photos/objects/foo.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .body("hello http")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // GET
    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/foo.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello http");

    // HEAD
    let resp = client()
        .head(format!(
            "http://{}/v1/subvolumes/photos/objects/foo.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("10")
    );

    // DELETE
    let resp = client()
        .delete(format!(
            "http://{}/v1/subvolumes/photos/objects/foo.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // GET -> 404
    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/foo.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn group_member_read_allowed_write_forbidden() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let bob = h.svc.create_user("bob", "Bob", "pw").unwrap();
    let staff = h.svc.create_group("staff", "").unwrap();
    h.svc.add_user_to_group(bob.id, staff.id).unwrap();

    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::User(alice.id),
        permissions: [Permission::Admin].into_iter().collect(),
    });
    acl.entries.push(AclEntry {
        principal: Principal::Group(staff.id),
        permissions: [Permission::Read, Permission::List].into_iter().collect(),
    });
    h.svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
        .await
        .unwrap();

    // Alice seeds the object.
    client()
        .put(format!(
            "http://{}/v1/subvolumes/photos/objects/shared.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .body("shared")
        .send()
        .await
        .unwrap();

    // Bob reads successfully.
    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/shared.bin",
            h.addr
        ))
        .basic_auth("bob", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "shared");

    // But Bob cannot write.
    let resp = client()
        .put(format!(
            "http://{}/v1/subvolumes/photos/objects/other.bin",
            h.addr
        ))
        .basic_auth("bob", Some("pw"))
        .body("bob was here")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn public_read_with_allow_public_true() {
    let h = spawn(true).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::User(alice.id),
        permissions: [Permission::Admin].into_iter().collect(),
    });
    acl.entries.push(AclEntry {
        principal: Principal::Public,
        permissions: [Permission::Read].into_iter().collect(),
    });
    h.svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
        .await
        .unwrap();
    client()
        .put(format!(
            "http://{}/v1/subvolumes/photos/objects/open.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .body("public")
        .send()
        .await
        .unwrap();

    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/open.bin",
            h.addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "public");
}

#[tokio::test]
async fn public_entry_denied_when_allow_public_false() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::User(alice.id),
        permissions: [Permission::Admin].into_iter().collect(),
    });
    acl.entries.push(AclEntry {
        principal: Principal::Public,
        permissions: [Permission::Read].into_iter().collect(),
    });
    h.svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
        .await
        .unwrap();
    client()
        .put(format!(
            "http://{}/v1/subvolumes/photos/objects/open.bin",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .body("public")
        .send()
        .await
        .unwrap();

    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/open.bin",
            h.addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn list_returns_json_entries() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    for k in ["a.bin", "b.bin"] {
        client()
            .put(format!(
                "http://{}/v1/subvolumes/photos/objects/{k}",
                h.addr
            ))
            .basic_auth("alice", Some("pw"))
            .body(k)
            .send()
            .await
            .unwrap();
    }
    let resp = client()
        .get(format!("http://{}/v1/subvolumes/photos/objects", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["subvolume"], "photos");
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn quota_exceeded_returns_400() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("tiny", alice.id, 4, None)
        .await
        .unwrap();
    let resp = client()
        .put(format!("http://{}/v1/subvolumes/tiny/objects/big", h.addr))
        .basic_auth("alice", Some("pw"))
        .body(vec![0u8; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
