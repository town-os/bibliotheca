//! Integration tests for the authenticated HTTP interface.
//!
//! Spawns the interface on an ephemeral port, creates users/subvolumes
//! through the in-process `BibliothecaService`, and verifies the four
//! ACL branches end-to-end via a real HTTP client:
//!
//! 1. Unknown subvolume -> 404
//! 2. Anonymous request on a non-public ACL -> 401 + WWW-Authenticate
//! 3. Authenticated request without ACL grant -> 403
//! 4. Authenticated request with ACL grant -> 204 (body streaming is
//!    the next implementation step, so 204 is the current success code)
//! 5. Anonymous request on an ACL with Public Read + allow_public=true
//!    -> 204
//! 6. Anonymous request with allow_public=false even when the ACL has
//!    Public Read -> 401

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

    // Bind ephemeral port, then hand the address back to the test.
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
            },
        )
        .await;
    });

    // Wait for the listener to be accepting.
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
    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/missing/objects/foo",
            h.addr
        ))
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
async fn owner_is_authorized() {
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
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    // Body streaming is not yet implemented — success path currently
    // returns 204 once ACL passes.
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn group_member_is_authorized() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let bob = h.svc.create_user("bob", "Bob", "pw").unwrap();
    let staff = h.svc.create_group("staff", "").unwrap();
    h.svc.add_user_to_group(bob.id, staff.id).unwrap();

    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::Group(staff.id),
        permissions: [Permission::Read].into_iter().collect(),
    });
    h.svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
        .await
        .unwrap();

    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/foo",
            h.addr
        ))
        .basic_auth("bob", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn public_with_allow_public_true() {
    let h = spawn(true).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::Public,
        permissions: [Permission::Read].into_iter().collect(),
    });
    h.svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
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
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn public_entry_denied_when_allow_public_false() {
    let h = spawn(false).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::Public,
        permissions: [Permission::Read].into_iter().collect(),
    });
    h.svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
        .await
        .unwrap();

    // Same ACL, but the daemon was told not to honour Public.
    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/foo",
            h.addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn bad_password_falls_through_to_public_check() {
    let h = spawn(true).await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::Public,
        permissions: [Permission::Read].into_iter().collect(),
    });
    h.svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
        .await
        .unwrap();

    // Wrong credentials: the server currently treats auth-failure the
    // same as anonymous and re-evaluates ACLs against `None`. With a
    // Public Read entry and allow_public=true, that succeeds.
    let resp = client()
        .get(format!(
            "http://{}/v1/subvolumes/photos/objects/foo",
            h.addr
        ))
        .basic_auth("alice", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}
