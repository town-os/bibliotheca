//! End-to-end tests for the admin HTTP panel.
//!
//! Spawns the panel on an ephemeral TCP port, seeds the metadata
//! store with users / groups / subvolumes, and drives the routes
//! with a real HTTP client. The decisive assertions are that a
//! member of the admin group can browse and download objects in
//! subvolumes they do *not* own, and that a non-member cannot get
//! past the middleware at all.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_admin::{start, AdminConfig};
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use tempfile::TempDir;

struct Harness {
    _tmp: TempDir,
    addr: SocketAddr,
    svc: BibliothecaService,
}

async fn spawn_with_group(make_admins: bool) -> Harness {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);

    // Seed the common fixture: alice (admin), bob (non-admin),
    // carol (independent owner), plus two subvolumes with some
    // objects.
    let alice = svc.create_user("alice", "Alice", "pw").unwrap();
    let _bob = svc.create_user("bob", "Bob", "pw").unwrap();
    let carol = svc.create_user("carol", "Carol", "pw").unwrap();
    if make_admins {
        let admins = svc.create_group("admins", "admin panel").unwrap();
        svc.add_user_to_group(alice.id, admins.id).unwrap();
    }

    svc.create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();
    svc.create_subvolume("private", carol.id, 0, None)
        .await
        .unwrap();

    let data = DataStore::new(svc.clone());
    data.put("photos", "hello.txt", Some(alice.id), false, b"hi admin")
        .unwrap();
    data.put(
        "photos",
        "sub/deep.bin",
        Some(alice.id),
        false,
        &[1u8, 2, 3],
    )
    .unwrap();
    data.put("private", "secret.txt", Some(carol.id), false, b"shh")
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let svc_spawn = svc.clone();
    tokio::spawn(async move {
        let _ = start(
            svc_spawn,
            AdminConfig {
                listen: addr,
                admin_group: "admins".into(),
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

async fn spawn() -> Harness {
    spawn_with_group(true).await
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn health_ok() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/health", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn dashboard_requires_auth() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/admin", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("www-authenticate"));
}

#[tokio::test]
async fn dashboard_denies_non_admin() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/admin", h.addr))
        .basic_auth("bob", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn dashboard_allows_admin() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/admin", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("dashboard"), "body: {body}");
    assert!(body.contains("users"), "body: {body}");
    assert!(body.contains("subvolumes"), "body: {body}");
}

#[tokio::test]
async fn subvolumes_index_lists_all() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/admin/subvolumes", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains(">photos<"), "body: {body}");
    assert!(body.contains(">private<"), "body: {body}");
}

#[tokio::test]
async fn subvolume_detail_shows_acl() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/admin/subvolumes/photos", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("user: alice"), "body: {body}");
    assert!(body.contains("admin"), "body: {body}");
}

#[tokio::test]
async fn tree_lists_directory() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/admin/subvolumes/photos/tree", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("hello.txt"), "body: {body}");
    assert!(body.contains("sub/"), "body: {body}");
}

#[tokio::test]
async fn tree_nested() {
    let h = spawn().await;
    let resp = client()
        .get(format!(
            "http://{}/admin/subvolumes/photos/tree/sub",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("deep.bin"), "body: {body}");
    // Breadcrumb links back to the subvolume root.
    assert!(
        body.contains("/admin/subvolumes/photos/tree"),
        "body: {body}"
    );
}

#[tokio::test]
async fn download_round_trips_bytes() {
    let h = spawn().await;
    let resp = client()
        .get(format!(
            "http://{}/admin/subvolumes/photos/download/hello.txt",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert!(resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("hello.txt"));
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"hi admin");
}

#[tokio::test]
async fn download_bypasses_acl() {
    // alice is in "admins" but has no entry on `private`'s ACL
    // (private is owned by carol). The admin panel must still
    // serve the bytes — that's the whole point of the bypass.
    let h = spawn().await;
    assert!(!h
        .svc
        .check_permission(
            h.svc.get_subvolume("private").unwrap().id,
            Some(h.svc.get_user("alice").unwrap().id),
            bibliotheca_core::acl::Permission::Read,
            false,
        )
        .unwrap());
    let resp = client()
        .get(format!(
            "http://{}/admin/subvolumes/private/download/secret.txt",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"shh");
}

#[tokio::test]
async fn traversal_rejected() {
    let h = spawn().await;
    let resp = client()
        .get(format!(
            "http://{}/admin/subvolumes/photos/tree/..%2F..%2Fetc%2Fpasswd",
            h.addr
        ))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("root:"), "leaked /etc/passwd: {body}");
}

#[tokio::test]
async fn users_and_groups_pages() {
    let h = spawn().await;
    // Users list contains both alice and bob.
    let resp = client()
        .get(format!("http://{}/admin/users", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains(">alice<"), "body: {body}");
    assert!(body.contains(">bob<"), "body: {body}");

    // Group detail for `admins` must contain alice but not bob.
    let resp = client()
        .get(format!("http://{}/admin/groups/admins", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains(">alice<"), "body: {body}");
    assert!(!body.contains(">bob<"), "body should not list bob: {body}");
}

#[tokio::test]
async fn missing_admin_group_denies_everyone() {
    let h = spawn_with_group(false).await;
    // alice has valid credentials but no admin group exists at all.
    let resp = client()
        .get(format!("http://{}/admin", h.addr))
        .basic_auth("alice", Some("pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
