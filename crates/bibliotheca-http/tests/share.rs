//! End-to-end tests for the anonymous share-link routes served by
//! `bibliotheca-http`. We drive the same in-process service harness
//! as `auth.rs`, mint share grants via the public
//! `BibliothecaService` API, and then GET the `/s/:token[/...]`
//! routes via a real HTTP client to assert status codes and audit
//! bookkeeping.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::share::CreateShareParams;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_http::{start, HttpConfig};
use tempfile::TempDir;
use time::OffsetDateTime;

struct Harness {
    _tmp: TempDir,
    addr: SocketAddr,
    svc: BibliothecaService,
}

async fn spawn(share_enabled: bool) -> Harness {
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
                allow_public: false,
                share_enabled,
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

/// Seed a subvolume owned by a fresh user and return (owner_id, sv_id).
async fn seed_subvolume(
    svc: &BibliothecaService,
    name: &str,
) -> (
    bibliotheca_core::identity::UserId,
    bibliotheca_core::subvolume::SubvolumeId,
) {
    let alice = svc.create_user("alice", "Alice", "pw").unwrap();
    let sv = svc.create_subvolume(name, alice.id, 0, None).await.unwrap();
    (alice.id, sv.id)
}

/// Seed an object inside a subvolume and return its key.
fn seed_object(svc: &BibliothecaService, sv_name: &str, owner: bibliotheca_core::identity::UserId) {
    let data = DataStore::new(svc.clone());
    data.put(sv_name, "hello.txt", Some(owner), false, b"hi there")
        .unwrap();
}

#[tokio::test]
async fn disabled_share_route_returns_404() {
    let h = spawn(false).await;
    let resp = client()
        .get(format!("http://{}/s/anytoken", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn pinned_key_share_serves_bytes() {
    let h = spawn(true).await;
    let (alice, sv_id) = seed_subvolume(&h.svc, "photos").await;
    seed_object(&h.svc, "photos", alice);

    let grant = h
        .svc
        .create_share(
            CreateShareParams {
                subvolume_id: sv_id,
                created_by: alice,
                key: Some("hello.txt".into()),
                expires_at: None,
                use_limit: None,
                note: "pinned".into(),
            },
            "tok-pinned-1".into(),
        )
        .unwrap();

    // With a pinned key, the bare `/s/:token` route works.
    let resp = client()
        .get(format!("http://{}/s/{}", h.addr, grant.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hi there");

    // Asking for a different key must 403, since the share is pinned.
    let resp = client()
        .get(format!("http://{}/s/{}/other.txt", h.addr, grant.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Uses should be 1 now.
    let refreshed = h.svc.get_share(grant.id).unwrap();
    assert_eq!(refreshed.uses, 1);
}

#[tokio::test]
async fn whole_subvolume_share_requires_key() {
    let h = spawn(true).await;
    let (alice, sv_id) = seed_subvolume(&h.svc, "photos").await;
    seed_object(&h.svc, "photos", alice);

    let grant = h
        .svc
        .create_share(
            CreateShareParams {
                subvolume_id: sv_id,
                created_by: alice,
                key: None,
                expires_at: None,
                use_limit: None,
                note: "whole".into(),
            },
            "tok-whole-1".into(),
        )
        .unwrap();

    // Bare root without a key = 400.
    let resp = client()
        .get(format!("http://{}/s/{}", h.addr, grant.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // With a key, bytes flow.
    let resp = client()
        .get(format!("http://{}/s/{}/hello.txt", h.addr, grant.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hi there");
}

#[tokio::test]
async fn revoked_share_is_gone() {
    let h = spawn(true).await;
    let (alice, sv_id) = seed_subvolume(&h.svc, "photos").await;
    seed_object(&h.svc, "photos", alice);

    let grant = h
        .svc
        .create_share(
            CreateShareParams {
                subvolume_id: sv_id,
                created_by: alice,
                key: Some("hello.txt".into()),
                expires_at: None,
                use_limit: None,
                note: String::new(),
            },
            "tok-revoked-1".into(),
        )
        .unwrap();
    h.svc.revoke_share(grant.id).unwrap();

    let resp = client()
        .get(format!("http://{}/s/{}", h.addr, grant.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 410);
}

#[tokio::test]
async fn expired_share_is_gone() {
    let h = spawn(true).await;
    let (alice, sv_id) = seed_subvolume(&h.svc, "photos").await;
    seed_object(&h.svc, "photos", alice);

    let past = OffsetDateTime::now_utc() - time::Duration::seconds(60);
    let grant = h
        .svc
        .create_share(
            CreateShareParams {
                subvolume_id: sv_id,
                created_by: alice,
                key: Some("hello.txt".into()),
                expires_at: Some(past),
                use_limit: None,
                note: String::new(),
            },
            "tok-exp-1".into(),
        )
        .unwrap();

    let resp = client()
        .get(format!("http://{}/s/{}", h.addr, grant.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 410);
}

#[tokio::test]
async fn use_limit_exhaustion_returns_429() {
    let h = spawn(true).await;
    let (alice, sv_id) = seed_subvolume(&h.svc, "photos").await;
    seed_object(&h.svc, "photos", alice);

    let grant = h
        .svc
        .create_share(
            CreateShareParams {
                subvolume_id: sv_id,
                created_by: alice,
                key: Some("hello.txt".into()),
                expires_at: None,
                use_limit: Some(2),
                note: String::new(),
            },
            "tok-lim-1".into(),
        )
        .unwrap();

    for expected in [200, 200, 429] {
        let resp = client()
            .get(format!("http://{}/s/{}", h.addr, grant.token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), expected);
    }

    // Events should include the final deny.
    let events = h.svc.recent_share_events(grant.id, 10).unwrap();
    assert!(events.iter().any(|e| e.action == "deny" && e.status == 429));
    assert!(events.iter().filter(|e| e.action == "use").count() >= 2);
}

#[tokio::test]
async fn unknown_token_is_not_found() {
    let h = spawn(true).await;
    let resp = client()
        .get(format!("http://{}/s/does-not-exist", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn path_traversal_rejected() {
    let h = spawn(true).await;
    let (alice, sv_id) = seed_subvolume(&h.svc, "photos").await;
    seed_object(&h.svc, "photos", alice);

    let grant = h
        .svc
        .create_share(
            CreateShareParams {
                subvolume_id: sv_id,
                created_by: alice,
                key: None,
                expires_at: None,
                use_limit: None,
                note: String::new(),
            },
            "tok-trav-1".into(),
        )
        .unwrap();

    // axum won't even let `..` reach us in most cases, but make sure
    // the service-layer guard catches any that do.
    let resp = client()
        .get(format!(
            "http://{}/s/{}/..%2Fetc%2Fpasswd",
            h.addr, grant.token
        ))
        .send()
        .await
        .unwrap();
    assert!(matches!(resp.status().as_u16(), 400 | 404));
}
