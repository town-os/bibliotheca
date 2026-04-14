//! End-to-end tests for the Google Photos Library API surface.
//!
//! Spawns the interface on an ephemeral TCP port, seeds a library
//! subvolume with `MemoryBackend`, then drives the upload →
//! batchCreate → list → search → download flow via `reqwest` plus
//! covers the auth / permission edges.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_photos::{start, PhotosConfig};
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

    // alice owns the photos library; bob is an unrelated user.
    let alice = svc.create_user("alice", "Alice", "pw").unwrap();
    let _bob = svc.create_user("bob", "Bob", "pw").unwrap();
    svc.create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let svc_spawn = svc.clone();
    tokio::spawn(async move {
        let _ = start(
            svc_spawn,
            PhotosConfig {
                listen: addr,
                library: "photos".into(),
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

fn bearer(user: &str, pw: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"));
    format!("Bearer {b64}")
}

fn url_safe_b64(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn upload(h: &Harness, user: &str, file_name: &str, bytes: Vec<u8>) -> reqwest::Response {
    client()
        .post(format!("http://{}/v1/uploads", h.addr))
        .header("authorization", bearer(user, "pw"))
        .header("content-type", "application/octet-stream")
        .header("x-goog-upload-protocol", "raw")
        .header("x-goog-upload-file-name", file_name)
        .body(bytes)
        .send()
        .await
        .unwrap()
}

async fn batch_create(
    h: &Harness,
    user: &str,
    album_id: Option<&str>,
    token: &str,
    file_name: &str,
) -> reqwest::Response {
    let mut body = serde_json::json!({
        "newMediaItems": [
            { "simpleMediaItem": { "uploadToken": token, "fileName": file_name } }
        ]
    });
    if let Some(id) = album_id {
        body["albumId"] = serde_json::Value::String(id.to_string());
    }
    client()
        .post(format!("http://{}/v1/mediaItems/batchCreate", h.addr))
        .header("authorization", bearer(user, "pw"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn unauth_is_rejected() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/v1/albums", h.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn create_and_list_album() {
    let h = spawn().await;
    let resp = client()
        .post(format!("http://{}/v1/albums", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .json(&serde_json::json!({ "album": { "title": "trip-2024" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["title"], "trip-2024");
    let album_id = v["id"].as_str().unwrap().to_string();

    let resp = client()
        .get(format!("http://{}/v1/albums", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let albums = v["albums"].as_array().unwrap();
    assert_eq!(albums.len(), 1);
    assert_eq!(albums[0]["id"], album_id);
    assert_eq!(albums[0]["title"], "trip-2024");
}

#[tokio::test]
async fn upload_batch_create_round_trip() {
    let h = spawn().await;

    // Create album.
    let resp = client()
        .post(format!("http://{}/v1/albums", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .json(&serde_json::json!({ "album": { "title": "vacation" } }))
        .send()
        .await
        .unwrap();
    let album_id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Upload raw bytes → token.
    let resp = upload(&h, "alice", "sunset.jpg", b"pixels here".to_vec()).await;
    assert_eq!(resp.status(), 200);
    let token = resp.text().await.unwrap();
    assert!(!token.is_empty());

    // batchCreate with the token + album id.
    let resp = batch_create(&h, "alice", Some(&album_id), &token, "sunset.jpg").await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let results = v["newMediaItemResults"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["status"]["code"], 0);
    let media = &results[0]["mediaItem"];
    let media_id = media["id"].as_str().unwrap().to_string();
    assert_eq!(media["filename"], "sunset.jpg");

    // list mediaItems → contains our item.
    let resp = client()
        .get(format!("http://{}/v1/mediaItems", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let items = v["mediaItems"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], media_id);

    // search with albumId.
    let resp = client()
        .post(format!("http://{}/v1/mediaItems/search", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .json(&serde_json::json!({ "albumId": album_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let items = v["mediaItems"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], media_id);

    // Get one.
    let resp = client()
        .get(format!("http://{}/v1/mediaItems/{media_id}", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["filename"], "sunset.jpg");

    // Download via /v1/downloads/:id returns the bytes we uploaded.
    let resp = client()
        .get(format!("http://{}/v1/downloads/{media_id}", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"pixels here");
}

#[tokio::test]
async fn batch_create_rejects_unknown_token() {
    let h = spawn().await;
    let resp = batch_create(&h, "alice", None, "no-such-token", "x.jpg").await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let results = v["newMediaItemResults"].as_array().unwrap();
    assert_eq!(results[0]["status"]["code"], 3);
}

#[tokio::test]
async fn search_filters_by_album() {
    let h = spawn().await;
    // Create two albums.
    for title in ["a", "b"] {
        client()
            .post(format!("http://{}/v1/albums", h.addr))
            .header("authorization", bearer("alice", "pw"))
            .json(&serde_json::json!({ "album": { "title": title } }))
            .send()
            .await
            .unwrap();
    }
    let id_a = url_safe_b64("a");
    let id_b = url_safe_b64("b");

    // Put one item into each.
    for (album_id, file) in [(&id_a, "1.jpg"), (&id_b, "2.jpg")] {
        let tok = upload(&h, "alice", file, file.as_bytes().to_vec())
            .await
            .text()
            .await
            .unwrap();
        let resp = batch_create(&h, "alice", Some(album_id), &tok, file).await;
        assert_eq!(resp.status(), 200);
    }

    // Search album A → one item.
    let resp = client()
        .post(format!("http://{}/v1/mediaItems/search", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .json(&serde_json::json!({ "albumId": id_a }))
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    let items = v["mediaItems"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["filename"], "1.jpg");

    // Unfiltered list → two items.
    let resp = client()
        .get(format!("http://{}/v1/mediaItems", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["mediaItems"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn other_user_cannot_upload() {
    let h = spawn().await;
    // bob has valid creds but isn't on the photos subvolume ACL.
    let resp = upload(&h, "bob", "evil.jpg", b"no".to_vec()).await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn other_user_cannot_list() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/v1/mediaItems", h.addr))
        .header("authorization", bearer("bob", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn get_album_by_id() {
    let h = spawn().await;
    client()
        .post(format!("http://{}/v1/albums", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .json(&serde_json::json!({ "album": { "title": "vacation" } }))
        .send()
        .await
        .unwrap();
    let id = url_safe_b64("vacation");
    let resp = client()
        .get(format!("http://{}/v1/albums/{id}", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["title"], "vacation");
    assert_eq!(v["id"], id);
}

#[tokio::test]
async fn invalid_album_id_rejected() {
    let h = spawn().await;
    let resp = client()
        .get(format!("http://{}/v1/albums/***not-base64***", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn missing_upload_file_name_rejected() {
    let h = spawn().await;
    let resp = client()
        .post(format!("http://{}/v1/uploads", h.addr))
        .header("authorization", bearer("alice", "pw"))
        .body(Vec::from(&b"bytes"[..]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn upload_requires_library_write() {
    let h = spawn().await;
    // Wipe alice's subvolume owner ACL + replace with read-only for her.
    // Easiest: make bob the owner and alice loses all permissions.
    // We can't re-assign ownership, so instead: create a read-only ACL
    // with only a dummy user, then alice becomes an unrelated caller.
    use bibliotheca_core::acl::{Acl, AclEntry, Permission, Principal};
    let carol = h.svc.create_user("carol", "Carol", "pw").unwrap();
    let mut ro = Acl::new();
    ro.entries.push(AclEntry {
        principal: Principal::User(carol.id),
        permissions: [Permission::Read, Permission::List].into_iter().collect(),
    });
    // Apply the read-only ACL to the existing photos subvolume.
    let sv = h.svc.get_subvolume("photos").unwrap();
    h.svc.set_acl(sv.id, &ro).unwrap();

    // carol can list (no items yet) but cannot upload.
    let resp = client()
        .get(format!("http://{}/v1/mediaItems", h.addr))
        .header("authorization", bearer("carol", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = upload(&h, "carol", "a.jpg", b"nope".to_vec()).await;
    assert_eq!(resp.status(), 403);
}
