//! End-to-end tests for the iCloud (CloudKit Web Services) interface.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_icloud::{start, ICloudConfig};
use tempfile::TempDir;

const CONTAINER: &str = "iCloud.com.town-os.test";

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
            ICloudConfig {
                listen: addr,
                container: CONTAINER.into(),
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

fn cksession(user: &str, pw: &str) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"));
    format!("Basic {b64}")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn url(addr: SocketAddr, tail: &str) -> String {
    format!("http://{addr}/database/1/{CONTAINER}/public/public/{tail}")
}

#[tokio::test]
async fn unauth_is_rejected() {
    let h = spawn().await;
    let resp = client()
        .post(url(h.addr, "records/query"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn unknown_container_returns_404() {
    let h = spawn().await;
    let resp = client()
        .post(format!(
            "http://{}/database/1/iCloud.com.other/public/public/records/query",
            h.addr
        ))
        .header("cksession", cksession("alice", "pw"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn records_modify_create_delete_round_trip() {
    let h = spawn().await;
    let _alice = h.svc.create_user("alice", "Alice", "pw").unwrap();

    let resp = client()
        .post(url(h.addr, "records/modify"))
        .header("cksession", cksession("alice", "pw"))
        .json(&serde_json::json!({
            "operations": [
                { "operationType": "create", "record": { "recordName": "photos", "fields": {} } }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(h.svc.get_subvolume("photos").is_ok());

    let resp = client()
        .post(url(h.addr, "records/modify"))
        .header("cksession", cksession("alice", "pw"))
        .json(&serde_json::json!({
            "operations": [
                { "operationType": "forceDelete", "record": { "recordName": "photos" } }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(h.svc.get_subvolume("photos").is_err());
}

#[tokio::test]
async fn asset_upload_and_download() {
    let h = spawn().await;
    let alice = h.svc.create_user("alice", "Alice", "pw").unwrap();
    h.svc
        .create_subvolume("photos", alice.id, 0, None)
        .await
        .unwrap();

    let resp = client()
        .post(url(h.addr, "assets/upload?subvolume=photos&key=a.bin"))
        .header("cksession", cksession("alice", "pw"))
        .body(Vec::from(&b"bytes"[..]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["size"], 5);

    let resp = client()
        .get(url(h.addr, "assets/photos/a.bin"))
        .header("cksession", cksession("alice", "pw"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"bytes");
}

#[tokio::test]
async fn records_query_lists_owned_subvolumes() {
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
        .post(url(h.addr, "records/query"))
        .header("cksession", cksession("alice", "pw"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let records = v["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
}
