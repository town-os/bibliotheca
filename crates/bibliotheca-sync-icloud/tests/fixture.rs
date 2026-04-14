//! Fixture-driven integration test for the iCloud Photos
//! connector.
//!
//! We do not talk to real Apple endpoints (the flow changes too
//! often for live CI to be useful). Instead we stand up an axum
//! mock that replays canned responses for the two endpoints the
//! list/fetch path actually hits on a pre-authenticated session:
//!
//!   * `/database/1/com.apple.photos.cloud/production/private/records/query`
//!   * a content download URL for each asset
//!
//! The test constructs an `ICloudConnector` directly with an
//! already-authenticated `ICloudSession` (there's no need to
//! exercise SRP in a fixture replay; the auth path is covered by
//! its own unit tests and the live-test that `BIBLIOTHECA_ICLOUD_LIVE=1`
//! gates).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes as AxumBytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use bibliotheca_sync_core::trait_::{Change, RemoteObject};
use bibliotheca_sync_icloud::auth::ICloudSession;
use bibliotheca_sync_icloud::cloudkit::CloudKitClient;
use bibliotheca_sync_icloud::{ICloudConfig, ICloudConnector, ICloudCreds};
use parking_lot::Mutex;
use serde_json::json;

#[derive(Default)]
struct MockState {
    query_calls: Mutex<u32>,
    blobs: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    base: Mutex<String>,
}

async fn records_query(
    State(state): State<Arc<MockState>>,
    Json(_body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    *state.query_calls.lock() += 1;
    Json(json!({
        "records": [
            {
                "recordName": "rec-1",
                "fields": {
                    "filenameEnc": { "value": "IMG_0001.jpg" },
                    "assetDate":   { "value": 1_729_000_000_000i64 },
                    "resJPEGFullRes": {
                        "value": {
                            "downloadURL": "http://127.0.0.1/content/rec-1",
                            "size": 5
                        }
                    }
                }
            }
        ],
        "syncToken": "tok-next",
        "moreComing": false
    }))
}

async fn records_modify(
    State(state): State<Arc<MockState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let op = body["operations"][0]["operationType"]
        .as_str()
        .unwrap_or("");
    if op == "create" {
        let base = state.base.lock().clone();
        Json(json!({
            "records": [
                {
                    "recordName": "new-record",
                    "pendingAssets": [
                        { "uploadURL": format!("{base}/upload/new-record") }
                    ]
                }
            ]
        }))
    } else {
        Json(json!({ "records": [{ "recordName": "new-record" }] }))
    }
}

async fn content_download(
    State(state): State<Arc<MockState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.blobs.lock().get(&id).cloned() {
        Some(b) => (StatusCode::OK, b).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upload_put(
    State(state): State<Arc<MockState>>,
    Path(id): Path<String>,
    body: AxumBytes,
) -> Json<serde_json::Value> {
    state.blobs.lock().insert(id, body.to_vec());
    Json(json!({
        "fileChecksum": "fake",
        "size": body.len()
    }))
}

async fn spawn_mock() -> (SocketAddr, Arc<MockState>) {
    let state = Arc::new(MockState::default());
    state
        .blobs
        .lock()
        .insert("rec-1".to_string(), b"pxls!".to_vec());

    let app = Router::new()
        .route(
            "/database/1/com.apple.photos.cloud/production/private/records/query",
            post(records_query),
        )
        .route(
            "/database/1/com.apple.photos.cloud/production/private/records/modify",
            post(records_modify),
        )
        .route("/content/:id", get(content_download))
        .route("/upload/:id", axum::routing::put(upload_put))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    *state.base.lock() = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, state)
}

fn cloudkit_client(addr: SocketAddr) -> CloudKitClient {
    let config = ICloudConfig {
        auth_url: format!("http://{addr}"),
        setup_url: format!("http://{addr}"),
        ckdb_url: format!("http://{addr}"),
        content_url: format!("http://{addr}"),
        container: "com.apple.photos.cloud".into(),
        zone: "PrimarySync".into(),
    };
    let session = ICloudSession {
        dsid: "dsid-1".into(),
        ck_database_url: format!("http://{addr}"),
        cookies: Vec::new(),
        auth_token: "auth-tok".into(),
    };
    CloudKitClient::new(config, session)
}

#[tokio::test]
async fn factory_rejects_non_icloud_credentials() {
    use bibliotheca_sync_core::credentials::CredentialBlob;
    let factory = ICloudConnector::factory();
    let wrong = CredentialBlob::Basic {
        username: "u".into(),
        password: "p".into(),
    };
    assert!(factory(&wrong, "{}").is_err());
}

#[tokio::test]
async fn fixture_list_then_fetch() {
    let (addr, state) = spawn_mock().await;
    let client = cloudkit_client(addr);
    let page = bibliotheca_sync_icloud::photos::list::list_since(&client, None)
        .await
        .unwrap();
    assert_eq!(*state.query_calls.lock(), 1);
    assert_eq!(page.changes.len(), 1);
    let Change::Upsert(obj) = &page.changes[0] else {
        panic!("expected upsert");
    };
    assert!(obj.key.contains("IMG_0001.jpg"));

    // Rewrite the RemoteObject id so the content download URL
    // hits our mock (the fixture emitted `http://127.0.0.1/...`
    // but the test listener is on an ephemeral port).
    let rewritten = RemoteObject {
        id: format!("rec-1::http://{addr}/content/rec-1"),
        ..obj.clone()
    };
    let bytes = bibliotheca_sync_icloud::photos::fetch::fetch(&client, &rewritten)
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), b"pxls!");
}

#[tokio::test]
async fn fixture_upload_two_phase() {
    let (addr, _state) = spawn_mock().await;
    let client = cloudkit_client(addr);
    let obj = bibliotheca_sync_icloud::photos::upload::upload(
        &client,
        "2026/04/01.jpg",
        b"photo",
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(obj.size, 5);
    assert_eq!(obj.key, "2026/04/01.jpg");
}

#[tokio::test]
async fn construct_connector_with_credentials() {
    // Smoke-test the factory path: we can build a connector
    // given a well-formed ICloud credential blob. The full auth
    // flow requires real Apple endpoints and is behind
    // `BIBLIOTHECA_ICLOUD_LIVE=1`.
    use bibliotheca_sync_core::credentials::CredentialBlob;
    let factory = ICloudConnector::factory();
    let blob = CredentialBlob::ICloud {
        apple_id: "alice@example.com".into(),
        password: "pw".into(),
        trust_token: None,
        session_cookies: Vec::new(),
        anisette_url: "http://127.0.0.1:6969".into(),
    };
    let conn = factory(&blob, "{}").unwrap();
    assert_eq!(
        conn.kind(),
        bibliotheca_sync_core::mount::ConnectorKind::ICloudPhotos
    );
    // Keep the config/creds types imported via the crate's public
    // re-exports so the test owns the same types the production
    // daemon reaches for.
    let _: Option<ICloudConfig> = None;
    let _: Option<ICloudCreds> = None;
}
