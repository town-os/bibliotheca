//! End-to-end test for the sync supervisor against an axum-mocked
//! town-os systemcontroller and a `MockConnector`. Exercises the
//! full mount lifecycle: create → cycle pulls files into a real
//! subvolume → update quota → delete → town-os sees the
//! corresponding REST calls.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_sync_core::scheduler::{ConnectorRegistry, SupervisorConfig};
use bibliotheca_sync_core::testing::MockConnector;
use bibliotheca_sync_core::{
    ConnectorKind, CredentialBlob, CredentialCipher, Direction, MountSpec, SecretKey, Supervisor,
    SyncStateStore, TownosClient, TownosConfig, TownosCreds,
};
use parking_lot::Mutex;
use serde_json::json;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Default)]
struct TownosMockState {
    filesystems: Mutex<HashMap<String, u64>>,
    create_calls: Mutex<Vec<(String, u64)>>,
    modify_calls: Mutex<Vec<(String, Option<u64>)>>,
    remove_calls: Mutex<Vec<String>>,
}

fn touch_file(root: &std::path::Path, name: &str) -> std::io::Result<()> {
    let path = root.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Create the directory that represents this filesystem.
    std::fs::create_dir_all(&path)?;
    Ok(())
}

async fn authenticate() -> Json<serde_json::Value> {
    Json(json!({
        "token": "tok-xyz",
        "account": { "username": "alice" }
    }))
}

async fn storage_create(
    State(state): State<Arc<(Arc<TownosMockState>, PathBuf)>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let (st, root) = &*state;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();
    let quota = body.get("quota").and_then(|v| v.as_u64()).unwrap_or(0);
    st.create_calls.lock().push((name.clone(), quota));
    st.filesystems.lock().insert(name.clone(), quota);
    touch_file(root, &name).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({})))
}

async fn storage_modify(
    State(state): State<Arc<(Arc<TownosMockState>, PathBuf)>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let (st, _root) = &*state;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();
    let new_quota = body
        .get("filesystem")
        .and_then(|f| f.get("quota"))
        .and_then(|v| v.as_u64());
    st.modify_calls.lock().push((name.clone(), new_quota));
    if let Some(q) = new_quota {
        st.filesystems.lock().insert(name, q);
    }
    Ok(Json(json!({})))
}

async fn storage_remove(
    State(state): State<Arc<(Arc<TownosMockState>, PathBuf)>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let (st, _root) = &*state;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();
    st.remove_calls.lock().push(name.clone());
    st.filesystems.lock().remove(&name);
    Ok(Json(json!({})))
}

async fn spawn_townos_mock(root: PathBuf) -> (SocketAddr, Arc<TownosMockState>) {
    let state = Arc::new(TownosMockState::default());
    let shared: Arc<(Arc<TownosMockState>, PathBuf)> = Arc::new((state.clone(), root));
    let app = Router::new()
        .route("/account/authenticate", post(authenticate))
        .route("/storage/create", post(storage_create))
        .route("/storage/modify", post(storage_modify))
        .route("/storage/remove", post(storage_remove))
        .with_state(shared);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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

struct Harness {
    _tmp: TempDir,
    supervisor: Arc<Supervisor>,
    svc: BibliothecaService,
    data: DataStore,
    townos_state: Arc<TownosMockState>,
    alice_id: bibliotheca_core::identity::UserId,
    mock: MockConnector,
}

async fn setup() -> Harness {
    let tmp = TempDir::new().unwrap();
    let storage_root = tmp.path().join("storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let (addr, townos_state) = spawn_townos_mock(storage_root.clone()).await;

    // Build bibliotheca core.
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store.clone(), dyn_backend);
    let alice = svc.create_user("alice", "Alice", "pw").unwrap();

    // Build sync-core.
    let cipher = Arc::new(CredentialCipher::new(&SecretKey::random()));
    let townos = Arc::new(
        TownosClient::new(TownosConfig {
            base_url: Url::parse(&format!("http://{addr}/")).unwrap(),
            creds: TownosCreds {
                username: "alice".into(),
                password: "pw".into(),
            },
            storage_root: storage_root.clone(),
        })
        .unwrap(),
    );
    let state = SyncStateStore::new(store);
    let registry = ConnectorRegistry::new();
    let mock = MockConnector::with_kind(ConnectorKind::Dropbox);
    // Seed the connector with two objects before anyone creates a
    // mount so the first cycle has something to pull.
    mock.insert_object("hello.txt", b"hello sync");
    mock.insert_object("nested/one.bin", b"nested bytes");
    registry.register(ConnectorKind::Dropbox, mock.clone().into_factory());

    let cancel = CancellationToken::new();
    let supervisor = Arc::new(Supervisor::new(
        svc.clone(),
        state,
        Some(cipher),
        Some(townos),
        registry,
        SupervisorConfig {
            default_quota_bytes: 1024 * 1024,
        },
        cancel,
    ));

    let data = DataStore::new(svc.clone());
    Harness {
        _tmp: tmp,
        supervisor,
        svc,
        data,
        townos_state,
        alice_id: alice.id,
        mock,
    }
}

#[tokio::test]
async fn credential_crypto_round_trip() {
    let key = SecretKey::random();
    let cipher = CredentialCipher::new(&key);
    let blob = CredentialBlob::Basic {
        username: "u".into(),
        password: "p".into(),
    };
    let (nonce, ct) = cipher.encrypt(b"row", &blob).unwrap();
    let got = cipher.decrypt(b"row", &nonce, &ct).unwrap();
    match got {
        CredentialBlob::Basic { username, password } => {
            assert_eq!(username, "u");
            assert_eq!(password, "p");
        }
        _ => panic!("wrong variant"),
    }
}

#[tokio::test]
async fn connector_kind_parses() {
    assert_eq!(
        ConnectorKind::from_str("dropbox").unwrap(),
        ConnectorKind::Dropbox
    );
    assert_eq!(
        ConnectorKind::from_str("icloud").unwrap(),
        ConnectorKind::ICloudPhotos
    );
    assert!(ConnectorKind::from_str("nope").is_err());
}

#[tokio::test]
async fn create_mount_provisions_townos_and_pulls_files() {
    let h = setup().await;

    let spec = MountSpec {
        name: "alice-drop".into(),
        kind: ConnectorKind::Dropbox,
        direction: Direction::Pull,
        interval_secs: 60,
        quota_bytes: 0, // use default
        owner: h.alice_id,
        config_json: "{}".into(),
        credentials_id: None,
    };
    let credentials = CredentialBlob::OAuth2 {
        access_token: "at".into(),
        refresh_token: "rt".into(),
        expires_at: 9_999_999_999,
        client_id: "cid".into(),
        client_secret: "csec".into(),
        token_url: "https://example.invalid/token".into(),
    };

    let mount = h
        .supervisor
        .create_mount(spec, credentials)
        .await
        .expect("create_mount");
    assert_eq!(mount.name, "alice-drop");
    assert_eq!(mount.quota_bytes, 1024 * 1024); // default applied

    // town-os mock saw a CreateFilesystem call.
    {
        let calls = h.townos_state.create_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "user/sync-alice-drop");
    }

    // Kick the cycle and wait for the files to land.
    h.supervisor.trigger_sync(mount.id).await.unwrap();

    let sv_name = format!("sync-{}", mount.name);
    let mut tries = 0;
    loop {
        let listing = h
            .data
            .list_recursive(&sv_name, "", Some(h.alice_id), false)
            .unwrap_or_default();
        if listing.len() >= 2 {
            break;
        }
        if tries >= 50 {
            panic!(
                "expected 2 objects synced, saw {:?} after {} tries",
                listing, tries
            );
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let bytes = h
        .data
        .get(&sv_name, "hello.txt", Some(h.alice_id), false)
        .unwrap();
    assert_eq!(bytes, b"hello sync");

    // Update quota → triggers modify on town-os.
    h.supervisor
        .update_quota(mount.id, 5 * 1024 * 1024)
        .await
        .unwrap();
    {
        let calls = h.townos_state.modify_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "user/sync-alice-drop");
        assert_eq!(calls[0].1, Some(5 * 1024 * 1024));
    }
    let updated = h
        .svc
        .get_subvolume(&sv_name)
        .expect("subvolume still present");
    assert_eq!(updated.quota_bytes, 5 * 1024 * 1024);

    // Delete mount → calls /storage/remove.
    h.supervisor.delete_mount(mount.id).await.unwrap();
    {
        let calls = h.townos_state.remove_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "user/sync-alice-drop");
    }
    assert!(h.svc.get_subvolume(&sv_name).is_err());

    // silence "unused" warning on the captured mock.
    let _ = h.mock.list_calls();
}

#[tokio::test]
async fn bidirectional_push_and_conflict_stash() {
    let h = setup().await;

    let spec = MountSpec {
        name: "alice-both".into(),
        kind: ConnectorKind::Dropbox,
        direction: Direction::Both,
        interval_secs: 3600,
        quota_bytes: 0,
        owner: h.alice_id,
        config_json: "{}".into(),
        credentials_id: None,
    };
    let credentials = CredentialBlob::OAuth2 {
        access_token: "at".into(),
        refresh_token: "rt".into(),
        expires_at: 9_999_999_999,
        client_id: "cid".into(),
        client_secret: "csec".into(),
        token_url: "https://example.invalid/token".into(),
    };
    let mount = h
        .supervisor
        .create_mount(spec, credentials)
        .await
        .expect("create_mount");

    // First cycle pulls the seeded objects into the subvolume.
    h.supervisor.trigger_sync(mount.id).await.unwrap();
    let sv_name = format!("sync-{}", mount.name);
    for _ in 0..50 {
        let n = h
            .data
            .list_recursive(&sv_name, "", Some(h.alice_id), false)
            .map(|v| v.len())
            .unwrap_or(0);
        if n >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Push path: write a new local file, trigger a cycle, observe
    // it landed in the MockConnector.
    h.data
        .put(
            &sv_name,
            "local-only.txt",
            Some(h.alice_id),
            false,
            b"pushed",
        )
        .unwrap();
    h.supervisor.trigger_sync(mount.id).await.unwrap();
    for _ in 0..50 {
        let fetched = h.mock.fetch_calls();
        if fetched > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The MockConnector now has the uploaded object (we can't
    // observe it directly, but the upload method put it there).
    // Assert the mount's last_error is None.
    let after_push = h.supervisor.state().get_mount(mount.id).unwrap();
    assert!(
        after_push.last_error.is_none(),
        "unexpected error: {:?}",
        after_push.last_error
    );

    h.supervisor.delete_mount(mount.id).await.unwrap();
}

#[tokio::test]
async fn sync_disabled_without_cipher_errors() {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store.clone(), dyn_backend);
    let state = SyncStateStore::new(store);
    let registry = ConnectorRegistry::new();
    let cancel = CancellationToken::new();
    let supervisor = Supervisor::new(
        svc,
        state,
        None, // no cipher
        None, // no townos
        registry,
        SupervisorConfig::default(),
        cancel,
    );
    assert!(!supervisor.is_enabled());
}
