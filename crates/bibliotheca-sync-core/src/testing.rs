//! In-memory `MockConnector` for scheduler tests.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use time::OffsetDateTime;

use crate::credentials::CredentialBlob;
use crate::error::{Error, Result};
use crate::mount::ConnectorKind;
use crate::trait_::{Change, ConnectorFactory, ListPage, RemoteObject, SyncConnector, UploadHints};

#[derive(Default, Clone)]
pub struct MockConnector {
    inner: Arc<Mutex<MockState>>,
    kind: ConnectorKindMarker,
}

#[derive(Clone)]
struct ConnectorKindMarker(ConnectorKind);

impl Default for ConnectorKindMarker {
    fn default() -> Self {
        Self(ConnectorKind::Dropbox)
    }
}

#[derive(Default)]
struct MockState {
    objects: BTreeMap<String, (RemoteObject, Vec<u8>)>,
    pending_deletes: Vec<(String, String)>,
    list_calls: usize,
    fetch_calls: usize,
    force_transient_error: bool,
}

impl MockConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_kind(kind: ConnectorKind) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockState::default())),
            kind: ConnectorKindMarker(kind),
        }
    }

    pub fn insert_object(&self, key: &str, bytes: &[u8]) {
        let mut g = self.inner.lock();
        let now = OffsetDateTime::now_utc();
        let obj = RemoteObject {
            id: format!("id-{key}"),
            key: key.to_string(),
            size: bytes.len() as u64,
            etag: Some(format!("etag-{}", bytes.len())),
            modified: now,
            is_dir: false,
        };
        g.objects.insert(key.to_string(), (obj, bytes.to_vec()));
    }

    pub fn remove_object(&self, key: &str) {
        let mut g = self.inner.lock();
        if let Some((obj, _)) = g.objects.remove(key) {
            g.pending_deletes.push((obj.id, obj.key));
        }
    }

    pub fn force_transient_error(&self, value: bool) {
        self.inner.lock().force_transient_error = value;
    }

    pub fn list_calls(&self) -> usize {
        self.inner.lock().list_calls
    }

    pub fn fetch_calls(&self) -> usize {
        self.inner.lock().fetch_calls
    }

    /// A connector factory that always returns this same mock
    /// instance, wrapped as the trait object the supervisor
    /// expects. Use it when you want a single shared state across
    /// create_mount/spawn_worker.
    pub fn into_factory(self) -> ConnectorFactory {
        let shared = Arc::new(self);
        Arc::new(move |_creds: &CredentialBlob, _config: &str| {
            let c: Arc<dyn SyncConnector> = shared.clone();
            Ok(c)
        })
    }
}

#[async_trait]
impl SyncConnector for MockConnector {
    fn kind(&self) -> ConnectorKind {
        self.kind.0
    }

    async fn list_since(&self, _cursor: Option<&[u8]>) -> Result<ListPage> {
        let mut g = self.inner.lock();
        g.list_calls += 1;
        if g.force_transient_error {
            return Err(Error::Transient("mock transient".into()));
        }
        let mut changes: Vec<Change> = g
            .objects
            .values()
            .map(|(obj, _)| Change::Upsert(obj.clone()))
            .collect();
        for (id, key) in g.pending_deletes.drain(..) {
            changes.push(Change::Delete { id, key });
        }
        Ok(ListPage {
            changes,
            next_cursor: None,
            more: false,
        })
    }

    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes> {
        let mut g = self.inner.lock();
        g.fetch_calls += 1;
        let (_, bytes) = g
            .objects
            .get(&obj.key)
            .ok_or_else(|| Error::NotFound(format!("mock object: {}", obj.key)))?;
        Ok(Bytes::from(bytes.clone()))
    }

    async fn upload(&self, key: &str, bytes: &[u8], _hints: UploadHints) -> Result<RemoteObject> {
        let mut g = self.inner.lock();
        let now = OffsetDateTime::now_utc();
        let obj = RemoteObject {
            id: format!("id-{key}"),
            key: key.to_string(),
            size: bytes.len() as u64,
            etag: Some(format!("etag-{}", bytes.len())),
            modified: now,
            is_dir: false,
        };
        g.objects
            .insert(key.to_string(), (obj.clone(), bytes.to_vec()));
        Ok(obj)
    }

    async fn delete(&self, obj: &RemoteObject) -> Result<()> {
        let mut g = self.inner.lock();
        g.objects.remove(&obj.key);
        g.pending_deletes.push((obj.id.clone(), obj.key.clone()));
        Ok(())
    }
}
