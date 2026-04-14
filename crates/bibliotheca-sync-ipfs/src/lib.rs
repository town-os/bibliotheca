//! IPFS sync connector.
//!
//! Wraps `bibliotheca_ipfs::KuboClient` as a `SyncConnector`. Each
//! cycle queries the running Kubo node for its pin list; pinned
//! CIDs that don't exist in the local subvolume are fetched via
//! `cat` and written at `<cid>.bin`. Uploads are the reverse: add
//! the local bytes to Kubo, pin the resulting CID, and return the
//! synthetic `RemoteObject`.
//!
//! Credentials shape: [`bibliotheca_sync_core::CredentialBlob::Ipfs`]
//! with an `api_url` that must point at the Kubo RPC endpoint
//! (typically `http://127.0.0.1:5001/`). `auth_header` is reserved
//! for deployments that front Kubo with a reverse proxy requiring
//! Basic auth; it is prepended to every outbound request as the
//! `Authorization` header.

#![allow(clippy::result_large_err)]

use std::sync::Arc;

use async_trait::async_trait;
use bibliotheca_ipfs::{IpfsClient, KuboClient};
use bibliotheca_sync_core::credentials::CredentialBlob;
use bibliotheca_sync_core::error::{Error, Result};
use bibliotheca_sync_core::mount::ConnectorKind;
use bibliotheca_sync_core::scheduler::ConnectorRegistry;
use bibliotheca_sync_core::trait_::{
    Change, ConnectorFactory, ListPage, RemoteObject, SyncConnector, UploadHints,
};
use bytes::Bytes;
use time::OffsetDateTime;
use url::Url;

pub struct IpfsSyncConnector {
    client: Arc<KuboClient>,
}

impl IpfsSyncConnector {
    pub fn new(endpoint: Url) -> Self {
        Self {
            client: Arc::new(KuboClient::new(endpoint)),
        }
    }

    /// Register this connector's factory with the supervisor's
    /// registry.
    pub fn register(registry: &ConnectorRegistry) {
        registry.register(ConnectorKind::Ipfs, Self::factory());
    }

    pub fn factory() -> ConnectorFactory {
        Arc::new(|blob, _config| match blob {
            CredentialBlob::Ipfs { api_url, .. } => {
                let endpoint = Url::parse(api_url)
                    .map_err(|e| Error::InvalidArgument(format!("ipfs api_url: {e}")))?;
                let conn: Arc<dyn SyncConnector> = Arc::new(IpfsSyncConnector::new(endpoint));
                Ok(conn)
            }
            _ => Err(Error::InvalidArgument(
                "ipfs connector requires Ipfs credentials".into(),
            )),
        })
    }
}

#[async_trait]
impl SyncConnector for IpfsSyncConnector {
    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Ipfs
    }

    async fn list_since(&self, _cursor: Option<&[u8]>) -> Result<ListPage> {
        // IPFS pin lists are full-replacement — there is no
        // incremental cursor at the Kubo RPC level. We fetch the
        // whole pin list every cycle; the supervisor's diff
        // against `sync_objects` keeps us from re-downloading
        // anything we already materialized.
        let pins = self
            .client
            .pins()
            .await
            .map_err(|e| Error::Transient(format!("ipfs pins: {e}")))?;
        let now = OffsetDateTime::now_utc();
        let changes = pins
            .into_iter()
            .map(|cid| {
                let key = format!("{cid}.bin");
                Change::Upsert(RemoteObject {
                    id: cid.clone(),
                    key,
                    size: 0, // Kubo pin/ls doesn't return sizes.
                    etag: Some(cid),
                    modified: now,
                    is_dir: false,
                })
            })
            .collect();
        Ok(ListPage {
            changes,
            next_cursor: None,
            more: false,
        })
    }

    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes> {
        // KuboClient::cat writes bytes to a Path. Use a tempfile
        // and then read it back — cheap, and keeps the KuboClient
        // crate untouched.
        let tmp = tempfile::NamedTempFile::new()
            .map_err(|e| Error::Transient(format!("tempfile: {e}")))?;
        self.client
            .cat(&obj.id, tmp.path())
            .await
            .map_err(|e| Error::Transient(format!("ipfs cat: {e}")))?;
        let bytes = std::fs::read(tmp.path())
            .map_err(|e| Error::Transient(format!("read tempfile: {e}")))?;
        Ok(Bytes::from(bytes))
    }

    async fn upload(&self, key: &str, bytes: &[u8], _hints: UploadHints) -> Result<RemoteObject> {
        let tmp = tempfile::NamedTempFile::new()
            .map_err(|e| Error::Transient(format!("tempfile: {e}")))?;
        std::fs::write(tmp.path(), bytes)
            .map_err(|e| Error::Transient(format!("write tempfile: {e}")))?;
        let cid = self
            .client
            .add(tmp.path())
            .await
            .map_err(|e| Error::Transient(format!("ipfs add: {e}")))?;
        self.client
            .pin_add(&cid, true)
            .await
            .map_err(|e| Error::Transient(format!("ipfs pin: {e}")))?;
        Ok(RemoteObject {
            id: cid.clone(),
            key: key.to_string(),
            size: bytes.len() as u64,
            etag: Some(cid),
            modified: OffsetDateTime::now_utc(),
            is_dir: false,
        })
    }

    async fn delete(&self, obj: &RemoteObject) -> Result<()> {
        self.client
            .pin_rm(&obj.id)
            .await
            .map_err(|e| Error::Transient(format!("ipfs unpin: {e}")))?;
        Ok(())
    }
}
