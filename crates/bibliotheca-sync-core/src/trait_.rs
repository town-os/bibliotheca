//! Connector trait + the message types that flow in and out of it.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;

use crate::credentials::CredentialBlob;
use crate::error::Result;
use crate::mount::ConnectorKind;

/// Opaque remote-object description returned by a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteObject {
    /// Connector-opaque stable ID (CloudKit record id, Dropbox id, CID, …).
    pub id: String,
    /// Path-like key, forward-slash separated, relative to the
    /// subvolume root. Must NOT contain `..` or leading `/`.
    pub key: String,
    pub size: u64,
    /// Strong content identity if the provider gives us one.
    pub etag: Option<String>,
    pub modified: OffsetDateTime,
    /// Directories show up only for connectors that want them; most
    /// flat backends leave this false.
    pub is_dir: bool,
}

/// A change observed during `list_since`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Change {
    Upsert(RemoteObject),
    Delete { id: String, key: String },
}

/// A single page of changes + the next opaque cursor.
#[derive(Debug, Clone)]
pub struct ListPage {
    pub changes: Vec<Change>,
    pub next_cursor: Option<Vec<u8>>,
    /// If true, the caller should immediately poll again rather than
    /// sleeping the configured interval — there are more results.
    pub more: bool,
}

/// Extra hints passed to upload handlers.
#[derive(Debug, Clone, Default)]
pub struct UploadHints {
    pub content_type: Option<String>,
    pub mtime: Option<OffsetDateTime>,
}

/// The wire-facing surface every sync connector implements.
#[async_trait]
pub trait SyncConnector: Send + Sync + 'static {
    fn kind(&self) -> ConnectorKind;

    /// List changes since `cursor` (or from the beginning if None).
    async fn list_since(&self, cursor: Option<&[u8]>) -> Result<ListPage>;

    /// Fetch the bytes of one remote object.
    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes>;

    /// Upload (create or replace) local bytes at `key`. Returns the
    /// remote object record that was created, including any
    /// provider-assigned id/etag.
    async fn upload(&self, key: &str, bytes: &[u8], hints: UploadHints) -> Result<RemoteObject>;

    /// Delete a remote object.
    async fn delete(&self, obj: &RemoteObject) -> Result<()>;
}

/// Factory used by the supervisor to construct a connector from a
/// credential blob and mount config. Each connector crate registers
/// one of these at daemon startup.
pub type ConnectorFactory = Arc<
    dyn Fn(
            &CredentialBlob,
            &str, // config_json
        ) -> Result<Arc<dyn SyncConnector>>
        + Send
        + Sync,
>;
