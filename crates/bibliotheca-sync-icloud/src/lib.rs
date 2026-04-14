//! iCloud Photos sync connector — a bibliotheca-native port of
//! the pyicloud Photos surface to pure Rust.
//!
//! This crate talks to Apple's real iCloud endpoints:
//!
//! - `idmsa.apple.com/appleauth/auth` for SRP-6a login
//! - `setup.icloud.com/setup/ws/1/accountLogin` for CloudKit
//!   session bootstrap
//! - `p*-ckdatabase.icloud.com` + `cvws.icloud-content.com` for
//!   the CloudKit Photos container operations and asset I/O
//!
//! Non-credential session state (cookies, trust token, CloudKit
//! endpoint map) lives inside the encrypted credential blob and is
//! re-encrypted on every mutation via
//! `SyncStateStore::update_credentials`. Phase 6's bidirectional
//! path carries that through unchanged.
//!
//! ## Scope
//!
//! - In scope: SRP-6a login, anisette-v3 integration, 2FA
//!   handshake (surfaced to operator via control plane), CloudKit
//!   accountLogin, Photos record-zone `CPLAsset` list/fetch,
//!   two-phase `records/modify` upload, delete.
//! - Out of scope: video, Live Photos, shared albums/libraries,
//!   family sharing, iCloud Drive/Calendar/Contacts/Mail,
//!   self-generating anisette (requires an external
//!   anisette-v3-server).
//!
//! ## Caveats
//!
//! Apple rewrites parts of this auth flow regularly. The auth
//! module is isolated under `auth/` so when Apple breaks it the
//! diff stays small. Live coverage is intentionally gated on
//! `BIBLIOTHECA_ICLOUD_LIVE=1`; CI runs a fixture-replay test
//! that exercises the HTTP surface against a recorded transcript.
//!
//! ## Per-mount config JSON
//!
//! ```json
//! {
//!   "auth_url":    "https://idmsa.apple.com",
//!   "setup_url":   "https://setup.icloud.com",
//!   "ckdb_url":    "https://p65-ckdatabase.icloud.com",
//!   "content_url": "https://cvws.icloud-content.com",
//!   "container":   "com.apple.photos.cloud",
//!   "zone":        "PrimarySync"
//! }
//! ```

#![allow(clippy::result_large_err)]

pub mod auth;
pub mod cloudkit;
pub mod photos;

use std::sync::Arc;

use async_trait::async_trait;
use bibliotheca_sync_core::credentials::CredentialBlob;
use bibliotheca_sync_core::error::{Error, Result};
use bibliotheca_sync_core::mount::ConnectorKind;
use bibliotheca_sync_core::scheduler::ConnectorRegistry;
use bibliotheca_sync_core::trait_::{
    ConnectorFactory, ListPage, RemoteObject, SyncConnector, UploadHints,
};
use bytes::Bytes;
use parking_lot::Mutex;
use serde::Deserialize;

pub use auth::{ICloudAuth, ICloudSession};
pub use cloudkit::CloudKitClient;

pub struct ICloudConnector {
    session: Mutex<Option<ICloudSession>>,
    config: ICloudConfig,
    creds: ICloudCreds,
}

#[derive(Clone, Debug)]
pub struct ICloudCreds {
    pub apple_id: String,
    pub password: String,
    pub trust_token: Option<String>,
    pub session_cookies: Vec<u8>,
    pub anisette_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ICloudConfig {
    #[serde(default = "default_auth_url")]
    pub auth_url: String,
    #[serde(default = "default_setup_url")]
    pub setup_url: String,
    #[serde(default = "default_ckdb_url")]
    pub ckdb_url: String,
    #[serde(default = "default_content_url")]
    pub content_url: String,
    #[serde(default = "default_container")]
    pub container: String,
    #[serde(default = "default_zone")]
    pub zone: String,
}

fn default_auth_url() -> String {
    "https://idmsa.apple.com".into()
}
fn default_setup_url() -> String {
    "https://setup.icloud.com".into()
}
fn default_ckdb_url() -> String {
    "https://p65-ckdatabase.icloud.com".into()
}
fn default_content_url() -> String {
    "https://cvws.icloud-content.com".into()
}
fn default_container() -> String {
    "com.apple.photos.cloud".into()
}
fn default_zone() -> String {
    "PrimarySync".into()
}

impl ICloudConnector {
    pub fn register(registry: &ConnectorRegistry) {
        registry.register(ConnectorKind::ICloudPhotos, Self::factory());
    }

    pub fn factory() -> ConnectorFactory {
        Arc::new(|blob, config_json| match blob {
            CredentialBlob::ICloud {
                apple_id,
                password,
                trust_token,
                session_cookies,
                anisette_url,
            } => {
                let config: ICloudConfig = if config_json.trim().is_empty() {
                    serde_json::from_str("{}").unwrap()
                } else {
                    serde_json::from_str(config_json).map_err(Error::from)?
                };
                let creds = ICloudCreds {
                    apple_id: apple_id.clone(),
                    password: password.clone(),
                    trust_token: trust_token.clone(),
                    session_cookies: session_cookies.clone(),
                    anisette_url: anisette_url.clone(),
                };
                let conn: Arc<dyn SyncConnector> = Arc::new(ICloudConnector {
                    session: Mutex::new(None),
                    config,
                    creds,
                });
                Ok(conn)
            }
            _ => Err(Error::InvalidArgument(
                "icloud connector requires ICloud credentials".into(),
            )),
        })
    }

    pub fn new(creds: ICloudCreds, config: ICloudConfig) -> Self {
        Self {
            session: Mutex::new(None),
            config,
            creds,
        }
    }

    async fn ensure_session(&self) -> Result<ICloudSession> {
        {
            let g = self.session.lock();
            if let Some(s) = g.as_ref() {
                return Ok(s.clone());
            }
        }
        let auth = ICloudAuth::new(self.config.clone(), self.creds.clone());
        let session = auth.login().await?;
        *self.session.lock() = Some(session.clone());
        Ok(session)
    }
}

#[async_trait]
impl SyncConnector for ICloudConnector {
    fn kind(&self) -> ConnectorKind {
        ConnectorKind::ICloudPhotos
    }

    async fn list_since(&self, cursor: Option<&[u8]>) -> Result<ListPage> {
        let session = self.ensure_session().await?;
        let client = CloudKitClient::new(self.config.clone(), session);
        photos::list::list_since(&client, cursor).await
    }

    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes> {
        let session = self.ensure_session().await?;
        let client = CloudKitClient::new(self.config.clone(), session);
        photos::fetch::fetch(&client, obj).await
    }

    async fn upload(&self, key: &str, bytes: &[u8], hints: UploadHints) -> Result<RemoteObject> {
        let session = self.ensure_session().await?;
        let client = CloudKitClient::new(self.config.clone(), session);
        photos::upload::upload(&client, key, bytes, hints).await
    }

    async fn delete(&self, obj: &RemoteObject) -> Result<()> {
        let session = self.ensure_session().await?;
        let client = CloudKitClient::new(self.config.clone(), session);
        photos::delete::delete(&client, obj).await
    }
}
