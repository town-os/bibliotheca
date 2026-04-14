//! town-os systemcontroller storage client.

pub mod auth;
pub mod storage;

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};

/// Credentials used to authenticate to town-os.
#[derive(Debug, Clone)]
pub struct TownosCreds {
    pub username: String,
    pub password: String,
}

/// Configuration for the sync subsystem's town-os client.
#[derive(Debug, Clone)]
pub struct TownosConfig {
    pub base_url: Url,
    pub creds: TownosCreds,
    /// Absolute filesystem root that town-os mounts user volumes
    /// underneath. A procured volume named `user/sync-alice-icloud`
    /// becomes `{storage_root}/user/sync-alice-icloud`.
    pub storage_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filesystem {
    pub name: String,
    pub quota: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Default)]
struct AuthState {
    token: Option<String>,
}

#[derive(Clone)]
pub struct TownosClient {
    base_url: Url,
    http: Client,
    creds: TownosCreds,
    storage_root: PathBuf,
    auth: Arc<Mutex<AuthState>>,
}

impl TownosClient {
    pub fn new(cfg: TownosConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::from)?;
        Ok(Self {
            base_url: cfg.base_url,
            http,
            creds: cfg.creds,
            storage_root: cfg.storage_root,
            auth: Arc::new(Mutex::new(AuthState::default())),
        })
    }

    pub fn storage_root(&self) -> &std::path::Path {
        &self.storage_root
    }

    /// Absolute mount path for a townos-procured filesystem name.
    pub fn mount_path_for(&self, name: &str) -> PathBuf {
        self.storage_root.join(name.trim_start_matches('/'))
    }

    /// Authenticate and return the resulting JWT. Cached in memory.
    pub async fn authenticate(&self) -> Result<String> {
        if let Some(tok) = self.auth.lock().token.clone() {
            return Ok(tok);
        }
        let token = auth::login(&self.http, &self.base_url, &self.creds).await?;
        self.auth.lock().token = Some(token.clone());
        Ok(token)
    }

    /// Clear the cached token (used when a request returned 401).
    pub fn invalidate_token(&self) {
        self.auth.lock().token = None;
    }

    pub async fn create_filesystem(&self, name: &str, quota: u64) -> Result<String> {
        storage::create(self, name, quota).await
    }

    pub async fn modify_filesystem(
        &self,
        current_name: &str,
        new_name: Option<&str>,
        new_quota: Option<u64>,
    ) -> Result<()> {
        storage::modify(self, current_name, new_name, new_quota).await
    }

    pub async fn remove_filesystem(&self, name: &str) -> Result<()> {
        storage::remove(self, name).await
    }

    pub async fn list_filesystems(&self, prefix: &str) -> Result<Vec<Filesystem>> {
        storage::list(self, prefix).await
    }

    pub(crate) fn http(&self) -> &Client {
        &self.http
    }

    pub(crate) fn base_url(&self) -> &Url {
        &self.base_url
    }
}
