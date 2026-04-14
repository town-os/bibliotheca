//! Dropbox v2 REST sync connector.
//!
//! Speaks the canonical Dropbox API shapes that third-party apps
//! use: OAuth2 refresh-token flow against `/oauth2/token`, and
//! `/2/files/{list_folder,list_folder/continue,download,upload,delete_v2}`
//! for the data plane. Incremental pulls reuse Dropbox's native
//! cursor from `list_folder/continue`, stored opaquely on the
//! mount's `cursor_blob`.
//!
//! Config JSON (per-mount, not secret):
//!
//! ```json
//! {
//!   "base_url": "https://api.dropboxapi.com",     // RPC endpoint
//!   "content_url": "https://content.dropboxapi.com" // upload/download
//! }
//! ```
//!
//! Credentials must be [`CredentialBlob::OAuth2`]; the refresh
//! token + client id/secret triple lives encrypted in the sync
//! credential store. The access token is cached in memory for the
//! lifetime of the connector and refreshed 30 s before expiry.

#![allow(clippy::result_large_err)]

use std::sync::Arc;

use async_trait::async_trait;
use bibliotheca_sync_core::credentials::CredentialBlob;
use bibliotheca_sync_core::error::{Error, Result};
use bibliotheca_sync_core::mount::ConnectorKind;
use bibliotheca_sync_core::scheduler::ConnectorRegistry;
use bibliotheca_sync_core::trait_::{
    Change, ConnectorFactory, ListPage, RemoteObject, SyncConnector, UploadHints,
};
use bytes::Bytes;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;

const DEFAULT_BASE_URL: &str = "https://api.dropboxapi.com";
const DEFAULT_CONTENT_URL: &str = "https://content.dropboxapi.com";

pub struct DropboxConnector {
    http: reqwest::Client,
    base_url: String,
    content_url: String,
    oauth: OAuthCreds,
    token: Arc<Mutex<TokenState>>,
}

#[derive(Clone)]
struct OAuthCreds {
    refresh_token: String,
    client_id: String,
    client_secret: String,
    token_url: String,
}

#[derive(Default)]
struct TokenState {
    access_token: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
}

#[derive(Debug, Deserialize, Default)]
struct DropboxConfig {
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    content_url: Option<String>,
}

impl DropboxConnector {
    pub fn new(base_url: String, content_url: String, oauth: OAuthCredsInput) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("dropbox reqwest client");
        Self {
            http,
            base_url,
            content_url,
            oauth: OAuthCreds {
                refresh_token: oauth.refresh_token,
                client_id: oauth.client_id,
                client_secret: oauth.client_secret,
                token_url: oauth.token_url,
            },
            token: Arc::new(Mutex::new(TokenState::default())),
        }
    }

    pub fn register(registry: &ConnectorRegistry) {
        registry.register(ConnectorKind::Dropbox, Self::factory());
    }

    pub fn factory() -> ConnectorFactory {
        Arc::new(|blob, config_json| match blob {
            CredentialBlob::OAuth2 {
                refresh_token,
                client_id,
                client_secret,
                token_url,
                ..
            } => {
                let cfg: DropboxConfig = serde_json::from_str(config_json).map_err(Error::from)?;
                let base_url = cfg.base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
                let content_url = cfg
                    .content_url
                    .unwrap_or_else(|| DEFAULT_CONTENT_URL.to_string());
                let conn: Arc<dyn SyncConnector> = Arc::new(DropboxConnector::new(
                    base_url,
                    content_url,
                    OAuthCredsInput {
                        refresh_token: refresh_token.clone(),
                        client_id: client_id.clone(),
                        client_secret: client_secret.clone(),
                        token_url: token_url.clone(),
                    },
                ));
                Ok(conn)
            }
            _ => Err(Error::InvalidArgument(
                "dropbox connector requires OAuth2 credentials".into(),
            )),
        })
    }

    async fn ensure_token(&self) -> Result<String> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        {
            let g = self.token.lock();
            if !g.access_token.is_empty() && g.expires_at > now + 30 {
                return Ok(g.access_token.clone());
            }
        }
        let resp = self
            .http
            .post(&self.oauth.token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", self.oauth.refresh_token.as_str()),
                ("client_id", self.oauth.client_id.as_str()),
                ("client_secret", self.oauth.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| Error::Transient(format!("dropbox token post: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Fatal(format!(
                "dropbox token refresh failed: {status}: {body}"
            )));
        }
        let tok: TokenResponse = resp
            .json()
            .await
            .map_err(|e| Error::Transient(format!("dropbox token body: {e}")))?;
        let expires_at = OffsetDateTime::now_utc().unix_timestamp()
            + if tok.expires_in > 0 {
                tok.expires_in
            } else {
                14_400
            };
        let mut g = self.token.lock();
        g.access_token = tok.access_token.clone();
        g.expires_at = expires_at;
        Ok(tok.access_token)
    }
}

pub struct OAuthCredsInput {
    pub refresh_token: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
}

fn key_from_path(path_display: &str) -> String {
    path_display.trim_start_matches('/').to_string()
}

fn dropbox_path(key: &str) -> String {
    let trimmed = key.trim_start_matches('/');
    format!("/{trimmed}")
}

#[async_trait]
impl SyncConnector for DropboxConnector {
    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Dropbox
    }

    async fn list_since(&self, cursor: Option<&[u8]>) -> Result<ListPage> {
        let token = self.ensure_token().await?;
        let (path, body) = match cursor {
            Some(c) => {
                let cursor = String::from_utf8(c.to_vec())
                    .map_err(|e| Error::Fatal(format!("cursor utf8: {e}")))?;
                (
                    format!("{}/2/files/list_folder/continue", self.base_url),
                    json!({ "cursor": cursor }),
                )
            }
            None => (
                format!("{}/2/files/list_folder", self.base_url),
                json!({
                    "path": "",
                    "recursive": true,
                    "include_deleted": true
                }),
            ),
        };
        let resp = self
            .http
            .post(&path)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("list_folder: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("list_folder http {status}")));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Transient(format!("list_folder body: {e}")))?;
        let mut changes = Vec::new();
        if let Some(entries) = v.get("entries").and_then(|e| e.as_array()) {
            for e in entries {
                let tag = e.get(".tag").and_then(|v| v.as_str()).unwrap_or("");
                let id = e
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let path_display = e
                    .get("path_display")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                match tag {
                    "file" => {
                        let key = key_from_path(&path_display);
                        let size = e.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                        let etag = e
                            .get("content_hash")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let modified = e
                            .get("server_modified")
                            .and_then(|v| v.as_str())
                            .and_then(|s| {
                                OffsetDateTime::parse(
                                    s,
                                    &time::format_description::well_known::Rfc3339,
                                )
                                .ok()
                            })
                            .unwrap_or_else(OffsetDateTime::now_utc);
                        changes.push(Change::Upsert(RemoteObject {
                            id,
                            key,
                            size,
                            etag,
                            modified,
                            is_dir: false,
                        }));
                    }
                    "deleted" => {
                        let key = key_from_path(&path_display);
                        changes.push(Change::Delete { id, key });
                    }
                    _ => {}
                }
            }
        }
        let next_cursor = v
            .get("cursor")
            .and_then(|c| c.as_str())
            .map(|s| s.as_bytes().to_vec());
        let more = v.get("has_more").and_then(|m| m.as_bool()).unwrap_or(false);
        Ok(ListPage {
            changes,
            next_cursor,
            more,
        })
    }

    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes> {
        let token = self.ensure_token().await?;
        let arg = json!({ "path": dropbox_path(&obj.key) });
        let resp = self
            .http
            .post(format!("{}/2/files/download", self.content_url))
            .bearer_auth(&token)
            .header("Dropbox-API-Arg", arg.to_string())
            .send()
            .await
            .map_err(|e| Error::Transient(format!("download: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("download http {status}")));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Transient(format!("download body: {e}")))?;
        Ok(bytes)
    }

    async fn upload(&self, key: &str, bytes: &[u8], _hints: UploadHints) -> Result<RemoteObject> {
        let token = self.ensure_token().await?;
        let arg = json!({
            "path": dropbox_path(key),
            "mode": "overwrite",
            "autorename": false,
            "mute": true
        });
        let resp = self
            .http
            .post(format!("{}/2/files/upload", self.content_url))
            .bearer_auth(&token)
            .header("Dropbox-API-Arg", arg.to_string())
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| Error::Transient(format!("upload: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("upload http {status}")));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Transient(format!("upload body: {e}")))?;
        Ok(RemoteObject {
            id: v
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            key: key.to_string(),
            size: bytes.len() as u64,
            etag: v
                .get("content_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            modified: OffsetDateTime::now_utc(),
            is_dir: false,
        })
    }

    async fn delete(&self, obj: &RemoteObject) -> Result<()> {
        let token = self.ensure_token().await?;
        let body = json!({ "path": dropbox_path(&obj.key) });
        let resp = self
            .http
            .post(format!("{}/2/files/delete_v2", self.base_url))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("delete: {e}")))?;
        let status = resp.status();
        // Dropbox returns 409 for "path/not_found", which we treat
        // as a successful idempotent delete.
        if !status.is_success() && status.as_u16() != 409 {
            return Err(Error::Transient(format!("delete http {status}")));
        }
        Ok(())
    }
}
