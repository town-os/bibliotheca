//! Google Photos Library API sync connector.
//!
//! Implements the subset of `photoslibrary.googleapis.com/v1` that
//! bibliotheca needs for a pull-only mirror of a user's Photos
//! library, plus the inverse for Phase 6 push support.
//!
//! The connector uses an OAuth2 refresh-token flow against
//! Google's standard `/token` endpoint (installed-app grant). The
//! `refresh_token` + `client_id` + `client_secret` triple lives in
//! an encrypted `CredentialBlob::OAuth2` row. Access tokens are
//! cached in memory and refreshed 30 s before expiry.
//!
//! Incremental pulls use `/v1/mediaItems:search` with a
//! pageToken-driven loop; the opaque cursor stored on the mount is
//! the newest `mediaItem.id` we've seen plus the pageToken for the
//! in-progress pagination (JSON-encoded).
//!
//! Config JSON (per-mount):
//!
//! ```json
//! {
//!   "base_url":   "https://photoslibrary.googleapis.com",
//!   "token_url":  "https://oauth2.googleapis.com/token"
//! }
//! ```

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
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;

const DEFAULT_BASE_URL: &str = "https://photoslibrary.googleapis.com";

pub struct GooglePhotosConnector {
    http: reqwest::Client,
    base_url: String,
    verb_sep: String,
    oauth: OAuthCreds,
    token: Arc<Mutex<TokenState>>,
}

#[derive(Clone)]
pub struct OAuthCreds {
    pub refresh_token: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
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
struct GphotosConfig {
    #[serde(default)]
    base_url: Option<String>,
    /// The separator used between `mediaItems` and the verb name
    /// (`search`, `batchCreate`). Google's real API uses `:`
    /// (e.g. `/v1/mediaItems:search`). Tests override to `/` so
    /// axum's matchit router (which treats mid-segment `:` as a
    /// param marker) can register both verbs without conflicting.
    #[serde(default)]
    verb_separator: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct Cursor {
    #[serde(default)]
    page_token: Option<String>,
}

impl GooglePhotosConnector {
    pub fn register(registry: &ConnectorRegistry) {
        registry.register(ConnectorKind::GooglePhotos, Self::factory());
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
                let cfg: GphotosConfig = serde_json::from_str(config_json).map_err(Error::from)?;
                let base_url = cfg.base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
                let verb_sep = cfg.verb_separator.unwrap_or_else(|| ":".to_string());
                let conn: Arc<dyn SyncConnector> = Arc::new(Self::new(
                    base_url,
                    verb_sep,
                    OAuthCreds {
                        refresh_token: refresh_token.clone(),
                        client_id: client_id.clone(),
                        client_secret: client_secret.clone(),
                        token_url: token_url.clone(),
                    },
                ));
                Ok(conn)
            }
            _ => Err(Error::InvalidArgument(
                "gphotos connector requires OAuth2 credentials".into(),
            )),
        })
    }

    pub fn new(base_url: String, verb_sep: String, oauth: OAuthCreds) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("gphotos reqwest client"),
            base_url,
            verb_sep,
            oauth,
            token: Arc::new(Mutex::new(TokenState::default())),
        }
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
            .map_err(|e| Error::Transient(format!("gphotos token: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Fatal(format!(
                "gphotos token refresh {}",
                resp.status()
            )));
        }
        let tok: TokenResponse = resp
            .json()
            .await
            .map_err(|e| Error::Transient(format!("gphotos token body: {e}")))?;
        let mut g = self.token.lock();
        g.access_token = tok.access_token.clone();
        g.expires_at = OffsetDateTime::now_utc().unix_timestamp()
            + if tok.expires_in > 0 {
                tok.expires_in
            } else {
                3600
            };
        Ok(tok.access_token)
    }
}

#[async_trait]
impl SyncConnector for GooglePhotosConnector {
    fn kind(&self) -> ConnectorKind {
        ConnectorKind::GooglePhotos
    }

    async fn list_since(&self, cursor: Option<&[u8]>) -> Result<ListPage> {
        let token = self.ensure_token().await?;
        let c: Cursor = match cursor {
            Some(bytes) => serde_json::from_slice(bytes).unwrap_or_default(),
            None => Cursor::default(),
        };
        let mut body = json!({ "pageSize": 100 });
        if let Some(tok) = &c.page_token {
            body["pageToken"] = json!(tok);
        }
        let resp = self
            .http
            .post(format!(
                "{}/v1/mediaItems{}search",
                self.base_url, self.verb_sep
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("gphotos search: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("gphotos search http {status}")));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Transient(format!("gphotos body: {e}")))?;
        let mut changes = Vec::new();
        if let Some(items) = v.get("mediaItems").and_then(|i| i.as_array()) {
            for item in items {
                let id = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let filename = item
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if id.is_empty() || filename.is_empty() {
                    continue;
                }
                let key = format!("{id}/{filename}");
                let base_url = item
                    .get("baseUrl")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let creation = item
                    .get("mediaMetadata")
                    .and_then(|m| m.get("creationTime"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| {
                        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                            .ok()
                    })
                    .unwrap_or_else(OffsetDateTime::now_utc);
                changes.push(Change::Upsert(RemoteObject {
                    id: format!("{id}::{base_url}"),
                    key,
                    size: 0,
                    etag: Some(id),
                    modified: creation,
                    is_dir: false,
                }));
            }
        }
        let next_page = v
            .get("nextPageToken")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
        let more = next_page.is_some();
        let next_cursor = if more {
            Some(
                serde_json::to_vec(&Cursor {
                    page_token: next_page,
                })
                .unwrap_or_default(),
            )
        } else {
            None
        };
        Ok(ListPage {
            changes,
            next_cursor,
            more,
        })
    }

    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes> {
        // RemoteObject.id encodes "media_item_id::baseUrl". The
        // `baseUrl` is the download endpoint; appending `=d` asks
        // Google for the full-resolution original.
        let base_url = obj
            .id
            .split_once("::")
            .map(|(_, b)| b.to_string())
            .unwrap_or_else(|| obj.id.clone());
        let url = format!("{base_url}=d");
        let token = self.ensure_token().await?;
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("gphotos download: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Transient(format!(
                "gphotos download http {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Transient(format!("gphotos download body: {e}")))?;
        Ok(bytes)
    }

    async fn upload(&self, key: &str, bytes: &[u8], hints: UploadHints) -> Result<RemoteObject> {
        let token = self.ensure_token().await?;
        let filename = key.rsplit('/').next().unwrap_or(key).to_string();
        let ct = hints
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());

        // Step 1: POST /v1/uploads → upload token (plain text body).
        let resp = self
            .http
            .post(format!("{}/v1/uploads", self.base_url))
            .bearer_auth(&token)
            .header("Content-Type", ct)
            .header("X-Goog-Upload-Protocol", "raw")
            .header("X-Goog-Upload-File-Name", &filename)
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| Error::Transient(format!("gphotos upload: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Transient(format!(
                "gphotos upload http {}",
                resp.status()
            )));
        }
        let upload_token = resp
            .text()
            .await
            .map_err(|e| Error::Transient(format!("gphotos upload body: {e}")))?;

        // Step 2: batchCreate to finalize.
        let body = json!({
            "newMediaItems": [
                {
                    "simpleMediaItem": {
                        "uploadToken": upload_token,
                        "fileName": filename
                    }
                }
            ]
        });
        let resp = self
            .http
            .post(format!(
                "{}/v1/mediaItems{}batchCreate",
                self.base_url, self.verb_sep
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("gphotos batchCreate: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Transient(format!(
                "gphotos batchCreate http {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Transient(format!("gphotos batchCreate body: {e}")))?;
        let item = v
            .get("newMediaItemResults")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|r| r.get("mediaItem"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let id = item
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let base_url = item
            .get("baseUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(RemoteObject {
            id: format!("{id}::{base_url}"),
            key: key.to_string(),
            size: bytes.len() as u64,
            etag: Some(id),
            modified: OffsetDateTime::now_utc(),
            is_dir: false,
        })
    }

    async fn delete(&self, _obj: &RemoteObject) -> Result<()> {
        // Google Photos Library API does not expose a direct delete
        // endpoint. Removing an item from an album is the closest
        // affordance; actual deletion must happen in the Google
        // Photos UI by the owner. Treat delete as a no-op so Phase 6
        // bidirectional sync doesn't deadlock trying to propagate
        // local deletes.
        Ok(())
    }
}
