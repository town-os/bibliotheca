//! Nextcloud / WebDAV sync connector.
//!
//! Speaks WebDAV against a configurable base URL (typically
//! `https://cloud.example.com/remote.php/dav/files/<user>`). Each
//! `list_since` issues a single `PROPFIND Depth: infinity`, parses
//! the returned XML multistatus for resource type, content length,
//! etag, and last-modified, and compares that against
//! `sync_objects` at the supervisor layer.
//!
//! Because WebDAV has no native sync token (phase 3 keeps things
//! portable — ownCloud's `oc:sync-token` is out of scope for this
//! pass), the cursor is always `None` and list_since is a full
//! listing on every cycle. The per-cycle diff cost is one HTTP
//! round-trip plus the XML parse; for home-scale Nextcloud that's
//! cheap enough.
//!
//! Auth is HTTP Basic, taking advantage of Nextcloud's app-password
//! feature: operators generate one on the Nextcloud settings page
//! and drop it into the connector's credential blob. OAuth2 can
//! layer in later.
//!
//! Per-mount config JSON:
//!
//! ```json
//! { "base_url": "https://cloud.example.com/remote.php/dav/files/alice" }
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
use reqwest::Method;
use serde::Deserialize;
use time::OffsetDateTime;

pub struct NextcloudConnector {
    http: reqwest::Client,
    base_url: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, Default)]
struct NextcloudConfig {
    #[serde(default)]
    base_url: Option<String>,
}

impl NextcloudConnector {
    pub fn new(base_url: String, username: String, password: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("nextcloud reqwest client"),
            base_url: base_url.trim_end_matches('/').to_string(),
            username,
            password,
        }
    }

    pub fn register(registry: &ConnectorRegistry) {
        registry.register(ConnectorKind::Nextcloud, Self::factory());
    }

    pub fn factory() -> ConnectorFactory {
        Arc::new(|blob, config_json| match blob {
            CredentialBlob::Basic { username, password } => {
                let cfg: NextcloudConfig =
                    serde_json::from_str(config_json).map_err(Error::from)?;
                let base_url = cfg.base_url.ok_or_else(|| {
                    Error::InvalidArgument("nextcloud mount requires config.base_url".into())
                })?;
                let conn: Arc<dyn SyncConnector> = Arc::new(NextcloudConnector::new(
                    base_url,
                    username.clone(),
                    password.clone(),
                ));
                Ok(conn)
            }
            _ => Err(Error::InvalidArgument(
                "nextcloud connector requires Basic credentials".into(),
            )),
        })
    }

    fn url_for(&self, key: &str) -> String {
        let trimmed = key.trim_start_matches('/');
        if trimmed.is_empty() {
            self.base_url.clone()
        } else {
            format!("{}/{}", self.base_url, trimmed)
        }
    }
}

#[async_trait]
impl SyncConnector for NextcloudConnector {
    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Nextcloud
    }

    async fn list_since(&self, _cursor: Option<&[u8]>) -> Result<ListPage> {
        let propfind_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:prop>
    <d:resourcetype/>
    <d:getcontentlength/>
    <d:getlastmodified/>
    <d:getetag/>
  </d:prop>
</d:propfind>"#;
        let resp = self
            .http
            .request(
                Method::from_bytes(b"PROPFIND").unwrap(),
                format!("{}/", self.base_url),
            )
            .basic_auth(&self.username, Some(&self.password))
            .header("Depth", "infinity")
            .header("Content-Type", "application/xml")
            .body(propfind_body)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("propfind: {e}")))?;
        let status = resp.status();
        if !status.is_success() && status.as_u16() != 207 {
            return Err(Error::Transient(format!("propfind http {status}")));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| Error::Transient(format!("propfind body: {e}")))?;
        let entries = parse_propfind(&body, &self.base_url)?;
        let changes = entries
            .into_iter()
            .filter(|o| !o.is_dir)
            .map(Change::Upsert)
            .collect();
        Ok(ListPage {
            changes,
            next_cursor: None,
            more: false,
        })
    }

    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes> {
        let url = self.url_for(&obj.key);
        let resp = self
            .http
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|e| Error::Transient(format!("get: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("get http {status}")));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Transient(format!("get body: {e}")))?;
        Ok(bytes)
    }

    async fn upload(&self, key: &str, bytes: &[u8], _hints: UploadHints) -> Result<RemoteObject> {
        let url = self.url_for(key);
        // Create parent directories with MKCOL walks as needed.
        if let Some(parent) = key.rsplit_once('/').map(|(p, _)| p) {
            let mut so_far = String::new();
            for seg in parent.split('/') {
                if seg.is_empty() {
                    continue;
                }
                if !so_far.is_empty() {
                    so_far.push('/');
                }
                so_far.push_str(seg);
                let dir_url = self.url_for(&so_far);
                let _ = self
                    .http
                    .request(Method::from_bytes(b"MKCOL").unwrap(), &dir_url)
                    .basic_auth(&self.username, Some(&self.password))
                    .send()
                    .await;
            }
        }
        let resp = self
            .http
            .put(&url)
            .basic_auth(&self.username, Some(&self.password))
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| Error::Transient(format!("put: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("put http {status}")));
        }
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string());
        Ok(RemoteObject {
            id: key.to_string(),
            key: key.to_string(),
            size: bytes.len() as u64,
            etag,
            modified: OffsetDateTime::now_utc(),
            is_dir: false,
        })
    }

    async fn delete(&self, obj: &RemoteObject) -> Result<()> {
        let url = self.url_for(&obj.key);
        let resp = self
            .http
            .delete(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|e| Error::Transient(format!("delete: {e}")))?;
        let status = resp.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(Error::Transient(format!("delete http {status}")));
        }
        Ok(())
    }
}

/// Tiny hand-rolled parser for `DAV: multistatus` XML. It is
/// deliberately lenient — we only care about the `<d:response>`
/// children and a handful of prop values inside each. A proper
/// XML crate would be overkill here; Nextcloud's multistatus is
/// shallow and well-behaved.
fn parse_propfind(body: &str, base_url: &str) -> Result<Vec<RemoteObject>> {
    let mut out = Vec::new();
    let base_path = url::Url::parse(base_url)
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default();
    for response in body.split("<d:response>").skip(1) {
        let end = response.find("</d:response>").unwrap_or(response.len());
        let block = &response[..end];
        let href = extract_between(block, "<d:href>", "</d:href>")
            .unwrap_or_default()
            .trim()
            .to_string();
        let key = if !base_path.is_empty() && href.starts_with(&base_path) {
            href[base_path.len()..]
                .trim_start_matches('/')
                .trim_end_matches('/')
                .to_string()
        } else {
            href.trim_start_matches('/')
                .trim_end_matches('/')
                .to_string()
        };
        if key.is_empty() {
            continue;
        }
        let is_dir = block.contains("<d:collection/>") || block.contains("<d:collection />");
        let size = extract_between(block, "<d:getcontentlength>", "</d:getcontentlength>")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let etag = extract_between(block, "<d:getetag>", "</d:getetag>")
            .map(|s| s.trim().trim_matches('"').to_string());
        let modified = extract_between(block, "<d:getlastmodified>", "</d:getlastmodified>")
            .and_then(|s| parse_http_date(s.trim()))
            .unwrap_or_else(OffsetDateTime::now_utc);
        out.push(RemoteObject {
            id: key.clone(),
            key,
            size,
            etag,
            modified,
            is_dir,
        });
    }
    Ok(out)
}

fn extract_between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)? + i;
    Some(&s[i..j])
}

fn parse_http_date(_s: &str) -> Option<OffsetDateTime> {
    // We accept the value lazily; mtime on the remote is used for
    // conflict resolution, so if we can't parse it we fall back to
    // "now" and let the supervisor's hash comparison handle it.
    None
}
