//! Solid / LDP sync connector.
//!
//! Walks a Solid pod's LDP container graph recursively, using the
//! `ldp:contains` triples in each container's Turtle representation
//! to discover children. Non-container resources are fetched with a
//! plain `GET`; uploads are `PUT` with a `Content-Type: text/turtle`
//! or `application/octet-stream` hint; deletes are `DELETE`.
//!
//! Authentication is Bearer token in phase 3 — this covers Solid's
//! "static OIDC token" path that most development pods accept.
//! DPoP and dynamic OIDC can layer in alongside the same connector
//! struct once Solid-OIDC DPoP support is available.
//!
//! Per-mount config JSON:
//!
//! ```json
//! {
//!   "pod_url": "https://pod.example/alice/",
//!   "content_type": "application/octet-stream"
//! }
//! ```

#![allow(clippy::result_large_err)]

use std::collections::VecDeque;
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
use serde::Deserialize;
use time::OffsetDateTime;

pub struct SolidConnector {
    http: reqwest::Client,
    pod_url: String,
    token: String,
    default_ct: String,
}

#[derive(Debug, Deserialize, Default)]
struct SolidConfig {
    #[serde(default)]
    pod_url: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

impl SolidConnector {
    pub fn new(pod_url: String, token: String, default_ct: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("solid reqwest client"),
            pod_url: pod_url.trim_end_matches('/').to_string(),
            token,
            default_ct,
        }
    }

    pub fn register(registry: &ConnectorRegistry) {
        registry.register(ConnectorKind::Solid, Self::factory());
    }

    pub fn factory() -> ConnectorFactory {
        Arc::new(|blob, config_json| match blob {
            CredentialBlob::Token { token, .. } => {
                let cfg: SolidConfig = serde_json::from_str(config_json).map_err(Error::from)?;
                let pod_url = cfg.pod_url.ok_or_else(|| {
                    Error::InvalidArgument("solid mount requires config.pod_url".into())
                })?;
                let default_ct = cfg
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                let conn: Arc<dyn SyncConnector> =
                    Arc::new(SolidConnector::new(pod_url, token.clone(), default_ct));
                Ok(conn)
            }
            _ => Err(Error::InvalidArgument(
                "solid connector requires Token credentials".into(),
            )),
        })
    }

    fn resource_url(&self, key: &str) -> String {
        let trimmed = key.trim_start_matches('/');
        if trimmed.is_empty() {
            format!("{}/", self.pod_url)
        } else {
            format!("{}/{}", self.pod_url, trimmed)
        }
    }

    async fn walk_container(&self, prefix: &str, out: &mut Vec<RemoteObject>) -> Result<()> {
        let url = self.resource_url(prefix);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .header("Accept", "text/turtle")
            .send()
            .await
            .map_err(|e| Error::Transient(format!("solid get container: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("solid http {status}")));
        }
        let ttl = resp
            .text()
            .await
            .map_err(|e| Error::Transient(format!("solid body: {e}")))?;
        let now = OffsetDateTime::now_utc();
        let children = parse_ldp_contains(&ttl);
        for child in children {
            let child_key = if prefix.is_empty() {
                child.clone()
            } else {
                format!("{prefix}/{child}")
            };
            if child.ends_with('/') {
                // Nested container; recurse.
                let nested = child_key.trim_end_matches('/').to_string();
                Box::pin(self.walk_container(&nested, out)).await?;
            } else {
                out.push(RemoteObject {
                    id: child_key.clone(),
                    key: child_key,
                    size: 0,
                    etag: None,
                    modified: now,
                    is_dir: false,
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SyncConnector for SolidConnector {
    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Solid
    }

    async fn list_since(&self, _cursor: Option<&[u8]>) -> Result<ListPage> {
        let mut out = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(String::new());
        self.walk_container("", &mut out).await?;
        let _ = queue; // keep the import warm for later phases
        Ok(ListPage {
            changes: out.into_iter().map(Change::Upsert).collect(),
            next_cursor: None,
            more: false,
        })
    }

    async fn fetch(&self, obj: &RemoteObject) -> Result<Bytes> {
        let url = self.resource_url(&obj.key);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("solid get: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("solid get http {status}")));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Transient(format!("solid get body: {e}")))?;
        Ok(bytes)
    }

    async fn upload(&self, key: &str, bytes: &[u8], hints: UploadHints) -> Result<RemoteObject> {
        let url = self.resource_url(key);
        let ct = hints
            .content_type
            .unwrap_or_else(|| self.default_ct.clone());
        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.token)
            .header("Content-Type", ct)
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| Error::Transient(format!("solid put: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transient(format!("solid put http {status}")));
        }
        Ok(RemoteObject {
            id: key.to_string(),
            key: key.to_string(),
            size: bytes.len() as u64,
            etag: None,
            modified: OffsetDateTime::now_utc(),
            is_dir: false,
        })
    }

    async fn delete(&self, obj: &RemoteObject) -> Result<()> {
        let url = self.resource_url(&obj.key);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("solid delete: {e}")))?;
        let status = resp.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(Error::Transient(format!("solid delete http {status}")));
        }
        Ok(())
    }
}

/// Very lightweight Turtle parser that only cares about
/// `ldp:contains` triples — the single primitive LDP containers
/// use to enumerate children. For each `ldp:contains <child>`
/// or `<child>,` we return the child's relative path (the portion
/// after the last slash in its IRI).
fn parse_ldp_contains(ttl: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = ttl;
    while let Some(i) = rest.find("ldp:contains") {
        rest = &rest[i + "ldp:contains".len()..];
        // Everything until the next `.` is the object list for this
        // `ldp:contains` predicate. Split by `,` for multiple
        // children.
        let end = rest.find('.').unwrap_or(rest.len());
        let objects = &rest[..end];
        for obj in objects.split(',') {
            let trimmed = obj.trim();
            let iri = trimmed.trim_start_matches('<').trim_end_matches('>').trim();
            if iri.is_empty() {
                continue;
            }
            // Relative IRI — take the last path segment (with a
            // trailing slash preserved if it's a container).
            let tail = iri
                .rsplit_once('/')
                .map(|(_, t)| t.to_string())
                .unwrap_or_else(|| iri.to_string());
            if !tail.is_empty() {
                out.push(tail);
            } else if iri.ends_with('/') {
                // A bare `/` means "self" — skip.
                continue;
            }
        }
        rest = &rest[end..];
    }
    out
}
