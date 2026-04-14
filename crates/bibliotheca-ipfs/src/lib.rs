//! IPFS ingest / manipulation.
//!
//! bibliotheca does not embed an IPFS node. Instead it talks to a local
//! Kubo (go-ipfs) RPC API — that's the same approach town-os already
//! uses for service integrations and lets us reuse Kubo's pinning,
//! garbage collection and gateway machinery. The control plane exposes
//! `Pin / Unpin / Import / Export / ListPins`; this crate is the
//! bibliotheca-side shim that translates those into Kubo HTTP calls and
//! materializes (or sources) bytes inside the target subvolume.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bibliotheca_core::error::Result;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::subvolume::SubvolumeId;
use tracing::info;
use url::Url;

#[async_trait]
pub trait IpfsClient: Send + Sync + 'static {
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<u64>;
    async fn pin_rm(&self, cid: &str) -> Result<()>;
    async fn add(&self, path: &Path) -> Result<String>;
    async fn cat(&self, cid: &str, dest: &Path) -> Result<u64>;
    async fn pins(&self) -> Result<Vec<String>>;
}

#[derive(Clone)]
pub struct IpfsService {
    svc: BibliothecaService,
    client: Arc<dyn IpfsClient>,
}

impl IpfsService {
    pub fn new(svc: BibliothecaService, client: Arc<dyn IpfsClient>) -> Self {
        Self { svc, client }
    }

    /// Pin `cid` and record it as belonging to `subvolume`. Bytes are
    /// not materialized into the subvolume — pinning just keeps them
    /// alive in Kubo. Use [`Self::export`] to materialize a copy.
    pub async fn pin(&self, cid: &str, subvolume: SubvolumeId, recursive: bool) -> Result<u64> {
        let _ = self.svc.store().get_subvolume(subvolume)?;
        let size = self.client.pin_add(cid, recursive).await?;
        info!(cid, %subvolume, size, "pinned");
        Ok(size)
    }

    pub async fn unpin(&self, cid: &str) -> Result<()> {
        self.client.pin_rm(cid).await
    }

    /// Import an existing file inside `subvolume` into IPFS, returning
    /// the resulting CID.
    pub async fn import(&self, subvolume: SubvolumeId, source: &Path) -> Result<String> {
        let sv = self.svc.store().get_subvolume(subvolume)?;
        let abs = absolutize(&sv.mount_path, source)?;
        self.client.add(&abs).await
    }

    /// Export `cid` from IPFS into `subvolume` at `dest_path`.
    pub async fn export(&self, subvolume: SubvolumeId, cid: &str, dest_path: &Path) -> Result<u64> {
        let sv = self.svc.store().get_subvolume(subvolume)?;
        let abs = absolutize(&sv.mount_path, dest_path)?;
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.client.cat(cid, &abs).await
    }

    pub async fn list_pins(&self) -> Result<Vec<String>> {
        self.client.pins().await
    }
}

fn absolutize(root: &Path, p: &Path) -> Result<PathBuf> {
    use bibliotheca_core::error::Error;
    use std::path::Component;

    // Canonicalize the root up front so symlinks on the way in don't
    // let a caller slip past the containment check.
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let candidate = if p.is_absolute() {
        p.to_path_buf()
    } else {
        canon_root.join(p)
    };

    // Resolve `.` and `..` textually so we catch escapes even when the
    // target doesn't exist yet — filesystem canonicalization can't
    // help for paths that are about to be created.
    let mut normalized = PathBuf::new();
    for comp in candidate.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(Error::InvalidArgument(format!(
                        "path escapes subvolume: {}",
                        p.display()
                    )));
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    if !normalized.starts_with(&canon_root) {
        return Err(Error::InvalidArgument(format!(
            "path escapes subvolume: {}",
            p.display()
        )));
    }
    Ok(normalized)
}

/// Default Kubo client that talks to an HTTP RPC endpoint, usually
/// `http://127.0.0.1:5001`. All Kubo RPCs are `POST` requests that
/// return newline-delimited JSON; the endpoint URL is joined with a
/// path like `/api/v0/pin/add` for each call.
pub struct KuboClient {
    endpoint: Url,
    http: reqwest::Client,
}

impl KuboClient {
    pub fn new(endpoint: Url) -> Self {
        Self::with_client(endpoint, reqwest::Client::new())
    }

    pub fn with_client(endpoint: Url, http: reqwest::Client) -> Self {
        Self { endpoint, http }
    }

    fn url(&self, path: &str) -> std::result::Result<Url, bibliotheca_core::error::Error> {
        self.endpoint
            .join(path)
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("kubo url join: {e}")))
    }
}

#[async_trait]
impl IpfsClient for KuboClient {
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<u64> {
        let url = self.url("api/v0/pin/add")?;
        let resp = self
            .http
            .post(url)
            .query(&[
                ("arg", cid),
                ("recursive", if recursive { "true" } else { "false" }),
            ])
            .send()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("pin_add: {e}")))?;
        if !resp.status().is_success() {
            return Err(bibliotheca_core::error::Error::Backend(format!(
                "pin_add http {}",
                resp.status()
            )));
        }
        // Kubo returns `{"Pins":["<cid>"]}` on success — the pinned
        // size is reported separately by `pin/ls` so we just echo 0
        // here.
        Ok(0)
    }

    async fn pin_rm(&self, cid: &str) -> Result<()> {
        let url = self.url("api/v0/pin/rm")?;
        let resp = self
            .http
            .post(url)
            .query(&[("arg", cid)])
            .send()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("pin_rm: {e}")))?;
        if !resp.status().is_success() {
            return Err(bibliotheca_core::error::Error::Backend(format!(
                "pin_rm http {}",
                resp.status()
            )));
        }
        Ok(())
    }

    async fn add(&self, path: &Path) -> Result<String> {
        let bytes = std::fs::read(path)?;
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("blob")
            .to_string();
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.clone())
            .mime_str("application/octet-stream")
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("add mime: {e}")))?;
        let form = reqwest::multipart::Form::new().part("file", part);

        let url = self.url("api/v0/add")?;
        let resp = self
            .http
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("add: {e}")))?;
        if !resp.status().is_success() {
            return Err(bibliotheca_core::error::Error::Backend(format!(
                "add http {}",
                resp.status()
            )));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("add body: {e}")))?;
        // Kubo streams add results as one JSON object per line; take
        // the last line that has a `Hash` field.
        let mut cid: Option<String> = None;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(h) = v.get("Hash").and_then(|h| h.as_str()) {
                    cid = Some(h.to_string());
                }
            }
        }
        cid.ok_or_else(|| {
            bibliotheca_core::error::Error::Backend("add: missing Hash in response".into())
        })
    }

    async fn cat(&self, cid: &str, dest: &Path) -> Result<u64> {
        let url = self.url("api/v0/cat")?;
        let resp = self
            .http
            .post(url)
            .query(&[("arg", cid)])
            .send()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("cat: {e}")))?;
        if !resp.status().is_success() {
            return Err(bibliotheca_core::error::Error::Backend(format!(
                "cat http {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("cat body: {e}")))?;
        std::fs::write(dest, &bytes)?;
        Ok(bytes.len() as u64)
    }

    async fn pins(&self) -> Result<Vec<String>> {
        let url = self.url("api/v0/pin/ls")?;
        let resp = self
            .http
            .post(url)
            .send()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("pin_ls: {e}")))?;
        if !resp.status().is_success() {
            return Err(bibliotheca_core::error::Error::Backend(format!(
                "pin_ls http {}",
                resp.status()
            )));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| bibliotheca_core::error::Error::Backend(format!("pin_ls body: {e}")))?;
        Ok(body
            .get("Keys")
            .and_then(|k| k.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default())
    }
}
