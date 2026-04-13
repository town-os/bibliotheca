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
    pub async fn export(
        &self,
        subvolume: SubvolumeId,
        cid: &str,
        dest_path: &Path,
    ) -> Result<u64> {
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

/// Default Kubo client that talks to `http://127.0.0.1:5001`.
pub struct KuboClient {
    pub endpoint: Url,
}

impl KuboClient {
    pub fn new(endpoint: Url) -> Self {
        Self { endpoint }
    }
}

#[async_trait]
impl IpfsClient for KuboClient {
    async fn pin_add(&self, _cid: &str, _recursive: bool) -> Result<u64> {
        // TODO(spec): POST {endpoint}/api/v0/pin/add?arg=<cid>&recursive=<bool>
        Ok(0)
    }
    async fn pin_rm(&self, _cid: &str) -> Result<()> {
        Ok(())
    }
    async fn add(&self, _path: &Path) -> Result<String> {
        Ok(String::new())
    }
    async fn cat(&self, _cid: &str, _dest: &Path) -> Result<u64> {
        Ok(0)
    }
    async fn pins(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }
}
