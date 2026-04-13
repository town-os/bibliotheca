//! Btrfs subvolume backend.
//!
//! Mirrors the surface area of the Go `BtrFSController` in town-os
//! (`town-os/src/storage/btrfs.go`) so bibliotheca can sit alongside the
//! existing storage manager without contention. The controller shells
//! out to the `btrfs` binary; that binary's path is configurable so the
//! daemon can run under tests with a fake.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::error::{Error, Result};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, instrument};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct BtrfsBackend {
    bin_path: PathBuf,
    root: PathBuf,
    op_timeout: Duration,
}

impl BtrfsBackend {
    /// Create a new backend that places subvolumes under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            bin_path: PathBuf::from("btrfs"),
            root: root.into(),
            op_timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_bin(mut self, bin: impl Into<PathBuf>) -> Self {
        self.bin_path = bin.into();
        self
    }

    pub fn with_timeout(mut self, d: Duration) -> Self {
        self.op_timeout = d;
        self
    }

    #[instrument(skip(self), fields(bin = %self.bin_path.display()))]
    async fn run(&self, args: &[&str]) -> Result<()> {
        debug!(?args, "btrfs invoke");
        let fut = async {
            let out = Command::new(&self.bin_path)
                .args(args)
                .stdin(Stdio::null())
                .output()
                .await?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
                return Err(Error::Backend(format!(
                    "btrfs {}: {}",
                    args.join(" "),
                    stderr.trim()
                )));
            }
            Ok::<_, Error>(())
        };
        match timeout(self.op_timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(Error::Backend(format!(
                "btrfs {} timed out",
                args.join(" ")
            ))),
        }
    }
}

#[async_trait]
impl SubvolumeBackend for BtrfsBackend {
    fn root(&self) -> &Path {
        &self.root
    }

    async fn create_subvolume(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.run(&["subvolume", "create", &path.display().to_string()])
            .await
    }

    async fn delete_subvolume(&self, path: &Path) -> Result<()> {
        self.run(&[
            "subvolume",
            "delete",
            "--commit-after",
            &path.display().to_string(),
        ])
        .await
    }

    async fn set_quota(&self, path: &Path, bytes: u64) -> Result<()> {
        // `qgroup limit` requires that quotas have been enabled on the
        // containing filesystem (`btrfs quota enable`). The town-os
        // installer enables that on the data filesystem at provisioning
        // time; nothing to do here.
        let limit = if bytes == 0 {
            "none".to_string()
        } else {
            bytes.to_string()
        };
        self.run(&[
            "qgroup",
            "limit",
            &limit,
            &path.display().to_string(),
        ])
        .await
    }

    async fn snapshot(&self, source: &Path, dest: &Path, readonly: bool) -> Result<()> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut args: Vec<&str> = vec!["subvolume", "snapshot"];
        if readonly {
            args.push("-r");
        }
        let src = source.display().to_string();
        let dst = dest.display().to_string();
        args.push(&src);
        args.push(&dst);
        self.run(&args).await
    }
}
