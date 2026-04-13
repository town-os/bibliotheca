//! Test-support utilities.
//!
//! `MemoryBackend` is a filesystem-backed [`SubvolumeBackend`]
//! implementation that satisfies the trait without requiring btrfs or
//! root privileges. It is intended for tests: it creates real
//! directories under a caller-chosen root so that code which inspects
//! a subvolume's mount path (for example, `bibliotheca-ipfs`'s
//! path-traversal guard or the snapshot code that lists files) sees a
//! real path, not a mock.
//!
//! Gated behind the `test-support` feature on `bibliotheca-core`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::backend::SubvolumeBackend;
use crate::error::{Error, Result};

/// A filesystem-backed `SubvolumeBackend` that pretends it's btrfs.
///
/// Every operation records itself in [`MemoryBackend::ops`] so tests
/// can assert the daemon is issuing the backend calls they expect,
/// including the rollback path when a later step fails.
#[derive(Debug, Clone)]
pub struct MemoryBackend {
    root: PathBuf,
    inner: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    ops: Vec<Op>,
    fail_quota: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Create(PathBuf),
    Delete(PathBuf),
    SetQuota(PathBuf, u64),
    Snapshot {
        source: PathBuf,
        dest: PathBuf,
        readonly: bool,
    },
}

impl MemoryBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let _ = std::fs::create_dir_all(&root);
        Self {
            root,
            inner: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Make the next `set_quota` call fail. Used to exercise the
    /// create-then-rollback path in `BibliothecaService::create_subvolume`.
    pub fn fail_next_quota(&self) {
        self.inner.lock().fail_quota = true;
    }

    pub fn ops(&self) -> Vec<Op> {
        self.inner.lock().ops.clone()
    }

    pub fn ops_len(&self) -> usize {
        self.inner.lock().ops.len()
    }
}

#[async_trait]
impl SubvolumeBackend for MemoryBackend {
    fn root(&self) -> &Path {
        &self.root
    }

    async fn create_subvolume(&self, path: &Path) -> Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::create_dir(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::AlreadyExists(path.display().to_string())
            } else {
                Error::from(e)
            }
        })?;
        self.inner.lock().ops.push(Op::Create(path.to_path_buf()));
        Ok(())
    }

    async fn delete_subvolume(&self, path: &Path) -> Result<()> {
        if path.exists() {
            std::fs::remove_dir_all(path)?;
        }
        self.inner.lock().ops.push(Op::Delete(path.to_path_buf()));
        Ok(())
    }

    async fn set_quota(&self, path: &Path, bytes: u64) -> Result<()> {
        {
            let mut s = self.inner.lock();
            if s.fail_quota {
                s.fail_quota = false;
                return Err(Error::Backend("quota injection".into()));
            }
            s.ops.push(Op::SetQuota(path.to_path_buf(), bytes));
        }
        Ok(())
    }

    async fn snapshot(&self, source: &Path, dest: &Path, readonly: bool) -> Result<()> {
        if !source.exists() {
            return Err(Error::Backend(format!(
                "snapshot source missing: {}",
                source.display()
            )));
        }
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::create_dir(dest)?;
        // Shallow copy — enough for the assertions we care about.
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                std::fs::copy(entry.path(), dest.join(entry.file_name()))?;
            }
        }
        self.inner.lock().ops.push(Op::Snapshot {
            source: source.to_path_buf(),
            dest: dest.to_path_buf(),
            readonly,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn create_delete() {
        let tmp = TempDir::new().unwrap();
        let b = MemoryBackend::new(tmp.path().join("sv"));
        let p = b.path_for("a");
        b.create_subvolume(&p).await.unwrap();
        assert!(p.exists());
        b.delete_subvolume(&p).await.unwrap();
        assert!(!p.exists());
    }

    #[tokio::test]
    async fn fail_quota_flag() {
        let tmp = TempDir::new().unwrap();
        let b = MemoryBackend::new(tmp.path().join("sv"));
        b.fail_next_quota();
        let err = b
            .set_quota(tmp.path(), 100)
            .await
            .expect_err("should fail");
        assert!(matches!(err, Error::Backend(_)));
        // second call recovers
        b.set_quota(tmp.path(), 100).await.unwrap();
    }
}
