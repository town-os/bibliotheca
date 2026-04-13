use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::error::Result;

/// Filesystem operations needed by the storage service.
///
/// In production this is implemented by `bibliotheca-btrfs`. Tests use an
/// in-memory implementation that just shells out to `mkdir -p`.
#[async_trait]
pub trait SubvolumeBackend: Send + Sync + 'static {
    /// Root directory under which subvolumes will be created. Used so
    /// callers can construct the canonical mount path for a subvolume
    /// without inspecting the backend.
    fn root(&self) -> &Path;

    /// Create a btrfs subvolume at `path`.
    async fn create_subvolume(&self, path: &Path) -> Result<()>;

    /// Delete a subvolume rooted at `path`.
    async fn delete_subvolume(&self, path: &Path) -> Result<()>;

    /// Apply a quota (bytes) to the subvolume at `path`. 0 = unlimited.
    async fn set_quota(&self, path: &Path, bytes: u64) -> Result<()>;

    /// Snapshot `source` to `dest`. If `readonly` is true, the snapshot
    /// is taken with `-r`.
    async fn snapshot(&self, source: &Path, dest: &Path, readonly: bool) -> Result<()>;

    /// Compute the canonical filesystem path for a subvolume name.
    fn path_for(&self, name: &str) -> PathBuf {
        self.root().join(name)
    }
}
