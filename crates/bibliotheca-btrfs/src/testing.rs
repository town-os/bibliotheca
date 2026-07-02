//! Test-only backend selection for integration harnesses.
//!
//! Enabled by the `test-support` feature. Integration tests call
//! [`test_backend`] instead of constructing a backend directly, which lets
//! the whole transport test matrix run against either an in-memory fake (the
//! default) or a **real** btrfs filesystem when [`REAL_BTRFS_ROOT_ENV`] points
//! at one. `ci/container-tests.sh` sets that variable after mounting a
//! throwaway loopback btrfs, so the real subvolume + byte path is exercised in
//! CI without touching the host.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::testing::MemoryBackend;

use crate::BtrfsBackend;

/// Environment variable naming a writable **btrfs** directory. When set to a
/// non-empty value, [`test_backend`] returns a real [`BtrfsBackend`] rooted
/// beneath it instead of the in-memory fake.
pub const REAL_BTRFS_ROOT_ENV: &str = "BIBLIOTHECA_REAL_BTRFS_ROOT";

/// Disambiguates the per-harness subdirectory so concurrent `spawn()` calls
/// (and repeated ones within a test binary) never collide on subvolume names.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// Return a subvolume backend for an integration harness.
///
/// If [`REAL_BTRFS_ROOT_ENV`] names a non-empty path, returns a real
/// [`BtrfsBackend`] rooted at a fresh unique subdirectory beneath it — so a
/// harness that creates a subvolume named `photos` never clashes with another
/// harness doing the same. Otherwise returns a filesystem-backed
/// [`MemoryBackend`] at `mem_root`, matching the historical default.
///
/// The real path needs the `btrfs` binary on `PATH` and privileges to run
/// `btrfs subvolume create`; run it via `make test-container`, which provides
/// both inside a container with a loopback btrfs filesystem.
pub fn test_backend(mem_root: impl Into<PathBuf>) -> Arc<dyn SubvolumeBackend> {
    match std::env::var(REAL_BTRFS_ROOT_ENV) {
        Ok(root) if !root.is_empty() => {
            let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
            let unique = PathBuf::from(root).join(format!("it-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&unique)
                .unwrap_or_else(|e| panic!("create btrfs test root {}: {e}", unique.display()));
            Arc::new(BtrfsBackend::new(unique))
        }
        _ => Arc::new(MemoryBackend::new(mem_root.into())),
    }
}
