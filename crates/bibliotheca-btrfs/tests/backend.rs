//! `BtrfsBackend` shells out to the `btrfs` binary. These tests
//! replace that binary with a hermetic shell script so we can assert
//! the exact argument list the backend produces for every operation,
//! and the error propagation path when the binary exits non-zero.
//!
//! There is also an `#[ignore]`-gated test that runs against a real
//! btrfs filesystem if the operator opts in by setting
//! `BIBLIOTHECA_REAL_BTRFS_ROOT` to a writable subdirectory of a btrfs
//! mount. Run that one explicitly with:
//!
//! ```sh
//! BIBLIOTHECA_REAL_BTRFS_ROOT=/data/bibliotheca-test \
//!   cargo test -p bibliotheca-btrfs --test backend -- --ignored
//! ```

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use bibliotheca_btrfs::BtrfsBackend;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::error::Error;
use tempfile::TempDir;
use tokio::sync::{Mutex, MutexGuard};

/// Serialize the whole test body.
///
/// These tests write a fake `btrfs` script to a tempdir and then
/// `exec` it. If another test is mid-`std::fs::write` on its own copy
/// when we fork to exec ours, the forked child inherits that other
/// test's still-open write fd, and Linux's ETXTBSY check triggers on
/// the exec target. The race is narrow but reproducible under cargo's
/// parallel test runner — holding this mutex for the duration of each
/// test is the cheapest robust fix.
///
/// `tokio::sync::Mutex` (not `std::sync::Mutex`) because the guard is
/// held across `.await` points.
fn serial_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn serial() -> MutexGuard<'static, ()> {
    serial_mutex().lock().await
}

/// Writes a fake `btrfs` shell script that records every invocation's
/// argv into `log` and optionally exits non-zero. No env vars are used,
/// so tests are hermetic and can run in parallel.
fn fake_btrfs(dir: &Path, log: &Path, fail: bool) -> PathBuf {
    let bin = dir.join("btrfs");
    let tail = if fail {
        "echo 'synthetic failure' >&2\nexit 1\n"
    } else {
        "exit 0\n"
    };
    // `printf '%s\n' "$@"` emits one arg per line so argv is
    // unambiguous even when individual args contain spaces.
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n{}",
        log.display(),
        tail
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

struct Harness {
    _tmp: TempDir,
    backend: BtrfsBackend,
    log: PathBuf,
}

fn harness(fail: bool) -> Harness {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("btrfs.log");
    let bin = fake_btrfs(tmp.path(), &log, fail);
    let root = tmp.path().join("sv");
    std::fs::create_dir_all(&root).unwrap();
    let backend = BtrfsBackend::new(root).with_bin(bin);
    Harness {
        _tmp: tmp,
        backend,
        log,
    }
}

fn invocations(log: &Path) -> Vec<Vec<String>> {
    if !log.exists() {
        return Vec::new();
    }
    let content = std::fs::read_to_string(log).unwrap();
    // Each call appends one line per arg terminated by blank-separated
    // runs; we separate invocations by recognising known first args.
    let args: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut invs = Vec::new();
    let mut current = Vec::<String>::new();
    for a in args {
        if matches!(
            a.as_str(),
            "subvolume" | "qgroup" | "quota" | "filesystem" | "property"
        ) && !current.is_empty()
        {
            invs.push(std::mem::take(&mut current));
        }
        current.push(a);
    }
    if !current.is_empty() {
        invs.push(current);
    }
    invs
}

#[tokio::test]
async fn create_subvolume_args() {
    let _g = serial().await;
    let h = harness(false);
    let path = h.backend.path_for("photos");
    h.backend.create_subvolume(&path).await.unwrap();

    let invs = invocations(&h.log);
    assert_eq!(invs.len(), 1);
    assert_eq!(invs[0][0..2], ["subvolume", "create"]);
    assert_eq!(invs[0][2], path.display().to_string());
    // The backend pre-creates the *parent* so `btrfs subvolume create`
    // doesn't fail on a missing directory; the subvolume path itself
    // is left alone — the real btrfs binary would create it.
    assert!(
        path.parent().unwrap().exists(),
        "backend should mkdir -p parent"
    );
    assert!(!path.exists(), "backend must not pre-create the target");
}

#[tokio::test]
async fn delete_subvolume_args_include_commit_after() {
    let _g = serial().await;
    let h = harness(false);
    let path = h.backend.path_for("photos");
    // delete_subvolume doesn't create the directory itself; the real
    // btrfs binary would refuse but our fake happily records the call.
    h.backend.delete_subvolume(&path).await.unwrap();

    let invs = invocations(&h.log);
    assert_eq!(invs.len(), 1);
    assert_eq!(
        invs[0],
        vec![
            "subvolume".to_string(),
            "delete".to_string(),
            "--commit-after".to_string(),
            path.display().to_string()
        ]
    );
}

#[tokio::test]
async fn set_quota_none_when_zero() {
    let _g = serial().await;
    let h = harness(false);
    let path = h.backend.path_for("photos");
    h.backend.set_quota(&path, 0).await.unwrap();

    let invs = invocations(&h.log);
    assert_eq!(invs.len(), 1);
    assert_eq!(
        invs[0],
        vec![
            "qgroup".to_string(),
            "limit".to_string(),
            "none".to_string(),
            path.display().to_string()
        ]
    );
}

#[tokio::test]
async fn set_quota_positive() {
    let _g = serial().await;
    let h = harness(false);
    let path = h.backend.path_for("photos");
    h.backend.set_quota(&path, 1073741824).await.unwrap();

    let invs = invocations(&h.log);
    assert_eq!(invs.len(), 1);
    assert_eq!(invs[0][2], "1073741824");
}

#[tokio::test]
async fn snapshot_readonly_flag() {
    let _g = serial().await;
    let h = harness(false);
    let src = h.backend.path_for("docs");
    std::fs::create_dir_all(&src).unwrap();
    let dst = h.backend.root().join(".snapshots/docs/s1");

    h.backend.snapshot(&src, &dst, true).await.unwrap();
    let invs = invocations(&h.log);
    assert_eq!(invs.len(), 1);
    assert_eq!(
        invs[0],
        vec![
            "subvolume".to_string(),
            "snapshot".to_string(),
            "-r".to_string(),
            src.display().to_string(),
            dst.display().to_string()
        ]
    );
}

#[tokio::test]
async fn snapshot_without_readonly() {
    let _g = serial().await;
    let h = harness(false);
    let src = h.backend.path_for("docs");
    std::fs::create_dir_all(&src).unwrap();
    let dst = h.backend.root().join(".snapshots/docs/s1");

    h.backend.snapshot(&src, &dst, false).await.unwrap();
    let invs = invocations(&h.log);
    assert_eq!(invs.len(), 1);
    assert!(!invs[0].contains(&"-r".to_string()));
    assert_eq!(invs[0][0..2], ["subvolume", "snapshot"]);
}

#[tokio::test]
async fn non_zero_exit_becomes_backend_error() {
    let _g = serial().await;
    let h = harness(true);
    let path = h.backend.path_for("photos");
    let err = h.backend.create_subvolume(&path).await.unwrap_err();
    match err {
        Error::Backend(msg) => {
            assert!(msg.contains("subvolume create"), "message: {msg}");
            assert!(msg.contains("synthetic failure"), "message: {msg}");
        }
        other => panic!("expected Backend error, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires BIBLIOTHECA_REAL_BTRFS_ROOT and `btrfs` on PATH"]
async fn real_btrfs_round_trip() {
    let root = std::env::var("BIBLIOTHECA_REAL_BTRFS_ROOT")
        .expect("set BIBLIOTHECA_REAL_BTRFS_ROOT to a writable btrfs directory");
    let backend = BtrfsBackend::new(PathBuf::from(root));
    let name = format!("bibliotheca-test-{}", std::process::id());
    let path = backend.path_for(&name);

    backend
        .create_subvolume(&path)
        .await
        .expect("create_subvolume");
    assert!(path.exists());

    // Best-effort cleanup.
    backend
        .delete_subvolume(&path)
        .await
        .expect("delete_subvolume");
    assert!(!path.exists());
}
