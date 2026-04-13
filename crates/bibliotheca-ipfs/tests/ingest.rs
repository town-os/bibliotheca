//! Integration tests for IPFS ingest.
//!
//! `IpfsService` is the orchestration layer on top of an `IpfsClient`
//! trait. The real Kubo client is covered manually; here we use a
//! deterministic fake so the service-side logic (ACL lookups,
//! path-traversal guard, subvolume materialization) is tested in
//! isolation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::error::{Error, Result};
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_ipfs::{IpfsClient, IpfsService};
use parking_lot::Mutex;
use tempfile::TempDir;

#[derive(Default)]
struct FakeInner {
    blobs: HashMap<String, Vec<u8>>,
    pins: Vec<String>,
    next_cid: u64,
}

#[derive(Default, Clone)]
struct FakeIpfs {
    inner: Arc<Mutex<FakeInner>>,
}

impl FakeIpfs {
    fn mint_cid(&self) -> String {
        let mut s = self.inner.lock();
        s.next_cid += 1;
        format!("Qm{:064x}", s.next_cid)
    }
}

#[async_trait]
impl IpfsClient for FakeIpfs {
    async fn pin_add(&self, cid: &str, _recursive: bool) -> Result<u64> {
        let mut s = self.inner.lock();
        if !s.blobs.contains_key(cid) {
            // allow pinning unknown CIDs — Kubo would fetch them.
            s.blobs.insert(cid.to_string(), Vec::new());
        }
        if !s.pins.iter().any(|c| c == cid) {
            s.pins.push(cid.to_string());
        }
        Ok(s.blobs.get(cid).map(|b| b.len() as u64).unwrap_or(0))
    }
    async fn pin_rm(&self, cid: &str) -> Result<()> {
        let mut s = self.inner.lock();
        s.pins.retain(|c| c != cid);
        Ok(())
    }
    async fn add(&self, path: &Path) -> Result<String> {
        let bytes = std::fs::read(path)?;
        let cid = self.mint_cid();
        self.inner.lock().blobs.insert(cid.clone(), bytes);
        Ok(cid)
    }
    async fn cat(&self, cid: &str, dest: &Path) -> Result<u64> {
        let s = self.inner.lock();
        let bytes = s
            .blobs
            .get(cid)
            .ok_or_else(|| Error::NotFound(format!("cid {cid}")))?
            .clone();
        drop(s);
        std::fs::write(dest, &bytes)?;
        Ok(bytes.len() as u64)
    }
    async fn pins(&self) -> Result<Vec<String>> {
        Ok(self.inner.lock().pins.clone())
    }
}

fn harness() -> (TempDir, IpfsService, FakeIpfs, BibliothecaService) {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);
    let fake = FakeIpfs::default();
    let ipfs = IpfsService::new(svc.clone(), Arc::new(fake.clone()));
    (tmp, ipfs, fake, svc)
}

#[tokio::test]
async fn import_and_export_round_trip() {
    let (_tmp, ipfs, _fake, svc) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc
        .create_subvolume("docs", alice.id, 0, None)
        .await
        .unwrap();

    let src = sv.mount_path.join("hello.txt");
    std::fs::write(&src, b"hello, ipfs").unwrap();

    let cid = ipfs.import(sv.id, &PathBuf::from("hello.txt")).await.unwrap();
    assert!(cid.starts_with("Qm"));

    // Export into a fresh relative path under the same subvolume.
    let written = ipfs
        .export(sv.id, &cid, &PathBuf::from("copy.txt"))
        .await
        .unwrap();
    assert_eq!(written, b"hello, ipfs".len() as u64);
    assert_eq!(
        std::fs::read(sv.mount_path.join("copy.txt")).unwrap(),
        b"hello, ipfs"
    );
}

#[tokio::test]
async fn pin_then_list_then_unpin() {
    let (_tmp, ipfs, _fake, svc) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc
        .create_subvolume("docs", alice.id, 0, None)
        .await
        .unwrap();

    ipfs.pin("QmDeadBeef", sv.id, true).await.unwrap();
    let pins = ipfs.list_pins().await.unwrap();
    assert_eq!(pins, vec!["QmDeadBeef".to_string()]);

    ipfs.unpin("QmDeadBeef").await.unwrap();
    let pins = ipfs.list_pins().await.unwrap();
    assert!(pins.is_empty());
}

#[tokio::test]
async fn pin_rejects_unknown_subvolume() {
    let (_tmp, ipfs, _fake, _svc) = harness();
    use bibliotheca_core::subvolume::SubvolumeId;
    let fake_sv = SubvolumeId::new();
    let err = ipfs.pin("Qm", fake_sv, true).await.unwrap_err();
    assert!(matches!(err, Error::NotFound(_)));
}

#[tokio::test]
async fn import_rejects_path_traversal() {
    let (tmp, ipfs, _fake, svc) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc
        .create_subvolume("docs", alice.id, 0, None)
        .await
        .unwrap();

    // Plant a file outside the subvolume root, then try to ingest it
    // by absolute path — the guard should reject.
    let outside = tmp.path().join("outside.txt");
    std::fs::write(&outside, b"nope").unwrap();
    let err = ipfs.import(sv.id, &outside).await.unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

    // And via a relative `..` escape too.
    let err = ipfs
        .import(sv.id, &PathBuf::from("../../etc/passwd"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
}

#[tokio::test]
async fn export_creates_parent_directories() {
    let (_tmp, ipfs, fake, svc) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc
        .create_subvolume("docs", alice.id, 0, None)
        .await
        .unwrap();

    // Seed the fake with a known blob.
    let src = sv.mount_path.join("seed.txt");
    std::fs::write(&src, b"seed").unwrap();
    let cid = ipfs.import(sv.id, &PathBuf::from("seed.txt")).await.unwrap();

    // Confirm it's in the fake store (guard against the fake eating writes).
    assert!(fake.inner.lock().blobs.contains_key(&cid));

    // Exporting to a path under a not-yet-existing subdirectory must
    // transparently create the parents.
    ipfs.export(sv.id, &cid, &PathBuf::from("nested/deep/out.txt"))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(sv.mount_path.join("nested/deep/out.txt")).unwrap(),
        b"seed"
    );
}
