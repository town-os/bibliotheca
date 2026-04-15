//! End-to-end archive tests driving `ArchiveService` through the
//! in-process `BibliothecaService` + `MemoryBackend` harness.

use std::path::PathBuf;
use std::sync::Arc;

use bibliotheca_archive::{
    ArchiveKind, ArchiveService, CreateArchiveParams, Error as ArchiveError,
};
use bibliotheca_config::ArchiveConfig;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::{Store, SubvolumePolicyRow};
use bibliotheca_core::testing::MemoryBackend;
use tempfile::TempDir;

struct Harness {
    _tmp: TempDir,
    svc: BibliothecaService,
    archive: ArchiveService,
}

async fn new_harness() -> Harness {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);
    let cfg = ArchiveConfig {
        root: tmp.path().join("archives"),
        default_kind: "tarball".into(),
        default_retention_days: Some(30),
        lifecycle_interval_secs: 0,
        min_archive_age_days: 0,
    };
    std::fs::create_dir_all(&cfg.root).unwrap();
    let archive = ArchiveService::new(svc.clone(), cfg);
    Harness {
        _tmp: tmp,
        svc,
        archive,
    }
}

async fn seed_subvolume(h: &Harness, name: &str) -> bibliotheca_core::subvolume::Subvolume {
    let user = h.svc.create_user("alice", "Alice", "pw").unwrap();
    let sv = h
        .svc
        .create_subvolume(name, user.id, 0, None)
        .await
        .unwrap();
    let data = DataStore::new(h.svc.clone());
    data.put(name, "a.txt", Some(user.id), false, b"aaaa")
        .unwrap();
    data.put(name, "b.txt", Some(user.id), false, b"bbbb")
        .unwrap();
    data.put(name, "sub/c.txt", Some(user.id), false, b"cccc")
        .unwrap();
    sv
}

#[tokio::test]
async fn tarball_archive_round_trip() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let archive = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "first".into(),
            kind: ArchiveKind::Tarball,
            retention_days: Some(7),
            note: "test".into(),
            created_by: None,
        })
        .await
        .expect("create");

    assert_eq!(archive.kind, ArchiveKind::Tarball);
    assert_eq!(archive.object_count, 3);
    assert!(archive.size_bytes > 0);
    assert!(PathBuf::from(&archive.path).exists());

    // Manifest should list the three seeded files.
    let manifest = h.archive.manifest(&archive.id).unwrap();
    let keys: Vec<&str> = manifest.iter().map(|e| e.key.as_str()).collect();
    assert!(keys.contains(&"a.txt"));
    assert!(keys.contains(&"b.txt"));
    assert!(keys.contains(&"sub/c.txt"));

    // Verify should report ok.
    let report = h.archive.verify(&archive.id).unwrap();
    assert!(report.is_ok(), "verify: {report:?}");
    assert_eq!(report.checked, 3);
}

#[tokio::test]
async fn snapshot_archive_round_trip() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let archive = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "snap1".into(),
            kind: ArchiveKind::Snapshot,
            retention_days: Some(7),
            note: String::new(),
            created_by: None,
        })
        .await
        .expect("create snapshot");

    assert_eq!(archive.kind, ArchiveKind::Snapshot);
    assert_eq!(archive.object_count, 3);

    let report = h.archive.verify(&archive.id).unwrap();
    assert!(report.is_ok(), "verify: {report:?}");
}

#[tokio::test]
async fn immutable_archive_blocks_subvolume_delete() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let _ = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "hold".into(),
            kind: ArchiveKind::Tarball,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .expect("create");

    let err = h.svc.delete_subvolume(sv.id, true).await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(msg.contains("immutable archive"), "unexpected error: {err}");
}

#[tokio::test]
async fn snapshot_archive_blocks_snapshot_delete() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let archive = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "snap-lock".into(),
            kind: ArchiveKind::Snapshot,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .expect("create snapshot");

    // Find the backing snapshot.
    let snaps = h.svc.list_snapshots(sv.id).unwrap();
    let snap = snaps
        .iter()
        .find(|s| s.mount_path.to_string_lossy() == archive.path.to_string_lossy())
        .expect("snap");
    let err = h.svc.delete_snapshot(snap.id).await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(msg.contains("immutable archive"), "unexpected error: {err}");

    // Force-delete via archive path should work.
    h.archive
        .delete(&archive.id, true)
        .await
        .expect("archive delete");
}

#[tokio::test]
async fn delete_without_force_refused_on_immutable() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let a = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "hold".into(),
            kind: ArchiveKind::Tarball,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .unwrap();
    let err = h.archive.delete(&a.id, false).await.unwrap_err();
    matches!(err, ArchiveError::Immutable(_));
}

#[tokio::test]
async fn restore_tarball_into_empty_subvolume() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let archive = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "backup".into(),
            kind: ArchiveKind::Tarball,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .unwrap();

    // Fresh target subvolume owned by the same user.
    let owner = h.svc.get_user("alice").unwrap();
    let target = h
        .svc
        .create_subvolume("restore-target", owner.id, 0, None)
        .await
        .unwrap();

    let restored = h
        .archive
        .restore(&archive.id, target.id, false)
        .expect("restore");
    assert_eq!(restored, 3);

    // Data should be readable out of the target.
    let data = DataStore::new(h.svc.clone());
    let bytes = data
        .get("restore-target", "a.txt", Some(owner.id), false)
        .unwrap();
    assert_eq!(bytes, b"aaaa");
}

#[tokio::test]
async fn restore_conflict_without_overwrite() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let archive = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "backup".into(),
            kind: ArchiveKind::Tarball,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .unwrap();

    let err = h
        .archive
        .restore(&archive.id, sv.id, false)
        .expect_err("should conflict");
    matches!(err, ArchiveError::RestoreConflict(_));
}

#[tokio::test]
async fn list_archives_filters_by_subvolume() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;
    let _ = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "a".into(),
            kind: ArchiveKind::Tarball,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .unwrap();
    let _ = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "b".into(),
            kind: ArchiveKind::Tarball,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .unwrap();
    let all = h.archive.list(None).unwrap();
    assert_eq!(all.len(), 2);
    let filtered = h.archive.list(Some(sv.id)).unwrap();
    assert_eq!(filtered.len(), 2);
}

#[tokio::test]
async fn lifecycle_creates_and_expires_archives() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    h.archive
        .set_policy(SubvolumePolicyRow {
            subvolume_id: sv.id.to_string(),
            kind: "tarball".into(),
            retention_days: Some(0), // expire immediately
            archive_interval_secs: 60,
            min_age_days: 0,
            enabled: true,
            last_run_at: None,
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        })
        .unwrap();

    let rep = h.archive.run_lifecycle_once().await.unwrap();
    assert_eq!(rep.archives_created, 1);

    // Sleep a second to ensure expires_at < now, then run again.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let rep2 = h.archive.run_lifecycle_once().await.unwrap();
    // First call in the sleep window may be idempotent (policy
    // interval has not elapsed), so no new archive is created; but
    // the expired one from the first pass should be swept up.
    assert!(rep2.expired_removed >= 1);
}

#[tokio::test]
async fn verify_detects_tampered_tarball() {
    let h = new_harness().await;
    let sv = seed_subvolume(&h, "photos").await;

    let a = h
        .archive
        .create(CreateArchiveParams {
            subvolume_id: sv.id,
            name: "to-tamper".into(),
            kind: ArchiveKind::Tarball,
            retention_days: None,
            note: String::new(),
            created_by: None,
        })
        .await
        .unwrap();

    // Overwrite the tarball file with garbage. `verify` should
    // refuse it at the full-file hash check.
    std::fs::write(&a.path, b"not a tar file").unwrap();
    let err = h.archive.verify(&a.id).unwrap_err();
    matches!(err, ArchiveError::VerifyFailed { .. });
}
