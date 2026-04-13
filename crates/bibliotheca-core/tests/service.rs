//! Integration tests for `BibliothecaService` against `MemoryBackend`.
//!
//! These tests cross module boundaries — Store + Service + Backend —
//! but stay in-process. They cover behaviours the gRPC e2e can't
//! easily reach (quota rollback, deterministic op ordering on the
//! backend, cross-group permission resolution).

use std::collections::HashSet;
use std::sync::Arc;

use bibliotheca_core::acl::{Acl, AclEntry, Permission, Principal};
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::error::Error;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::{MemoryBackend, Op};
use tempfile::TempDir;

fn harness() -> (TempDir, BibliothecaService, Arc<MemoryBackend>) {
    let tmp = TempDir::new().unwrap();
    let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend.clone();
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);
    (tmp, svc, backend)
}

#[tokio::test]
async fn create_subvolume_records_backend_ops() {
    let (_tmp, svc, backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc
        .create_subvolume("photos", alice.id, 1024, None)
        .await
        .unwrap();

    let ops = backend.ops();
    assert_eq!(ops.len(), 2, "expected create + set_quota, got {ops:?}");
    assert!(matches!(ops[0], Op::Create(ref p) if p.ends_with("photos")));
    assert!(matches!(ops[1], Op::SetQuota(ref p, 1024) if p.ends_with("photos")));
    assert!(sv.mount_path.exists());
}

#[tokio::test]
async fn create_subvolume_rolls_back_on_quota_failure() {
    let (_tmp, svc, backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();

    backend.fail_next_quota();
    let err = svc
        .create_subvolume("photos", alice.id, 1024, None)
        .await
        .expect_err("quota should fail");
    assert!(matches!(err, Error::Backend(_)));

    let ops = backend.ops();
    // Create, then (after the quota err) Delete to roll back.
    assert_eq!(ops.len(), 2, "{ops:?}");
    assert!(matches!(ops[0], Op::Create(_)));
    assert!(matches!(ops[1], Op::Delete(_)));

    // And the metadata row was never committed.
    assert!(svc.get_subvolume("photos").is_err());
}

#[tokio::test]
async fn create_subvolume_rejects_unknown_owner() {
    let (_tmp, svc, backend) = harness();
    let fake = bibliotheca_core::identity::UserId::new();
    let err = svc
        .create_subvolume("photos", fake, 0, None)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)));
    assert_eq!(backend.ops_len(), 0, "backend should not be touched");
}

#[tokio::test]
async fn create_subvolume_rejects_path_traversal_name() {
    let (_tmp, svc, _backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let err = svc
        .create_subvolume("../escape", alice.id, 0, None)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)));
}

#[tokio::test]
async fn delete_subvolume_requires_force_with_snapshots() {
    let (_tmp, svc, _backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc.create_subvolume("docs", alice.id, 0, None).await.unwrap();
    svc.create_snapshot(sv.id, "s1", true).await.unwrap();

    let err = svc.delete_subvolume(sv.id, false).await.unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)));

    // Force deletes both.
    svc.delete_subvolume(sv.id, true).await.unwrap();
    assert!(svc.get_subvolume("docs").is_err());
}

#[tokio::test]
async fn quota_update_reaches_backend_and_store() {
    let (_tmp, svc, backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc.create_subvolume("docs", alice.id, 0, None).await.unwrap();
    // No quota set_quota op because original was 0.
    assert!(!backend
        .ops()
        .iter()
        .any(|op| matches!(op, Op::SetQuota(_, _))));
    svc.set_quota(sv.id, 2048).await.unwrap();
    assert!(backend
        .ops()
        .iter()
        .any(|op| matches!(op, Op::SetQuota(_, 2048))));
    assert_eq!(svc.get_subvolume("docs").unwrap().quota_bytes, 2048);
}

#[tokio::test]
async fn acl_group_and_owner_precedence() {
    let (_tmp, svc, _backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let bob = svc.create_user("bob", "Bob", "p").unwrap();
    let staff = svc.create_group("staff", "").unwrap();
    svc.add_user_to_group(bob.id, staff.id).unwrap();

    // Alice owns the subvolume; give staff READ only.
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::Group(staff.id),
        permissions: [Permission::Read].into_iter().collect(),
    });
    let sv = svc
        .create_subvolume("photos", alice.id, 0, Some(acl))
        .await
        .unwrap();

    // Owner bypasses ACL entries entirely.
    assert!(svc
        .check_permission(sv.id, Some(alice.id), Permission::Admin, false)
        .unwrap());

    // Bob via staff: READ yes, WRITE no.
    assert!(svc
        .check_permission(sv.id, Some(bob.id), Permission::Read, false)
        .unwrap());
    assert!(!svc
        .check_permission(sv.id, Some(bob.id), Permission::Write, false)
        .unwrap());

    // After removing bob from staff, READ is denied.
    svc.remove_user_from_group(bob.id, staff.id).unwrap();
    assert!(!svc
        .check_permission(sv.id, Some(bob.id), Permission::Read, false)
        .unwrap());
}

#[tokio::test]
async fn public_acl_requires_interface_opt_in() {
    let (_tmp, svc, _backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::Public,
        permissions: [Permission::Read].into_iter().collect(),
    });
    let sv = svc
        .create_subvolume("public", alice.id, 0, Some(acl))
        .await
        .unwrap();

    // public_allowed=false (HTTP disabled) — still denied.
    assert!(!svc
        .check_permission(sv.id, None, Permission::Read, false)
        .unwrap());
    // public_allowed=true — now allowed.
    assert!(svc
        .check_permission(sv.id, None, Permission::Read, true)
        .unwrap());
    // But write is never granted by this entry.
    assert!(!svc
        .check_permission(sv.id, None, Permission::Write, true)
        .unwrap());
}

#[tokio::test]
async fn acl_admin_implies_all_permissions() {
    use bibliotheca_core::acl::Permission::*;
    let (_tmp, svc, _backend) = harness();
    let owner = svc.create_user("owner", "O", "p").unwrap();
    let carol = svc.create_user("carol", "C", "p").unwrap();
    let mut acl = Acl::new();
    acl.entries.push(AclEntry {
        principal: Principal::User(carol.id),
        permissions: [Admin].into_iter().collect(),
    });
    let sv = svc.create_subvolume("c", owner.id, 0, Some(acl)).await.unwrap();

    for p in [Read, Write, List, Delete, Admin] {
        assert!(svc
            .check_permission(sv.id, Some(carol.id), p, false)
            .unwrap(),
            "admin should imply {p:?}");
    }
}

#[tokio::test]
async fn verify_user_password_round_trip() {
    let (_tmp, svc, _backend) = harness();
    let alice = svc.create_user("alice", "Alice", "s3cret").unwrap();
    assert!(svc.verify_user_password("alice", "s3cret").unwrap().is_some());
    assert!(svc.verify_user_password("alice", "wrong").unwrap().is_none());
    assert!(svc.verify_user_password("nobody", "s3cret").unwrap().is_none());
    svc.set_user_password(alice.id, "rotated").unwrap();
    assert!(svc.verify_user_password("alice", "s3cret").unwrap().is_none());
    assert!(svc.verify_user_password("alice", "rotated").unwrap().is_some());
}

#[tokio::test]
async fn group_ids_for_user_is_sorted_and_consistent() {
    let (_tmp, svc, _backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let g1 = svc.create_group("g1", "").unwrap();
    let g2 = svc.create_group("g2", "").unwrap();
    svc.add_user_to_group(alice.id, g1.id).unwrap();
    svc.add_user_to_group(alice.id, g2.id).unwrap();

    let a = svc.store().group_ids_for_user(alice.id).unwrap();
    let b = svc.store().group_ids_for_user(alice.id).unwrap();
    assert_eq!(a, b, "deterministic");
    assert_eq!(a.len(), 2);

    let set: HashSet<_> = a.into_iter().collect();
    assert!(set.contains(&g1.id));
    assert!(set.contains(&g2.id));
}

#[tokio::test]
async fn snapshot_preserves_content_under_memory_backend() {
    let (_tmp, svc, _backend) = harness();
    let alice = svc.create_user("alice", "Alice", "p").unwrap();
    let sv = svc.create_subvolume("docs", alice.id, 0, None).await.unwrap();
    std::fs::write(sv.mount_path.join("hello.txt"), b"hi").unwrap();
    let snap = svc.create_snapshot(sv.id, "s1", true).await.unwrap();
    assert!(snap.mount_path.join("hello.txt").exists());
    let content = std::fs::read(snap.mount_path.join("hello.txt")).unwrap();
    assert_eq!(content, b"hi");
}
