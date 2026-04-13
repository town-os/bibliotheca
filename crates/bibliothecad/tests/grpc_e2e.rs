//! End-to-end test of the bibliothecad gRPC control plane.
//!
//! Spawns the server on a tempdir Unix socket and drives it through
//! the tonic-generated client — exactly the same path `bibliothecactl`
//! uses. Exercises the full surface the daemon exposes today.

mod common;

use bibliotheca_proto::v1 as pb;
use common::Harness;

#[tokio::test]
async fn health_check_starts_empty() {
    let h = Harness::new().await;
    let mut id = h.identity();
    let users = id
        .list_users(pb::ListUsersRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(users.users.is_empty());

    let mut st = h.storage();
    let svs = st
        .list_subvolumes(pb::ListSubvolumesRequest {
            owner_user_id: String::new(),
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(svs.subvolumes.is_empty());
}

#[tokio::test]
async fn user_lifecycle() {
    let h = Harness::new().await;
    let mut id = h.identity();

    let created = id
        .create_user(pb::CreateUserRequest {
            name: "alice".into(),
            display_name: "Alice".into(),
            password: "hunter2".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.name, "alice");
    assert!(!created.id.is_empty());

    // Duplicate fails with ALREADY_EXISTS.
    let err = id
        .create_user(pb::CreateUserRequest {
            name: "alice".into(),
            display_name: "A".into(),
            password: "x".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists, "{err:?}");

    // Fetch by name, then by id.
    let by_name = id
        .get_user(pb::GetUserRequest {
            id_or_name: "alice".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_name.id, created.id);
    let by_id = id
        .get_user(pb::GetUserRequest {
            id_or_name: created.id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_id.name, "alice");

    // Password rotation.
    id.set_user_password(pb::SetUserPasswordRequest {
        id: created.id.clone(),
        password: "newpw".into(),
    })
    .await
    .unwrap();
    assert!(h
        .svc
        .verify_user_password("alice", "newpw")
        .unwrap()
        .is_some());
    assert!(h
        .svc
        .verify_user_password("alice", "hunter2")
        .unwrap()
        .is_none());

    // Delete.
    id.delete_user(pb::DeleteUserRequest {
        id: created.id.clone(),
    })
    .await
    .unwrap();
    let err = id
        .get_user(pb::GetUserRequest {
            id_or_name: "alice".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn group_membership_lifecycle() {
    let h = Harness::new().await;
    let mut id = h.identity();

    let u1 = id
        .create_user(pb::CreateUserRequest {
            name: "alice".into(),
            display_name: "Alice".into(),
            password: "p".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let u2 = id
        .create_user(pb::CreateUserRequest {
            name: "bob".into(),
            display_name: "Bob".into(),
            password: "p".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let g = id
        .create_group(pb::CreateGroupRequest {
            name: "staff".into(),
            description: "".into(),
        })
        .await
        .unwrap()
        .into_inner();

    id.add_user_to_group(pb::AddUserToGroupRequest {
        user_id: u1.id.clone(),
        group_id: g.id.clone(),
    })
    .await
    .unwrap();
    id.add_user_to_group(pb::AddUserToGroupRequest {
        user_id: u2.id.clone(),
        group_id: g.id.clone(),
    })
    .await
    .unwrap();

    let listed = id
        .list_users(pb::ListUsersRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .users;
    assert_eq!(listed.len(), 2);
    for u in &listed {
        assert!(u.group_ids.contains(&g.id));
    }

    id.remove_user_from_group(pb::RemoveUserFromGroupRequest {
        user_id: u1.id.clone(),
        group_id: g.id.clone(),
    })
    .await
    .unwrap();

    let alice = id
        .get_user(pb::GetUserRequest {
            id_or_name: "alice".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(alice.group_ids.is_empty());
    let bob = id
        .get_user(pb::GetUserRequest {
            id_or_name: "bob".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(bob.group_ids.contains(&g.id));

    // Deleting the group should cascade membership.
    id.delete_group(pb::DeleteGroupRequest { id: g.id.clone() })
        .await
        .unwrap();
    let bob = id
        .get_user(pb::GetUserRequest {
            id_or_name: "bob".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(bob.group_ids.is_empty());
}

#[tokio::test]
async fn subvolume_lifecycle_with_acl() {
    let h = Harness::new().await;
    let mut id = h.identity();
    let mut st = h.storage();

    let alice = id
        .create_user(pb::CreateUserRequest {
            name: "alice".into(),
            display_name: "Alice".into(),
            password: "p".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let bob = id
        .create_user(pb::CreateUserRequest {
            name: "bob".into(),
            display_name: "Bob".into(),
            password: "p".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let readers = id
        .create_group(pb::CreateGroupRequest {
            name: "readers".into(),
            description: "".into(),
        })
        .await
        .unwrap()
        .into_inner();
    id.add_user_to_group(pb::AddUserToGroupRequest {
        user_id: bob.id.clone(),
        group_id: readers.id.clone(),
    })
    .await
    .unwrap();

    let sv = st
        .create_subvolume(pb::CreateSubvolumeRequest {
            name: "photos".into(),
            owner_user_id: alice.id.clone(),
            quota_bytes: 1024 * 1024,
            acl: None,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(sv.name, "photos");
    assert_eq!(sv.owner_user_id, alice.id);
    assert!(sv.mount_path.ends_with("photos"));

    // Disk layer did its thing.
    assert!(std::path::Path::new(&sv.mount_path).exists());

    // Quota change.
    let sv2 = st
        .set_quota(pb::SetQuotaRequest {
            id: sv.id.clone(),
            quota_bytes: 2 * 1024 * 1024,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(sv2.quota_bytes, 2 * 1024 * 1024);

    // Grant the readers group READ.
    let acl = pb::Acl {
        entries: vec![pb::AclEntry {
            principal_kind: pb::PrincipalKind::Group as i32,
            principal_id: readers.id.clone(),
            permissions: vec![pb::Permission::Read as i32, pb::Permission::List as i32],
        }],
    };
    st.set_acl(pb::SetAclRequest {
        subvolume_id: sv.id.clone(),
        acl: Some(acl),
    })
    .await
    .unwrap();

    let fetched_acl = st
        .get_acl(pb::GetAclRequest {
            subvolume_id: sv.id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched_acl.entries.len(), 1);
    let entry = &fetched_acl.entries[0];
    assert_eq!(entry.principal_kind, pb::PrincipalKind::Group as i32);
    assert_eq!(entry.principal_id, readers.id);
    assert_eq!(entry.permissions.len(), 2);

    // Bob (via group) can read, but not write.
    use bibliotheca_core::acl::Permission;
    use bibliotheca_core::identity::UserId;
    use bibliotheca_core::subvolume::SubvolumeId;
    let bob_id = UserId(uuid::Uuid::parse_str(&bob.id).unwrap());
    let sv_id = SubvolumeId(uuid::Uuid::parse_str(&sv.id).unwrap());
    assert!(h
        .svc
        .check_permission(sv_id, Some(bob_id), Permission::Read, false)
        .unwrap());
    assert!(!h
        .svc
        .check_permission(sv_id, Some(bob_id), Permission::Write, false)
        .unwrap());
    // Alice (owner) always passes.
    let alice_id = UserId(uuid::Uuid::parse_str(&alice.id).unwrap());
    assert!(h
        .svc
        .check_permission(sv_id, Some(alice_id), Permission::Admin, false)
        .unwrap());
    // Anonymous is denied even for Read because Public isn't in the ACL.
    assert!(!h
        .svc
        .check_permission(sv_id, None, Permission::Read, true)
        .unwrap());

    // Filter listing by owner.
    let by_owner = st
        .list_subvolumes(pb::ListSubvolumesRequest {
            owner_user_id: alice.id.clone(),
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .subvolumes;
    assert_eq!(by_owner.len(), 1);

    let other_owner = st
        .list_subvolumes(pb::ListSubvolumesRequest {
            owner_user_id: bob.id.clone(),
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .subvolumes;
    assert!(other_owner.is_empty());

    // Delete cleans up the directory.
    st.delete_subvolume(pb::DeleteSubvolumeRequest {
        id: sv.id.clone(),
        force: false,
    })
    .await
    .unwrap();
    assert!(!std::path::Path::new(&sv.mount_path).exists());
}

#[tokio::test]
async fn snapshot_flow() {
    let h = Harness::new().await;
    let mut id = h.identity();
    let mut st = h.storage();

    let alice = id
        .create_user(pb::CreateUserRequest {
            name: "alice".into(),
            display_name: "Alice".into(),
            password: "p".into(),
        })
        .await
        .unwrap()
        .into_inner();

    let sv = st
        .create_subvolume(pb::CreateSubvolumeRequest {
            name: "docs".into(),
            owner_user_id: alice.id.clone(),
            quota_bytes: 0,
            acl: None,
        })
        .await
        .unwrap()
        .into_inner();

    // Put a file under the subvolume so the snapshot copy has content
    // to reason about.
    let file = std::path::Path::new(&sv.mount_path).join("hello.txt");
    std::fs::write(&file, b"hi").unwrap();

    let snap = st
        .create_snapshot(pb::CreateSnapshotRequest {
            subvolume_id: sv.id.clone(),
            name: "first".into(),
            readonly: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(snap.name, "first");
    assert!(snap.readonly);
    assert!(std::path::Path::new(&snap.mount_path).exists());
    assert!(std::path::Path::new(&snap.mount_path)
        .join("hello.txt")
        .exists());

    let listed = st
        .list_snapshots(pb::ListSnapshotsRequest {
            subvolume_id: sv.id.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .snapshots;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, snap.id);

    // Deleting a subvolume with a snapshot requires force.
    let err = st
        .delete_subvolume(pb::DeleteSubvolumeRequest {
            id: sv.id.clone(),
            force: false,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Force deletion also cleans up snapshots.
    st.delete_subvolume(pb::DeleteSubvolumeRequest {
        id: sv.id.clone(),
        force: true,
    })
    .await
    .unwrap();
    assert!(!std::path::Path::new(&snap.mount_path).exists());
}

#[tokio::test]
async fn interfaces_list_is_empty() {
    // The runtime interface manager is intentionally a no-op for now;
    // the test locks that behaviour in so accidental changes blow up.
    let h = Harness::new().await;
    let mut client =
        bibliotheca_proto::v1::interfaces_client::InterfacesClient::new(h.channel.clone());
    let resp = client.list(()).await.unwrap().into_inner();
    assert!(resp.interfaces.is_empty());
}

#[tokio::test]
async fn ipfs_unimplemented_until_client_configured() {
    let h = Harness::new().await;
    let mut ipfs = h.ipfs();
    let err = ipfs
        .list_pins(pb::ListPinsRequest {
            subvolume_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}
