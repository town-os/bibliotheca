//! gRPC control plane bound to a Unix domain socket.
//!
//! This is the only authenticated surface that operators talk to:
//! filesystem permissions on the socket gate access. Each service
//! implementation is a thin adapter that translates protobuf into
//! [`BibliothecaService`] calls.

use std::collections::HashSet;
use std::path::PathBuf;

use bibliotheca_core::acl::{Acl, AclEntry, Permission, Principal};
use bibliotheca_core::error::Error;
use bibliotheca_core::identity::{GroupId, UserId};
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::subvolume::{SnapshotId, SubvolumeId};
use bibliotheca_proto::v1::identity_server::{Identity, IdentityServer};
use bibliotheca_proto::v1::interfaces_server::{Interfaces, InterfacesServer};
use bibliotheca_proto::v1::ipfs_server::{Ipfs, IpfsServer};
use bibliotheca_proto::v1::storage_server::{Storage, StorageServer};
use bibliotheca_proto::v1::{self as pb};
use prost_types::Timestamp;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::info;
use uuid::Uuid;

pub async fn serve(svc: BibliothecaService, socket: PathBuf) -> anyhow::Result<()> {
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    let stream = UnixListenerStream::new(listener);
    info!(socket = %socket.display(), "control plane listening");

    let identity = IdentitySvc { svc: svc.clone() };
    let storage = StorageSvc { svc: svc.clone() };
    let interfaces = InterfacesSvc {};
    let ipfs = IpfsSvc { svc };

    Server::builder()
        .add_service(IdentityServer::new(identity))
        .add_service(StorageServer::new(storage))
        .add_service(InterfacesServer::new(interfaces))
        .add_service(IpfsServer::new(ipfs))
        .serve_with_incoming(stream)
        .await?;
    Ok(())
}

// ---------- error mapping ----------

fn to_status(e: Error) -> Status {
    match e {
        Error::NotFound(m) => Status::not_found(m),
        Error::AlreadyExists(m) => Status::already_exists(m),
        Error::PermissionDenied => Status::permission_denied("denied"),
        Error::InvalidArgument(m) => Status::invalid_argument(m),
        other => Status::internal(other.to_string()),
    }
}

fn ts(t: time::OffsetDateTime) -> Timestamp {
    Timestamp {
        seconds: t.unix_timestamp(),
        nanos: t.nanosecond() as i32,
    }
}

fn parse_user_id(s: &str) -> Result<UserId, Status> {
    Uuid::parse_str(s)
        .map(UserId)
        .map_err(|_| Status::invalid_argument("user id"))
}

fn parse_group_id(s: &str) -> Result<GroupId, Status> {
    Uuid::parse_str(s)
        .map(GroupId)
        .map_err(|_| Status::invalid_argument("group id"))
}

fn parse_sv_id(s: &str) -> Result<SubvolumeId, Status> {
    Uuid::parse_str(s)
        .map(SubvolumeId)
        .map_err(|_| Status::invalid_argument("subvolume id"))
}

fn parse_snap_id(s: &str) -> Result<SnapshotId, Status> {
    Uuid::parse_str(s)
        .map(SnapshotId)
        .map_err(|_| Status::invalid_argument("snapshot id"))
}

// ---------- proto <-> domain ----------

fn user_to_pb(u: bibliotheca_core::identity::User, group_ids: Vec<GroupId>) -> pb::User {
    pb::User {
        id: u.id.to_string(),
        name: u.name,
        display_name: u.display_name,
        group_ids: group_ids.into_iter().map(|g| g.to_string()).collect(),
        created_at: Some(ts(u.created_at)),
        disabled: u.disabled,
    }
}

fn group_to_pb(g: bibliotheca_core::identity::Group) -> pb::Group {
    pb::Group {
        id: g.id.to_string(),
        name: g.name,
        description: g.description,
        created_at: Some(ts(g.created_at)),
    }
}

fn permission_from_pb(p: i32) -> Option<Permission> {
    match pb::Permission::try_from(p).ok()? {
        pb::Permission::Unspecified => None,
        pb::Permission::Read => Some(Permission::Read),
        pb::Permission::Write => Some(Permission::Write),
        pb::Permission::List => Some(Permission::List),
        pb::Permission::Delete => Some(Permission::Delete),
        pb::Permission::Admin => Some(Permission::Admin),
    }
}

fn permission_to_pb(p: Permission) -> i32 {
    match p {
        Permission::Read => pb::Permission::Read as i32,
        Permission::Write => pb::Permission::Write as i32,
        Permission::List => pb::Permission::List as i32,
        Permission::Delete => pb::Permission::Delete as i32,
        Permission::Admin => pb::Permission::Admin as i32,
    }
}

fn principal_from_pb(kind: i32, id: &str) -> Result<Principal, Status> {
    match pb::PrincipalKind::try_from(kind).unwrap_or(pb::PrincipalKind::Unspecified) {
        pb::PrincipalKind::User => Ok(Principal::User(parse_user_id(id)?)),
        pb::PrincipalKind::Group => Ok(Principal::Group(parse_group_id(id)?)),
        pb::PrincipalKind::Public => Ok(Principal::Public),
        pb::PrincipalKind::Unspecified => Err(Status::invalid_argument("principal kind")),
    }
}

fn principal_to_pb(p: &Principal) -> (i32, String) {
    match p {
        Principal::User(u) => (pb::PrincipalKind::User as i32, u.to_string()),
        Principal::Group(g) => (pb::PrincipalKind::Group as i32, g.to_string()),
        Principal::Public => (pb::PrincipalKind::Public as i32, String::new()),
    }
}

fn acl_from_pb(acl: Option<pb::Acl>) -> Result<Acl, Status> {
    let Some(acl) = acl else {
        return Ok(Acl::new());
    };
    let mut out = Acl::new();
    for entry in acl.entries {
        let principal = principal_from_pb(entry.principal_kind, &entry.principal_id)?;
        let mut perms: HashSet<Permission> = HashSet::new();
        for p in entry.permissions {
            if let Some(perm) = permission_from_pb(p) {
                perms.insert(perm);
            }
        }
        out.entries.push(AclEntry {
            principal,
            permissions: perms,
        });
    }
    Ok(out)
}

fn acl_to_pb(acl: &Acl) -> pb::Acl {
    pb::Acl {
        entries: acl
            .entries
            .iter()
            .map(|e| {
                let (kind, id) = principal_to_pb(&e.principal);
                pb::AclEntry {
                    principal_kind: kind,
                    principal_id: id,
                    permissions: e
                        .permissions
                        .iter()
                        .copied()
                        .map(permission_to_pb)
                        .collect(),
                }
            })
            .collect(),
    }
}

fn subvolume_to_pb(sv: bibliotheca_core::subvolume::Subvolume) -> pb::Subvolume {
    pb::Subvolume {
        id: sv.id.to_string(),
        name: sv.name,
        owner_user_id: sv.owner.to_string(),
        mount_path: sv.mount_path.display().to_string(),
        quota_bytes: sv.quota_bytes,
        acl: Some(acl_to_pb(&sv.acl)),
        created_at: Some(ts(sv.created_at)),
    }
}

fn snapshot_to_pb(s: bibliotheca_core::subvolume::Snapshot) -> pb::Snapshot {
    pb::Snapshot {
        id: s.id.0.to_string(),
        subvolume_id: s.subvolume.to_string(),
        name: s.name,
        mount_path: s.mount_path.display().to_string(),
        readonly: s.readonly,
        created_at: Some(ts(s.created_at)),
    }
}

// ---------- Identity ----------

pub struct IdentitySvc {
    svc: BibliothecaService,
}

#[tonic::async_trait]
impl Identity for IdentitySvc {
    async fn create_user(
        &self,
        req: Request<pb::CreateUserRequest>,
    ) -> Result<Response<pb::User>, Status> {
        let r = req.into_inner();
        let u = self
            .svc
            .create_user(&r.name, &r.display_name, &r.password)
            .map_err(to_status)?;
        Ok(Response::new(user_to_pb(u, vec![])))
    }

    async fn get_user(
        &self,
        req: Request<pb::GetUserRequest>,
    ) -> Result<Response<pb::User>, Status> {
        let r = req.into_inner();
        let u = self.svc.get_user(&r.id_or_name).map_err(to_status)?;
        let groups = self
            .svc
            .store()
            .group_ids_for_user(u.id)
            .map_err(to_status)?;
        Ok(Response::new(user_to_pb(u, groups)))
    }

    async fn list_users(
        &self,
        req: Request<pb::ListUsersRequest>,
    ) -> Result<Response<pb::ListUsersResponse>, Status> {
        let r = req.into_inner();
        let users = self.svc.list_users(r.limit, r.offset).map_err(to_status)?;
        let mut out = Vec::with_capacity(users.len());
        for u in users {
            let groups = self
                .svc
                .store()
                .group_ids_for_user(u.id)
                .map_err(to_status)?;
            out.push(user_to_pb(u, groups));
        }
        Ok(Response::new(pb::ListUsersResponse { users: out }))
    }

    async fn delete_user(
        &self,
        req: Request<pb::DeleteUserRequest>,
    ) -> Result<Response<()>, Status> {
        let id = parse_user_id(&req.into_inner().id)?;
        self.svc.delete_user(id).map_err(to_status)?;
        Ok(Response::new(()))
    }

    async fn set_user_password(
        &self,
        req: Request<pb::SetUserPasswordRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        let id = parse_user_id(&r.id)?;
        self.svc
            .set_user_password(id, &r.password)
            .map_err(to_status)?;
        Ok(Response::new(()))
    }

    async fn create_group(
        &self,
        req: Request<pb::CreateGroupRequest>,
    ) -> Result<Response<pb::Group>, Status> {
        let r = req.into_inner();
        let g = self
            .svc
            .create_group(&r.name, &r.description)
            .map_err(to_status)?;
        Ok(Response::new(group_to_pb(g)))
    }

    async fn get_group(
        &self,
        req: Request<pb::GetGroupRequest>,
    ) -> Result<Response<pb::Group>, Status> {
        let r = req.into_inner();
        let g = self.svc.get_group(&r.id_or_name).map_err(to_status)?;
        Ok(Response::new(group_to_pb(g)))
    }

    async fn list_groups(
        &self,
        req: Request<pb::ListGroupsRequest>,
    ) -> Result<Response<pb::ListGroupsResponse>, Status> {
        let r = req.into_inner();
        let groups = self.svc.list_groups(r.limit, r.offset).map_err(to_status)?;
        Ok(Response::new(pb::ListGroupsResponse {
            groups: groups.into_iter().map(group_to_pb).collect(),
        }))
    }

    async fn delete_group(
        &self,
        req: Request<pb::DeleteGroupRequest>,
    ) -> Result<Response<()>, Status> {
        let id = parse_group_id(&req.into_inner().id)?;
        self.svc.delete_group(id).map_err(to_status)?;
        Ok(Response::new(()))
    }

    async fn add_user_to_group(
        &self,
        req: Request<pb::AddUserToGroupRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        self.svc
            .add_user_to_group(parse_user_id(&r.user_id)?, parse_group_id(&r.group_id)?)
            .map_err(to_status)?;
        Ok(Response::new(()))
    }

    async fn remove_user_from_group(
        &self,
        req: Request<pb::RemoveUserFromGroupRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        self.svc
            .remove_user_from_group(parse_user_id(&r.user_id)?, parse_group_id(&r.group_id)?)
            .map_err(to_status)?;
        Ok(Response::new(()))
    }
}

// ---------- Storage ----------

pub struct StorageSvc {
    svc: BibliothecaService,
}

#[tonic::async_trait]
impl Storage for StorageSvc {
    async fn create_subvolume(
        &self,
        req: Request<pb::CreateSubvolumeRequest>,
    ) -> Result<Response<pb::Subvolume>, Status> {
        let r = req.into_inner();
        let owner = parse_user_id(&r.owner_user_id)?;
        let acl = if r.acl.is_some() {
            Some(acl_from_pb(r.acl)?)
        } else {
            None
        };
        let sv = self
            .svc
            .create_subvolume(&r.name, owner, r.quota_bytes, acl)
            .await
            .map_err(to_status)?;
        Ok(Response::new(subvolume_to_pb(sv)))
    }

    async fn get_subvolume(
        &self,
        req: Request<pb::GetSubvolumeRequest>,
    ) -> Result<Response<pb::Subvolume>, Status> {
        let r = req.into_inner();
        let sv = self.svc.get_subvolume(&r.id_or_name).map_err(to_status)?;
        Ok(Response::new(subvolume_to_pb(sv)))
    }

    async fn list_subvolumes(
        &self,
        req: Request<pb::ListSubvolumesRequest>,
    ) -> Result<Response<pb::ListSubvolumesResponse>, Status> {
        let r = req.into_inner();
        let owner = if r.owner_user_id.is_empty() {
            None
        } else {
            Some(parse_user_id(&r.owner_user_id)?)
        };
        let svs = self
            .svc
            .list_subvolumes(owner, r.limit, r.offset)
            .map_err(to_status)?;
        Ok(Response::new(pb::ListSubvolumesResponse {
            subvolumes: svs.into_iter().map(subvolume_to_pb).collect(),
        }))
    }

    async fn delete_subvolume(
        &self,
        req: Request<pb::DeleteSubvolumeRequest>,
    ) -> Result<Response<()>, Status> {
        let r = req.into_inner();
        let id = parse_sv_id(&r.id)?;
        self.svc
            .delete_subvolume(id, r.force)
            .await
            .map_err(to_status)?;
        Ok(Response::new(()))
    }

    async fn set_quota(
        &self,
        req: Request<pb::SetQuotaRequest>,
    ) -> Result<Response<pb::Subvolume>, Status> {
        let r = req.into_inner();
        let sv = self
            .svc
            .set_quota(parse_sv_id(&r.id)?, r.quota_bytes)
            .await
            .map_err(to_status)?;
        Ok(Response::new(subvolume_to_pb(sv)))
    }

    async fn set_acl(
        &self,
        req: Request<pb::SetAclRequest>,
    ) -> Result<Response<pb::Subvolume>, Status> {
        let r = req.into_inner();
        let acl = acl_from_pb(r.acl)?;
        let sv = self
            .svc
            .set_acl(parse_sv_id(&r.subvolume_id)?, &acl)
            .map_err(to_status)?;
        Ok(Response::new(subvolume_to_pb(sv)))
    }

    async fn get_acl(&self, req: Request<pb::GetAclRequest>) -> Result<Response<pb::Acl>, Status> {
        let r = req.into_inner();
        let sv = self
            .svc
            .store()
            .get_subvolume(parse_sv_id(&r.subvolume_id)?)
            .map_err(to_status)?;
        Ok(Response::new(acl_to_pb(&sv.acl)))
    }

    async fn create_snapshot(
        &self,
        req: Request<pb::CreateSnapshotRequest>,
    ) -> Result<Response<pb::Snapshot>, Status> {
        let r = req.into_inner();
        let snap = self
            .svc
            .create_snapshot(parse_sv_id(&r.subvolume_id)?, &r.name, r.readonly)
            .await
            .map_err(to_status)?;
        Ok(Response::new(snapshot_to_pb(snap)))
    }

    async fn list_snapshots(
        &self,
        req: Request<pb::ListSnapshotsRequest>,
    ) -> Result<Response<pb::ListSnapshotsResponse>, Status> {
        let r = req.into_inner();
        let snaps = self
            .svc
            .list_snapshots(parse_sv_id(&r.subvolume_id)?)
            .map_err(to_status)?;
        Ok(Response::new(pb::ListSnapshotsResponse {
            snapshots: snaps.into_iter().map(snapshot_to_pb).collect(),
        }))
    }

    async fn delete_snapshot(
        &self,
        req: Request<pb::DeleteSnapshotRequest>,
    ) -> Result<Response<()>, Status> {
        let id = parse_snap_id(&req.into_inner().id)?;
        self.svc.delete_snapshot(id).await.map_err(to_status)?;
        Ok(Response::new(()))
    }
}

// ---------- Interfaces (currently view-only — runtime config lives in
// the JSON file passed to the daemon) ----------

pub struct InterfacesSvc;

#[tonic::async_trait]
impl Interfaces for InterfacesSvc {
    async fn get(
        &self,
        _req: Request<pb::GetInterfaceRequest>,
    ) -> Result<Response<pb::InterfaceConfig>, Status> {
        Err(Status::unimplemented(
            "dynamic interface mgmt not yet wired",
        ))
    }
    async fn list(
        &self,
        _req: Request<()>,
    ) -> Result<Response<pb::ListInterfacesResponse>, Status> {
        Ok(Response::new(pb::ListInterfacesResponse {
            interfaces: vec![],
        }))
    }
    async fn configure(
        &self,
        _req: Request<pb::InterfaceConfig>,
    ) -> Result<Response<pb::InterfaceConfig>, Status> {
        Err(Status::unimplemented(
            "dynamic interface mgmt not yet wired",
        ))
    }
    async fn enable(
        &self,
        _req: Request<pb::EnableInterfaceRequest>,
    ) -> Result<Response<pb::InterfaceConfig>, Status> {
        Err(Status::unimplemented(
            "dynamic interface mgmt not yet wired",
        ))
    }
    async fn disable(
        &self,
        _req: Request<pb::DisableInterfaceRequest>,
    ) -> Result<Response<pb::InterfaceConfig>, Status> {
        Err(Status::unimplemented(
            "dynamic interface mgmt not yet wired",
        ))
    }
}

// ---------- IPFS ----------

pub struct IpfsSvc {
    svc: BibliothecaService,
}

#[tonic::async_trait]
impl Ipfs for IpfsSvc {
    async fn pin(
        &self,
        _req: Request<pb::PinRequest>,
    ) -> Result<Response<pb::PinResponse>, Status> {
        // Wired up once the operator has configured a Kubo endpoint —
        // see bibliotheca-ipfs::IpfsService.
        Err(Status::unimplemented("ipfs client not configured"))
    }
    async fn unpin(&self, _req: Request<pb::UnpinRequest>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("ipfs client not configured"))
    }
    async fn import(
        &self,
        _req: Request<pb::ImportRequest>,
    ) -> Result<Response<pb::ImportResponse>, Status> {
        Err(Status::unimplemented("ipfs client not configured"))
    }
    async fn export(
        &self,
        _req: Request<pb::ExportRequest>,
    ) -> Result<Response<pb::ExportResponse>, Status> {
        let _ = &self.svc; // keep the field used until wired
        Err(Status::unimplemented("ipfs client not configured"))
    }
    async fn list_pins(
        &self,
        _req: Request<pb::ListPinsRequest>,
    ) -> Result<Response<pb::ListPinsResponse>, Status> {
        Err(Status::unimplemented("ipfs client not configured"))
    }
}
