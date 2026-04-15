//! gRPC control plane bound to a Unix domain socket.
//!
//! This is the only authenticated surface that operators talk to:
//! filesystem permissions on the socket gate access. Each service
//! implementation is a thin adapter that translates protobuf into
//! [`BibliothecaService`] calls.

use std::collections::HashSet;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use bibliotheca_anisette::AnisetteProvider;
use bibliotheca_archive::{
    Archive as CoreArchive, ArchiveKind, ArchiveService, CreateArchiveParams as ArchiveCreateParams,
};
use bibliotheca_config::ShareConfig;
use bibliotheca_core::acl::{Acl, AclEntry, Permission, Principal};
use bibliotheca_core::error::Error;
use bibliotheca_core::identity::{GroupId, UserId};
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::share::{CreateShareParams, ShareGrant as CoreShareGrant, ShareId};
use bibliotheca_core::store::SubvolumePolicyRow;
use bibliotheca_core::subvolume::{SnapshotId, SubvolumeId};
use bibliotheca_proto::v1::anisette_admin_server::{AnisetteAdmin, AnisetteAdminServer};
use bibliotheca_proto::v1::archives_server::{Archives, ArchivesServer};
use bibliotheca_proto::v1::identity_server::{Identity, IdentityServer};
use bibliotheca_proto::v1::interfaces_server::{Interfaces, InterfacesServer};
use bibliotheca_proto::v1::ipfs_server::{Ipfs, IpfsServer};
use bibliotheca_proto::v1::sharing_server::{Sharing, SharingServer};
use bibliotheca_proto::v1::storage_server::{Storage, StorageServer};
use bibliotheca_proto::v1::sync_admin_server::{SyncAdmin, SyncAdminServer};
use bibliotheca_proto::v1::{self as pb};
use bibliotheca_sync_core::{
    ConnectorKind, CredentialBlob, Direction, MountId, MountSpec, Supervisor, SyncMount,
};
use futures::Stream;
use prost_types::Timestamp;
use rand::RngCore;
use time::OffsetDateTime;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::info;
use uuid::Uuid;

pub async fn serve(
    svc: BibliothecaService,
    supervisor: Option<Arc<Supervisor>>,
    anisette: Option<(Arc<dyn AnisetteProvider>, String)>,
    share_cfg: ShareConfig,
    archive: Option<Arc<ArchiveService>>,
    socket: PathBuf,
) -> anyhow::Result<()> {
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    let stream = UnixListenerStream::new(listener);
    info!(socket = %socket.display(), "control plane listening");

    let identity = IdentitySvc { svc: svc.clone() };
    let storage = StorageSvc { svc: svc.clone() };
    let interfaces = InterfacesSvc {};
    let ipfs = IpfsSvc { svc: svc.clone() };
    let sync = SyncAdminSvc {
        supervisor: supervisor.clone(),
    };
    let sharing = SharingSvc {
        svc: svc.clone(),
        cfg: share_cfg,
    };
    let archives_svc = ArchivesSvc {
        archive: archive.clone(),
    };
    let anisette_admin = AnisetteAdminSvc { provider: anisette };

    Server::builder()
        .add_service(IdentityServer::new(identity))
        .add_service(StorageServer::new(storage))
        .add_service(InterfacesServer::new(interfaces))
        .add_service(IpfsServer::new(ipfs))
        .add_service(SyncAdminServer::new(sync))
        .add_service(SharingServer::new(sharing))
        .add_service(ArchivesServer::new(archives_svc))
        .add_service(AnisetteAdminServer::new(anisette_admin))
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

// ---------- SyncAdmin ----------

pub struct SyncAdminSvc {
    supervisor: Option<Arc<Supervisor>>,
}

impl SyncAdminSvc {
    fn require(&self) -> Result<&Supervisor, Status> {
        match self.supervisor.as_deref() {
            Some(s) if s.is_enabled() => Ok(s),
            Some(_) => Err(Status::unavailable(
                "sync subsystem disabled: no secret key or town-os config",
            )),
            None => Err(Status::unavailable(
                "sync subsystem disabled: supervisor not constructed",
            )),
        }
    }
}

fn sync_err(e: bibliotheca_sync_core::Error) -> Status {
    use bibliotheca_sync_core::Error as E;
    match e {
        E::NotFound(m) => Status::not_found(m),
        E::AlreadyExists(m) => Status::already_exists(m),
        E::InvalidArgument(m) => Status::invalid_argument(m),
        E::PermissionDenied => Status::permission_denied("denied"),
        E::SyncDisabled(m) => Status::unavailable(m),
        E::UnknownConnector(m) => Status::unimplemented(format!("connector: {m}")),
        E::NeedsTwoFactor => Status::failed_precondition("two-factor required"),
        E::QuotaExceeded => Status::resource_exhausted("quota exceeded"),
        E::Core(c) => to_status(c),
        other => Status::internal(other.to_string()),
    }
}

fn mount_to_pb(m: &SyncMount) -> pb::SyncMount {
    pb::SyncMount {
        id: m.id.to_string(),
        name: m.name.clone(),
        kind: connector_kind_to_pb(m.kind) as i32,
        subvolume_id: m.subvolume_id.to_string(),
        townos_name: m.townos_name.clone(),
        direction: direction_to_pb(m.direction) as i32,
        interval_secs: m.interval_secs,
        quota_bytes: m.quota_bytes,
        enabled: m.enabled,
        paused: m.paused,
        last_sync_at: m.last_sync_at.map(ts),
        last_error: m.last_error.clone().unwrap_or_default(),
        created_at: Some(ts(m.created_at)),
        config: parse_config_map(&m.config_json),
    }
}

fn parse_config_map(s: &str) -> std::collections::HashMap<String, String> {
    serde_json::from_str(s).unwrap_or_default()
}

fn connector_kind_from_pb(k: i32) -> Result<ConnectorKind, Status> {
    Ok(
        match pb::SyncConnectorKind::try_from(k).map_err(|_| Status::invalid_argument("kind"))? {
            pb::SyncConnectorKind::SyncConnectorUnspecified => {
                return Err(Status::invalid_argument("connector kind unspecified"))
            }
            pb::SyncConnectorKind::SyncConnectorIcloudPhotos => ConnectorKind::ICloudPhotos,
            pb::SyncConnectorKind::SyncConnectorDropbox => ConnectorKind::Dropbox,
            pb::SyncConnectorKind::SyncConnectorNextcloud => ConnectorKind::Nextcloud,
            pb::SyncConnectorKind::SyncConnectorSolid => ConnectorKind::Solid,
            pb::SyncConnectorKind::SyncConnectorGooglePhotos => ConnectorKind::GooglePhotos,
            pb::SyncConnectorKind::SyncConnectorIpfs => ConnectorKind::Ipfs,
        },
    )
}

fn connector_kind_to_pb(k: ConnectorKind) -> pb::SyncConnectorKind {
    match k {
        ConnectorKind::ICloudPhotos => pb::SyncConnectorKind::SyncConnectorIcloudPhotos,
        ConnectorKind::Dropbox => pb::SyncConnectorKind::SyncConnectorDropbox,
        ConnectorKind::Nextcloud => pb::SyncConnectorKind::SyncConnectorNextcloud,
        ConnectorKind::Solid => pb::SyncConnectorKind::SyncConnectorSolid,
        ConnectorKind::GooglePhotos => pb::SyncConnectorKind::SyncConnectorGooglePhotos,
        ConnectorKind::Ipfs => pb::SyncConnectorKind::SyncConnectorIpfs,
    }
}

fn direction_from_pb(d: i32) -> Result<Direction, Status> {
    Ok(
        match pb::SyncDirection::try_from(d).map_err(|_| Status::invalid_argument("direction"))? {
            pb::SyncDirection::Unspecified => Direction::Pull,
            pb::SyncDirection::Pull => Direction::Pull,
            pb::SyncDirection::Push => Direction::Push,
            pb::SyncDirection::Both => Direction::Both,
        },
    )
}

fn direction_to_pb(d: Direction) -> pb::SyncDirection {
    match d {
        Direction::Pull => pb::SyncDirection::Pull,
        Direction::Push => pb::SyncDirection::Push,
        Direction::Both => pb::SyncDirection::Both,
    }
}

fn credentials_from_pb(
    creds: Option<pb::create_mount_request::Credentials>,
) -> Result<CredentialBlob, Status> {
    use pb::create_mount_request::Credentials as C;
    match creds.ok_or_else(|| Status::invalid_argument("missing credentials"))? {
        C::Oauth2(o) => Ok(CredentialBlob::OAuth2 {
            access_token: o.access_token,
            refresh_token: o.refresh_token,
            expires_at: o.expires_at,
            client_id: o.client_id,
            client_secret: o.client_secret,
            token_url: o.token_url,
        }),
        C::Basic(b) => Ok(CredentialBlob::Basic {
            username: b.username,
            password: b.password,
        }),
        C::Token(t) => Ok(CredentialBlob::Token {
            token: t.token,
            refresh_token: if t.refresh_token.is_empty() {
                None
            } else {
                Some(t.refresh_token)
            },
            expires_at: if t.expires_at == 0 {
                None
            } else {
                Some(t.expires_at)
            },
        }),
        C::Icloud(i) => Ok(CredentialBlob::ICloud {
            apple_id: i.apple_id,
            password: i.password,
            trust_token: None,
            session_cookies: Vec::new(),
            anisette_url: i.anisette_url,
        }),
        C::Ipfs(i) => Ok(CredentialBlob::Ipfs {
            api_url: i.api_url,
            auth_header: if i.auth_header.is_empty() {
                None
            } else {
                Some(i.auth_header)
            },
        }),
    }
}

fn parse_mount_id(s: &str) -> Result<MountId, Status> {
    Uuid::parse_str(s)
        .map(MountId)
        .map_err(|_| Status::invalid_argument("mount id"))
}

type TailStream = Pin<Box<dyn Stream<Item = Result<pb::SyncEvent, Status>> + Send>>;

#[tonic::async_trait]
impl SyncAdmin for SyncAdminSvc {
    async fn create_mount(
        &self,
        req: Request<pb::CreateMountRequest>,
    ) -> Result<Response<pb::SyncMount>, Status> {
        let sup = self.require()?;
        let r = req.into_inner();
        let kind = connector_kind_from_pb(r.kind)?;
        let direction = direction_from_pb(r.direction)?;
        let owner = parse_user_id(&r.owner_user_id)?;
        let config_json = serde_json::to_string(&r.config)
            .map_err(|e| Status::invalid_argument(format!("config: {e}")))?;
        let spec = MountSpec {
            name: r.name,
            kind,
            direction,
            interval_secs: if r.interval_secs == 0 {
                300
            } else {
                r.interval_secs
            },
            quota_bytes: r.quota_bytes,
            owner,
            config_json,
            credentials_id: None,
        };
        let mount = match (r.credentials, r.existing_credentials_id.as_str()) {
            (Some(_), id) if !id.is_empty() => {
                return Err(Status::invalid_argument(
                    "credentials and existing_credentials_id are mutually exclusive",
                ));
            }
            (Some(creds), _) => {
                let blob = credentials_from_pb(Some(creds))?;
                sup.create_mount(spec, blob).await.map_err(sync_err)?
            }
            (None, id) if !id.is_empty() => sup
                .create_mount_with_existing_credentials(spec, id.to_string())
                .await
                .map_err(sync_err)?,
            (None, _) => {
                return Err(Status::invalid_argument("missing credentials"));
            }
        };
        Ok(Response::new(mount_to_pb(&mount)))
    }

    async fn store_o_auth_credentials(
        &self,
        req: Request<pb::StoreOAuthCredentialsRequest>,
    ) -> Result<Response<pb::StoreOAuthCredentialsResponse>, Status> {
        let sup = self.require()?;
        let r = req.into_inner();
        let creds = r
            .credentials
            .ok_or_else(|| Status::invalid_argument("missing credentials"))?;
        let blob = CredentialBlob::OAuth2 {
            access_token: creds.access_token,
            refresh_token: creds.refresh_token,
            expires_at: creds.expires_at,
            client_id: creds.client_id,
            client_secret: creds.client_secret,
            token_url: creds.token_url,
        };
        let id = sup.store_credentials(&blob).map_err(sync_err)?;
        Ok(Response::new(pb::StoreOAuthCredentialsResponse {
            credentials_id: id,
        }))
    }

    async fn list_mounts(
        &self,
        _req: Request<()>,
    ) -> Result<Response<pb::ListMountsResponse>, Status> {
        let sup = self.require()?;
        let mounts = sup.state().list_mounts().map_err(sync_err)?;
        Ok(Response::new(pb::ListMountsResponse {
            mounts: mounts.iter().map(mount_to_pb).collect(),
        }))
    }

    async fn get_mount(
        &self,
        req: Request<pb::GetMountRequest>,
    ) -> Result<Response<pb::SyncMount>, Status> {
        let sup = self.require()?;
        let r = req.into_inner();
        let mount = if let Ok(id) = Uuid::parse_str(&r.id_or_name) {
            sup.state().get_mount(MountId(id)).map_err(sync_err)?
        } else {
            sup.state()
                .get_mount_by_name(&r.id_or_name)
                .map_err(sync_err)?
        };
        Ok(Response::new(mount_to_pb(&mount)))
    }

    async fn update_mount(
        &self,
        req: Request<pb::UpdateMountRequest>,
    ) -> Result<Response<pb::SyncMount>, Status> {
        let sup = self.require()?;
        let r = req.into_inner();
        let id = parse_mount_id(&r.id)?;
        if let Some(q) = r.quota_bytes {
            sup.update_quota(id, q).await.map_err(sync_err)?;
        }
        if let Some(i) = r.interval_secs {
            sup.update_interval(id, i).await.map_err(sync_err)?;
        }
        if let Some(d) = r.direction {
            let direction = direction_from_pb(d)?;
            sup.update_direction(id, direction)
                .await
                .map_err(sync_err)?;
        }
        let mount = sup.state().get_mount(id).map_err(sync_err)?;
        Ok(Response::new(mount_to_pb(&mount)))
    }

    async fn delete_mount(
        &self,
        req: Request<pb::DeleteMountRequest>,
    ) -> Result<Response<()>, Status> {
        let sup = self.require()?;
        let id = parse_mount_id(&req.into_inner().id)?;
        sup.delete_mount(id).await.map_err(sync_err)?;
        Ok(Response::new(()))
    }

    async fn pause(
        &self,
        req: Request<pb::MountIdRequest>,
    ) -> Result<Response<pb::SyncMount>, Status> {
        let sup = self.require()?;
        let id = parse_mount_id(&req.into_inner().id)?;
        let mount = sup.pause(id).await.map_err(sync_err)?;
        Ok(Response::new(mount_to_pb(&mount)))
    }

    async fn resume(
        &self,
        req: Request<pb::MountIdRequest>,
    ) -> Result<Response<pb::SyncMount>, Status> {
        let sup = self.require()?;
        let id = parse_mount_id(&req.into_inner().id)?;
        let mount = sup.resume(id).await.map_err(sync_err)?;
        Ok(Response::new(mount_to_pb(&mount)))
    }

    async fn trigger_sync(&self, req: Request<pb::MountIdRequest>) -> Result<Response<()>, Status> {
        let sup = self.require()?;
        let id = parse_mount_id(&req.into_inner().id)?;
        sup.trigger_sync(id).await.map_err(sync_err)?;
        Ok(Response::new(()))
    }

    async fn submit_two_factor_code(
        &self,
        req: Request<pb::SubmitTwoFactorCodeRequest>,
    ) -> Result<Response<()>, Status> {
        let sup = self.require()?;
        let r = req.into_inner();
        let id = parse_mount_id(&r.id)?;
        sup.submit_twofactor(id, r.code).map_err(sync_err)?;
        Ok(Response::new(()))
    }

    type TailEventsStream = TailStream;

    async fn tail_events(
        &self,
        req: Request<pb::TailEventsRequest>,
    ) -> Result<Response<Self::TailEventsStream>, Status> {
        let sup = self.require()?;
        let r = req.into_inner();
        let mut rx = sup.events();
        let mount_filter = if r.mount_id.is_empty() {
            None
        } else {
            Some(parse_mount_id(&r.mount_id)?)
        };
        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if let Some(f) = mount_filter {
                            if ev.mount_id != f {
                                continue;
                            }
                        }
                        let details = match ev.details.clone() {
                            serde_json::Value::Object(m) => m
                                .into_iter()
                                .map(|(k, v)| (k, v.to_string()))
                                .collect(),
                            _ => Default::default(),
                        };
                        yield Ok(pb::SyncEvent {
                            mount_id: ev.mount_id.to_string(),
                            ts: Some(ts(ev.ts)),
                            level: ev.level.as_wire().to_string(),
                            kind: ev.kind,
                            message: ev.message,
                            details,
                        });
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn rotate_secret_key(
        &self,
        req: Request<pb::RotateSecretKeyRequest>,
    ) -> Result<Response<()>, Status> {
        let sup = self.require()?;
        let n = sup
            .rotate_master_key(&req.into_inner().new_hex_key)
            .await
            .map_err(sync_err)?;
        info!(rotated = n, "sync secret key rotated");
        Ok(Response::new(()))
    }
}

// ---------- Sharing ----------

pub struct SharingSvc {
    svc: BibliothecaService,
    cfg: ShareConfig,
}

impl SharingSvc {
    fn mint_token(&self) -> String {
        let bytes = self.cfg.token_bytes.clamp(16, 128);
        let mut buf = vec![0u8; bytes];
        rand::thread_rng().fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
    }

    fn resolve_ttl(&self, requested: u64) -> Result<Option<OffsetDateTime>, Status> {
        let effective = if requested > 0 {
            Some(requested)
        } else {
            self.cfg.default_ttl_secs
        };
        let Some(secs) = effective else {
            return Ok(None);
        };
        if let Some(max) = self.cfg.max_ttl_secs {
            if secs > max {
                return Err(Status::invalid_argument(format!(
                    "ttl_secs={secs} exceeds daemon max of {max}"
                )));
            }
        }
        let exp = OffsetDateTime::now_utc() + time::Duration::seconds(secs as i64);
        Ok(Some(exp))
    }

    fn resolve_use_limit(&self, requested: u64) -> Option<u64> {
        if requested > 0 {
            Some(requested)
        } else {
            self.cfg.default_use_limit
        }
    }

    fn build_url(&self, token: &str) -> String {
        match &self.cfg.base_url {
            Some(base) => {
                let base = base.as_str().trim_end_matches('/');
                format!("{base}/s/{token}")
            }
            None => String::new(),
        }
    }
}

fn share_grant_to_pb(g: &CoreShareGrant) -> pb::ShareGrant {
    pb::ShareGrant {
        id: g.id.to_string(),
        token: g.token.clone(),
        subvolume_id: g.subvolume_id.to_string(),
        key: g.key.clone().unwrap_or_default(),
        created_by: g.created_by.to_string(),
        created_at: Some(ts(g.created_at)),
        expires_at: g.expires_at.map(|t| t.unix_timestamp()).unwrap_or(0),
        use_limit: g.use_limit.unwrap_or(0),
        uses: g.uses,
        revoked: g.revoked,
        note: g.note.clone(),
    }
}

fn parse_share_id(s: &str) -> Result<ShareId, Status> {
    Uuid::parse_str(s)
        .map(ShareId)
        .map_err(|_| Status::invalid_argument("share id"))
}

#[tonic::async_trait]
impl Sharing for SharingSvc {
    async fn create(
        &self,
        req: Request<pb::CreateShareRequest>,
    ) -> Result<Response<pb::CreateShareResponse>, Status> {
        let r = req.into_inner();
        let sv = if let Ok(uuid) = Uuid::parse_str(&r.subvolume_id) {
            self.svc
                .get_subvolume(&uuid.to_string())
                .map_err(to_status)?
        } else {
            self.svc.get_subvolume(&r.subvolume_id).map_err(to_status)?
        };
        let owner = parse_user_id(&r.created_by)?;
        let expires = self.resolve_ttl(r.ttl_secs)?;
        let use_limit = self.resolve_use_limit(r.use_limit);
        let token = self.mint_token();
        let params = CreateShareParams {
            subvolume_id: sv.id,
            created_by: owner,
            key: if r.key.is_empty() { None } else { Some(r.key) },
            expires_at: expires,
            use_limit,
            note: r.note,
        };
        let grant = self
            .svc
            .create_share(params, token.clone())
            .map_err(to_status)?;
        let url = self.build_url(&token);
        Ok(Response::new(pb::CreateShareResponse {
            grant: Some(share_grant_to_pb(&grant)),
            url,
        }))
    }

    async fn list(
        &self,
        req: Request<pb::ListSharesRequest>,
    ) -> Result<Response<pb::ListSharesResponse>, Status> {
        let r = req.into_inner();
        let sv = if r.subvolume_id.is_empty() {
            None
        } else {
            let s = self.svc.get_subvolume(&r.subvolume_id).map_err(to_status)?;
            Some(s.id)
        };
        let grants = self.svc.list_shares(sv).map_err(to_status)?;
        Ok(Response::new(pb::ListSharesResponse {
            grants: grants.iter().map(share_grant_to_pb).collect(),
        }))
    }

    async fn get(
        &self,
        req: Request<pb::GetShareRequest>,
    ) -> Result<Response<pb::ShareGrant>, Status> {
        let s = req.into_inner().id_or_token;
        let grant = if let Ok(uuid) = Uuid::parse_str(&s) {
            self.svc.get_share(ShareId(uuid)).map_err(to_status)?
        } else {
            self.svc.get_share_by_token(&s).map_err(to_status)?
        };
        Ok(Response::new(share_grant_to_pb(&grant)))
    }

    async fn revoke(&self, req: Request<pb::RevokeShareRequest>) -> Result<Response<()>, Status> {
        let id = parse_share_id(&req.into_inner().id)?;
        self.svc.revoke_share(id).map_err(to_status)?;
        Ok(Response::new(()))
    }

    async fn delete(&self, req: Request<pb::DeleteShareRequest>) -> Result<Response<()>, Status> {
        let id = parse_share_id(&req.into_inner().id)?;
        self.svc
            .store()
            .delete_share_grant(&id.to_string())
            .map_err(to_status)?;
        Ok(Response::new(()))
    }

    async fn list_events(
        &self,
        req: Request<pb::ListShareEventsRequest>,
    ) -> Result<Response<pb::ListShareEventsResponse>, Status> {
        let r = req.into_inner();
        let id = parse_share_id(&r.id)?;
        let rows = self
            .svc
            .recent_share_events(id, r.limit)
            .map_err(to_status)?;
        let events = rows
            .into_iter()
            .map(|row| pb::ShareEvent {
                id: row.id,
                share_id: row.share_id,
                ts: Some(Timestamp {
                    seconds: row.ts,
                    nanos: 0,
                }),
                action: row.action,
                remote_ip: row.remote_ip,
                user_agent: row.user_agent,
                key: row.key,
                status: row.status,
            })
            .collect();
        Ok(Response::new(pb::ListShareEventsResponse { events }))
    }
}

// ---------- Archives ----------

pub struct ArchivesSvc {
    archive: Option<Arc<ArchiveService>>,
}

impl ArchivesSvc {
    fn require(&self) -> Result<&Arc<ArchiveService>, Status> {
        self.archive
            .as_ref()
            .ok_or_else(|| Status::unavailable("archive subsystem disabled"))
    }
}

fn archive_err(e: bibliotheca_archive::Error) -> Status {
    use bibliotheca_archive::Error as E;
    match e {
        E::Core(c) => to_status(c),
        E::UnsupportedKind(m) => Status::invalid_argument(m),
        E::Immutable(m) => Status::failed_precondition(m),
        E::VerifyFailed { archive, reason } => Status::data_loss(format!("{archive}: {reason}")),
        E::RestoreConflict(m) => Status::already_exists(m),
        E::Io(e) => Status::internal(e.to_string()),
        E::Other(m) => Status::internal(m),
    }
}

fn archive_to_pb(a: &CoreArchive) -> pb::Archive {
    pb::Archive {
        id: a.id.clone(),
        subvolume_id: a.subvolume_id.to_string(),
        name: a.name.clone(),
        kind: a.kind.as_str().to_string(),
        path: a.path.to_string_lossy().into_owned(),
        size_bytes: a.size_bytes,
        object_count: a.object_count,
        sha256: a.sha256.clone(),
        created_at: Some(ts(a.created_at)),
        expires_at: a.expires_at.map(|t| t.unix_timestamp()).unwrap_or(0),
        retention_days: a.retention_days.unwrap_or(0),
        immutable: a.immutable,
        note: a.note.clone(),
        created_by: a.created_by.map(|u| u.to_string()).unwrap_or_default(),
    }
}

fn policy_to_pb(row: &SubvolumePolicyRow) -> pb::SubvolumePolicy {
    pb::SubvolumePolicy {
        subvolume_id: row.subvolume_id.clone(),
        kind: row.kind.clone(),
        retention_days: row.retention_days.map(|d| d.max(0) as u64).unwrap_or(0),
        archive_interval_secs: row.archive_interval_secs,
        min_age_days: row.min_age_days,
        enabled: row.enabled,
        last_run_at: row.last_run_at.unwrap_or(0),
    }
}

fn policy_from_pb(pb: pb::SubvolumePolicy) -> Result<SubvolumePolicyRow, Status> {
    // Validate subvolume id is parseable as a uuid even if we store it
    // as text — saves confusion later when the lifecycle task runs.
    let _ =
        Uuid::parse_str(&pb.subvolume_id).map_err(|_| Status::invalid_argument("subvolume_id"))?;
    if pb.kind != "snapshot" && pb.kind != "tarball" {
        return Err(Status::invalid_argument("kind must be snapshot or tarball"));
    }
    Ok(SubvolumePolicyRow {
        subvolume_id: pb.subvolume_id,
        kind: pb.kind,
        retention_days: if pb.retention_days == 0 {
            None
        } else {
            Some(pb.retention_days as i64)
        },
        archive_interval_secs: pb.archive_interval_secs.max(60),
        min_age_days: pb.min_age_days,
        enabled: pb.enabled,
        last_run_at: if pb.last_run_at == 0 {
            None
        } else {
            Some(pb.last_run_at)
        },
        created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
    })
}

#[tonic::async_trait]
impl Archives for ArchivesSvc {
    async fn create_archive(
        &self,
        req: Request<pb::CreateArchiveRequest>,
    ) -> Result<Response<pb::Archive>, Status> {
        let svc = self.require()?;
        let r = req.into_inner();
        let sv_uuid = Uuid::parse_str(&r.subvolume_id)
            .map_err(|_| Status::invalid_argument("subvolume_id"))?;
        let kind_str = if r.kind.is_empty() {
            svc.config().default_kind.clone()
        } else {
            r.kind
        };
        let kind = ArchiveKind::parse(&kind_str).map_err(archive_err)?;
        let created_by = if r.created_by.is_empty() {
            None
        } else {
            Some(parse_user_id(&r.created_by)?)
        };
        let retention = if r.retention_days == 0 {
            None
        } else {
            Some(r.retention_days)
        };
        let archive = svc
            .create(ArchiveCreateParams {
                subvolume_id: SubvolumeId(sv_uuid),
                name: r.name,
                kind,
                retention_days: retention,
                note: r.note,
                created_by,
            })
            .await
            .map_err(archive_err)?;
        Ok(Response::new(archive_to_pb(&archive)))
    }

    async fn list_archives(
        &self,
        req: Request<pb::ListArchivesRequest>,
    ) -> Result<Response<pb::ListArchivesResponse>, Status> {
        let svc = self.require()?;
        let r = req.into_inner();
        let sv = if r.subvolume_id.is_empty() {
            None
        } else {
            Some(SubvolumeId(
                Uuid::parse_str(&r.subvolume_id)
                    .map_err(|_| Status::invalid_argument("subvolume_id"))?,
            ))
        };
        let list = svc.list(sv).map_err(archive_err)?;
        Ok(Response::new(pb::ListArchivesResponse {
            archives: list.iter().map(archive_to_pb).collect(),
        }))
    }

    async fn get_archive(
        &self,
        req: Request<pb::GetArchiveRequest>,
    ) -> Result<Response<pb::Archive>, Status> {
        let svc = self.require()?;
        let id = req.into_inner().id;
        let archive = svc.get(&id).map_err(archive_err)?;
        Ok(Response::new(archive_to_pb(&archive)))
    }

    async fn delete_archive(
        &self,
        req: Request<pb::DeleteArchiveRequest>,
    ) -> Result<Response<()>, Status> {
        let svc = self.require()?;
        let r = req.into_inner();
        svc.delete(&r.id, r.force).await.map_err(archive_err)?;
        Ok(Response::new(()))
    }

    async fn verify_archive(
        &self,
        req: Request<pb::VerifyArchiveRequest>,
    ) -> Result<Response<pb::VerifyArchiveResponse>, Status> {
        let svc = self.require()?;
        let r = req.into_inner();
        let report = svc.verify(&r.id).map_err(archive_err)?;
        Ok(Response::new(pb::VerifyArchiveResponse {
            archive_id: report.archive_id,
            total: report.total,
            checked: report.checked,
            ok: report.mismatches.is_empty() && report.missing.is_empty(),
            mismatches: report.mismatches,
            missing: report.missing,
        }))
    }

    async fn restore_archive(
        &self,
        req: Request<pb::RestoreArchiveRequest>,
    ) -> Result<Response<pb::RestoreArchiveResponse>, Status> {
        let svc = self.require()?;
        let r = req.into_inner();
        let target = Uuid::parse_str(&r.target_subvolume_id)
            .map_err(|_| Status::invalid_argument("target_subvolume_id"))?;
        let n = svc
            .restore(&r.id, SubvolumeId(target), r.overwrite)
            .map_err(archive_err)?;
        Ok(Response::new(pb::RestoreArchiveResponse { restored: n }))
    }

    async fn get_manifest(
        &self,
        req: Request<pb::ArchiveManifestRequest>,
    ) -> Result<Response<pb::ArchiveManifestResponse>, Status> {
        let svc = self.require()?;
        let id = req.into_inner().id;
        let entries = svc.manifest(&id).map_err(archive_err)?;
        Ok(Response::new(pb::ArchiveManifestResponse {
            entries: entries
                .into_iter()
                .map(|e| pb::ArchiveManifestEntry {
                    key: e.key,
                    size: e.size,
                    sha256: e.sha256,
                })
                .collect(),
        }))
    }

    async fn set_policy(
        &self,
        req: Request<pb::SetSubvolumePolicyRequest>,
    ) -> Result<Response<pb::SubvolumePolicy>, Status> {
        let svc = self.require()?;
        let pb_policy = req
            .into_inner()
            .policy
            .ok_or_else(|| Status::invalid_argument("missing policy"))?;
        let row = policy_from_pb(pb_policy)?;
        svc.set_policy(row.clone()).map_err(archive_err)?;
        Ok(Response::new(policy_to_pb(&row)))
    }

    async fn get_policy(
        &self,
        req: Request<pb::GetSubvolumePolicyRequest>,
    ) -> Result<Response<pb::SubvolumePolicy>, Status> {
        let svc = self.require()?;
        let sv = Uuid::parse_str(&req.into_inner().subvolume_id)
            .map_err(|_| Status::invalid_argument("subvolume_id"))?;
        let row = svc
            .get_policy(SubvolumeId(sv))
            .map_err(archive_err)?
            .ok_or_else(|| Status::not_found("policy"))?;
        Ok(Response::new(policy_to_pb(&row)))
    }

    async fn delete_policy(
        &self,
        req: Request<pb::DeleteSubvolumePolicyRequest>,
    ) -> Result<Response<()>, Status> {
        let svc = self.require()?;
        let sv = Uuid::parse_str(&req.into_inner().subvolume_id)
            .map_err(|_| Status::invalid_argument("subvolume_id"))?;
        svc.delete_policy(SubvolumeId(sv)).map_err(archive_err)?;
        Ok(Response::new(()))
    }

    async fn list_policies(
        &self,
        _req: Request<()>,
    ) -> Result<Response<pb::ListSubvolumePoliciesResponse>, Status> {
        let svc = self.require()?;
        let rows = svc.list_policies().map_err(archive_err)?;
        Ok(Response::new(pb::ListSubvolumePoliciesResponse {
            policies: rows.iter().map(policy_to_pb).collect(),
        }))
    }

    async fn run_lifecycle_once(&self, _req: Request<()>) -> Result<Response<()>, Status> {
        let svc = self.require()?;
        svc.run_lifecycle_once().await.map_err(archive_err)?;
        Ok(Response::new(()))
    }
}

// ---------- AnisetteAdmin ----------

pub struct AnisetteAdminSvc {
    /// `None` means the anisette proxy was not configured at boot.
    /// Every RPC returns `Unavailable` in that case.
    provider: Option<(Arc<dyn AnisetteProvider>, String)>,
}

#[tonic::async_trait]
impl AnisetteAdmin for AnisetteAdminSvc {
    async fn status(&self, _req: Request<()>) -> Result<Response<pb::AnisetteStatus>, Status> {
        let Some((provider, listen)) = &self.provider else {
            return Ok(Response::new(pb::AnisetteStatus {
                enabled: false,
                kind: String::new(),
                upstreams: vec![],
                last_success_at: 0,
                cached_until: 0,
                listen: String::new(),
            }));
        };
        let s = provider.status();
        Ok(Response::new(pb::AnisetteStatus {
            enabled: true,
            kind: s.kind,
            upstreams: s
                .upstreams
                .into_iter()
                .map(|u| pb::AnisetteUpstreamHealth {
                    url: u.url,
                    ok_count: u.ok_count,
                    err_count: u.err_count,
                    last_error: u.last_error.unwrap_or_default(),
                })
                .collect(),
            last_success_at: s.last_success_at.unwrap_or(0),
            cached_until: s.cached_until.unwrap_or(0),
            listen: listen.clone(),
        }))
    }

    async fn reset(&self, _req: Request<()>) -> Result<Response<()>, Status> {
        let Some((provider, _)) = &self.provider else {
            return Err(Status::unavailable("anisette proxy disabled"));
        };
        provider.reset();
        Ok(Response::new(()))
    }

    async fn add_peer(
        &self,
        req: Request<pb::AnisettePeerRequest>,
    ) -> Result<Response<()>, Status> {
        let Some((provider, _)) = &self.provider else {
            return Err(Status::unavailable("anisette proxy disabled"));
        };
        let url = req.into_inner().url;
        provider.add_upstream(&url).map_err(anisette_err)?;
        info!(peer = %url, "anisette peer added");
        Ok(Response::new(()))
    }

    async fn remove_peer(
        &self,
        req: Request<pb::AnisettePeerRequest>,
    ) -> Result<Response<()>, Status> {
        let Some((provider, _)) = &self.provider else {
            return Err(Status::unavailable("anisette proxy disabled"));
        };
        let url = req.into_inner().url;
        provider.remove_upstream(&url).map_err(anisette_err)?;
        info!(peer = %url, "anisette peer removed");
        Ok(Response::new(()))
    }

    async fn list_peers(
        &self,
        _req: Request<()>,
    ) -> Result<Response<pb::ListPeersResponse>, Status> {
        let Some((provider, _)) = &self.provider else {
            return Ok(Response::new(pb::ListPeersResponse { urls: vec![] }));
        };
        Ok(Response::new(pb::ListPeersResponse {
            urls: provider.upstreams(),
        }))
    }
}

fn anisette_err(e: bibliotheca_anisette::Error) -> Status {
    use bibliotheca_anisette::Error as E;
    match e {
        E::NotSupported(m) => Status::unimplemented(m),
        E::AlreadyExists(m) => Status::already_exists(m),
        E::NotFound(m) => Status::not_found(m),
        E::InvalidUrl(m) => Status::invalid_argument(m),
        other => Status::internal(other.to_string()),
    }
}
