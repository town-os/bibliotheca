//! High-level orchestration: combines the metadata [`Store`] with a
//! [`SubvolumeBackend`] so the daemon (or in-process callers) can issue
//! single calls that keep the database and the on-disk state in sync.

use std::sync::Arc;

use tracing::{info, warn};

use crate::acl::{Acl, Permission};
use crate::backend::SubvolumeBackend;
use crate::data::resolve_key;
use crate::error::{Error, Result};
use crate::identity::{Group, GroupId, User, UserId};
use crate::password;
use crate::share::{CreateShareParams, ShareGrant, ShareId};
use crate::store::{ShareEventRow, ShareGrantRow, Store};
use crate::subvolume::{Snapshot, SnapshotId, Subvolume, SubvolumeId};

#[derive(Clone)]
pub struct BibliothecaService {
    store: Store,
    backend: Arc<dyn SubvolumeBackend>,
}

impl BibliothecaService {
    pub fn new(store: Store, backend: Arc<dyn SubvolumeBackend>) -> Self {
        Self { store, backend }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    // ---- identity ----

    pub fn create_user(&self, name: &str, display: &str, password_plain: &str) -> Result<User> {
        if name.trim().is_empty() {
            return Err(Error::InvalidArgument("user name required".into()));
        }
        let hash = password::hash(password_plain)?;
        self.store.create_user(name, display, &hash)
    }

    pub fn list_users(&self, limit: u32, offset: u32) -> Result<Vec<User>> {
        self.store.list_users(limit, offset)
    }

    pub fn get_user(&self, id_or_name: &str) -> Result<User> {
        if let Ok(uuid) = uuid::Uuid::parse_str(id_or_name) {
            self.store.get_user_by_id(UserId(uuid))
        } else {
            self.store.get_user_by_name(id_or_name)
        }
    }

    pub fn delete_user(&self, id: UserId) -> Result<()> {
        self.store.delete_user(id)
    }

    pub fn set_user_password(&self, id: UserId, password_plain: &str) -> Result<()> {
        let hash = password::hash(password_plain)?;
        self.store.set_password(id, &hash)
    }

    pub fn verify_user_password(&self, name: &str, password_plain: &str) -> Result<Option<User>> {
        let user = match self.store.get_user_by_name(name) {
            Ok(u) => u,
            Err(Error::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        if user.disabled {
            return Ok(None);
        }
        let hash = self.store.get_password_hash(user.id)?;
        if password::verify(password_plain, &hash)? {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub fn create_group(&self, name: &str, description: &str) -> Result<Group> {
        if name.trim().is_empty() {
            return Err(Error::InvalidArgument("group name required".into()));
        }
        self.store.create_group(name, description)
    }

    pub fn list_groups(&self, limit: u32, offset: u32) -> Result<Vec<Group>> {
        self.store.list_groups(limit, offset)
    }

    pub fn get_group(&self, id_or_name: &str) -> Result<Group> {
        if let Ok(uuid) = uuid::Uuid::parse_str(id_or_name) {
            self.store.get_group_by_id(GroupId(uuid))
        } else {
            self.store.get_group_by_name(id_or_name)
        }
    }

    pub fn delete_group(&self, id: GroupId) -> Result<()> {
        self.store.delete_group(id)
    }

    pub fn add_user_to_group(&self, user: UserId, group: GroupId) -> Result<()> {
        self.store.add_user_to_group(user, group)
    }

    pub fn remove_user_from_group(&self, user: UserId, group: GroupId) -> Result<()> {
        self.store.remove_user_from_group(user, group)
    }

    pub fn list_group_members(&self, group: GroupId) -> Result<Vec<User>> {
        let ids = self.store.users_in_group(group)?;
        ids.into_iter()
            .map(|id| self.store.get_user_by_id(id))
            .collect()
    }

    // ---- subvolumes ----

    pub async fn create_subvolume(
        &self,
        name: &str,
        owner: UserId,
        quota_bytes: u64,
        acl: Option<Acl>,
    ) -> Result<Subvolume> {
        if name.trim().is_empty() || name.contains('/') {
            return Err(Error::InvalidArgument("invalid subvolume name".into()));
        }
        let _ = self.store.get_user_by_id(owner)?; // existence check
        let path = self.backend.path_for(name);

        self.backend.create_subvolume(&path).await?;
        if quota_bytes > 0 {
            if let Err(e) = self.backend.set_quota(&path, quota_bytes).await {
                warn!(error = %e, "set_quota failed; rolling back subvolume");
                let _ = self.backend.delete_subvolume(&path).await;
                return Err(e);
            }
        }
        let acl = acl.unwrap_or_else(|| Acl::owner_only(owner));
        let sv = self
            .store
            .create_subvolume(name, owner, path.clone(), quota_bytes, &acl)?;
        info!(subvolume = %sv.id, name, "created subvolume");
        Ok(sv)
    }

    pub fn get_subvolume(&self, id_or_name: &str) -> Result<Subvolume> {
        if let Ok(uuid) = uuid::Uuid::parse_str(id_or_name) {
            self.store.get_subvolume(SubvolumeId(uuid))
        } else {
            self.store.get_subvolume_by_name(id_or_name)
        }
    }

    pub fn list_subvolumes(
        &self,
        owner: Option<UserId>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Subvolume>> {
        self.store.list_subvolumes(owner, limit, offset)
    }

    pub async fn delete_subvolume(&self, id: SubvolumeId, force: bool) -> Result<()> {
        let sv = self.store.get_subvolume(id)?;
        let snaps = self.store.list_snapshots(id)?;
        if !snaps.is_empty() && !force {
            return Err(Error::InvalidArgument(format!(
                "subvolume has {} snapshots; pass force",
                snaps.len()
            )));
        }
        for snap in snaps {
            let _ = self.backend.delete_subvolume(&snap.mount_path).await;
            let _ = self.store.delete_snapshot(snap.id);
        }
        self.backend.delete_subvolume(&sv.mount_path).await?;
        self.store.delete_subvolume(id)?;
        Ok(())
    }

    pub async fn set_quota(&self, id: SubvolumeId, bytes: u64) -> Result<Subvolume> {
        let sv = self.store.get_subvolume(id)?;
        self.backend.set_quota(&sv.mount_path, bytes).await?;
        self.store.set_quota(id, bytes)?;
        self.store.get_subvolume(id)
    }

    /// Adopt an externally-provisioned subvolume (for example one
    /// created by the town-os systemcontroller). Unlike
    /// [`Self::create_subvolume`], this does **not** touch the
    /// [`SubvolumeBackend`] — the caller promises the btrfs (or
    /// equivalent) subvolume already exists at `mount_path`. Used
    /// exclusively by the sync subsystem when procuring storage
    /// through town-os.
    pub fn adopt_subvolume(
        &self,
        name: &str,
        owner: UserId,
        mount_path: std::path::PathBuf,
        quota_bytes: u64,
        acl: Option<Acl>,
    ) -> Result<Subvolume> {
        if name.trim().is_empty() || name.contains('/') {
            return Err(Error::InvalidArgument("invalid subvolume name".into()));
        }
        let _ = self.store.get_user_by_id(owner)?;
        let acl = acl.unwrap_or_else(|| Acl::owner_only(owner));
        let sv = self
            .store
            .create_subvolume(name, owner, mount_path, quota_bytes, &acl)?;
        info!(subvolume = %sv.id, name, "adopted external subvolume");
        Ok(sv)
    }

    /// Drop the metadata row for a subvolume without calling the
    /// backend. Used when the underlying storage is owned by an
    /// external system (e.g. town-os) that will reclaim it
    /// separately.
    pub fn forget_subvolume(&self, id: SubvolumeId) -> Result<()> {
        let snaps = self.store.list_snapshots(id)?;
        for snap in snaps {
            let _ = self.store.delete_snapshot(snap.id);
        }
        self.store.delete_subvolume(id)?;
        Ok(())
    }

    /// Update the quota row without calling the backend. Used when
    /// the real quota is enforced elsewhere (town-os) but we still
    /// want [`DataStore::put`] to honour the limit locally.
    pub fn update_subvolume_quota(&self, id: SubvolumeId, quota_bytes: u64) -> Result<Subvolume> {
        self.store.set_quota(id, quota_bytes)?;
        self.store.get_subvolume(id)
    }

    pub fn set_acl(&self, id: SubvolumeId, acl: &Acl) -> Result<Subvolume> {
        self.store.set_acl(id, acl)?;
        self.store.get_subvolume(id)
    }

    // ---- snapshots ----

    pub async fn create_snapshot(
        &self,
        sv_id: SubvolumeId,
        name: &str,
        readonly: bool,
    ) -> Result<Snapshot> {
        if name.trim().is_empty() || name.contains('/') {
            return Err(Error::InvalidArgument("invalid snapshot name".into()));
        }
        let sv = self.store.get_subvolume(sv_id)?;
        let dest = sv
            .mount_path
            .parent()
            .unwrap_or(self.backend.root())
            .join(format!(".snapshots/{}/{name}", sv.name));
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.backend
            .snapshot(&sv.mount_path, &dest, readonly)
            .await?;
        self.store.create_snapshot(sv_id, name, dest, readonly)
    }

    pub fn list_snapshots(&self, sv: SubvolumeId) -> Result<Vec<Snapshot>> {
        self.store.list_snapshots(sv)
    }

    pub async fn delete_snapshot(&self, id: SnapshotId) -> Result<()> {
        let snap = self.store.delete_snapshot(id)?;
        self.backend.delete_subvolume(&snap.mount_path).await?;
        Ok(())
    }

    // ---- ACL helper for data-plane crates ----

    pub fn check_permission(
        &self,
        sv: SubvolumeId,
        user: Option<UserId>,
        wanted: Permission,
        public_allowed: bool,
    ) -> Result<bool> {
        self.store
            .check_permission(sv, user, wanted, public_allowed)
    }

    // ---- share grants ----

    pub fn create_share(&self, params: CreateShareParams, token: String) -> Result<ShareGrant> {
        // Validate that the subvolume exists.
        let sv = self.store.get_subvolume(params.subvolume_id)?;
        // If a specific key was requested, make sure it actually
        // resolves inside the mount and points at a file. That
        // keeps bogus tokens out of the DB and gives the operator
        // an immediate error instead of a 404 on first use.
        if let Some(ref k) = params.key {
            let abs = resolve_key(&sv.mount_path, k)?;
            if !abs.exists() {
                return Err(Error::NotFound(format!("{}/{}", sv.name, k)));
            }
        }
        let id = ShareId::new();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let row = ShareGrantRow {
            id: id.to_string(),
            token,
            subvolume_id: sv.id.to_string(),
            key: params.key.clone().unwrap_or_default(),
            created_by: params.created_by.to_string(),
            created_at: now,
            expires_at: params.expires_at.map(|t| t.unix_timestamp()),
            use_limit: params.use_limit.map(|n| n as i64),
            uses: 0,
            revoked: false,
            note: params.note,
        };
        self.store.insert_share_grant(&row)?;
        let _ = self.store.insert_share_event(&ShareEventRow {
            id: 0,
            share_id: row.id.clone(),
            ts: now,
            action: "create".into(),
            remote_ip: String::new(),
            user_agent: String::new(),
            key: row.key.clone(),
            status: 201,
        });
        ShareGrant::from_row(row)
    }

    pub fn list_shares(&self, sv: Option<SubvolumeId>) -> Result<Vec<ShareGrant>> {
        self.store
            .list_share_grants(sv)?
            .into_iter()
            .map(ShareGrant::from_row)
            .collect()
    }

    pub fn get_share(&self, id: ShareId) -> Result<ShareGrant> {
        let row = self.store.get_share_grant_by_id(&id.to_string())?;
        ShareGrant::from_row(row)
    }

    pub fn get_share_by_token(&self, token: &str) -> Result<ShareGrant> {
        let row = self.store.get_share_grant_by_token(token)?;
        ShareGrant::from_row(row)
    }

    pub fn revoke_share(&self, id: ShareId) -> Result<()> {
        self.store.revoke_share_grant(&id.to_string())?;
        let _ = self.store.insert_share_event(&ShareEventRow {
            id: 0,
            share_id: id.to_string(),
            ts: time::OffsetDateTime::now_utc().unix_timestamp(),
            action: "revoke".into(),
            remote_ip: String::new(),
            user_agent: String::new(),
            key: String::new(),
            status: 200,
        });
        Ok(())
    }

    /// Called by the HTTP share handler on every successful GET.
    /// Atomically validates the token and increments `uses`; records
    /// an audit event regardless of outcome.
    pub fn consume_share(
        &self,
        token: &str,
        key: &str,
        remote_ip: &str,
        user_agent: &str,
    ) -> Result<ShareGrant> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        match self.store.consume_share_use(token, now) {
            Ok(row) => {
                let grant = ShareGrant::from_row(row)?;
                let _ = self.store.insert_share_event(&ShareEventRow {
                    id: 0,
                    share_id: grant.id.to_string(),
                    ts: now,
                    action: "use".into(),
                    remote_ip: remote_ip.to_string(),
                    user_agent: user_agent.to_string(),
                    key: key.to_string(),
                    status: 200,
                });
                Ok(grant)
            }
            Err(e) => {
                // Best-effort audit write. If we can't find the
                // token at all, there's nothing to attach the
                // event to — silently drop it.
                if let Ok(existing) = self.store.get_share_grant_by_token(token) {
                    let action = match &e {
                        Error::InvalidArgument(m) if m.contains("expired") => "expire",
                        Error::InvalidArgument(m) if m.contains("exhausted") => "deny",
                        Error::PermissionDenied => "deny",
                        _ => "deny",
                    };
                    let status = match &e {
                        Error::InvalidArgument(m) if m.contains("expired") => 410,
                        Error::InvalidArgument(m) if m.contains("exhausted") => 429,
                        Error::PermissionDenied => 403,
                        _ => 500,
                    };
                    let _ = self.store.insert_share_event(&ShareEventRow {
                        id: 0,
                        share_id: existing.id,
                        ts: now,
                        action: action.into(),
                        remote_ip: remote_ip.to_string(),
                        user_agent: user_agent.to_string(),
                        key: key.to_string(),
                        status,
                    });
                }
                Err(e)
            }
        }
    }

    /// Read bytes on behalf of a share token, bypassing the usual
    /// ACL evaluation. Path traversal is still enforced through
    /// `resolve_key`; if the share pins a specific key, the caller
    /// must use that exact key or pass an empty string (both map to
    /// the pinned key). Otherwise the caller supplies the full key.
    pub fn read_shared_object(
        &self,
        grant: &ShareGrant,
        requested_key: &str,
    ) -> Result<(String, Vec<u8>)> {
        let sv = self.store.get_subvolume(grant.subvolume_id)?;
        let effective_key = match (&grant.key, requested_key) {
            (Some(pinned), "") => pinned.clone(),
            (Some(pinned), req) if req == pinned => pinned.clone(),
            (Some(_), _) => {
                return Err(Error::PermissionDenied);
            }
            (None, "") => {
                return Err(Error::InvalidArgument(
                    "share covers whole subvolume, key required in URL".into(),
                ));
            }
            (None, req) => req.to_string(),
        };
        let abs = resolve_key(&sv.mount_path, &effective_key)?;
        if !abs.exists() {
            return Err(Error::NotFound(format!("{}/{}", sv.name, effective_key)));
        }
        if abs.is_dir() {
            return Err(Error::InvalidArgument("target is a directory".into()));
        }
        let bytes = std::fs::read(&abs)?;
        Ok((effective_key, bytes))
    }

    pub fn recent_share_events(
        &self,
        id: ShareId,
        limit: u32,
    ) -> Result<Vec<crate::store::ShareEventRow>> {
        self.store.recent_share_events(&id.to_string(), limit)
    }
}
