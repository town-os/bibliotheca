//! High-level orchestration: combines the metadata [`Store`] with a
//! [`SubvolumeBackend`] so the daemon (or in-process callers) can issue
//! single calls that keep the database and the on-disk state in sync.

use std::sync::Arc;

use tracing::{info, warn};

use crate::acl::{Acl, Permission};
use crate::backend::SubvolumeBackend;
use crate::error::{Error, Result};
use crate::identity::{Group, GroupId, User, UserId};
use crate::password;
use crate::store::Store;
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
}
