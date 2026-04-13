use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::acl::Acl;
use crate::identity::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubvolumeId(pub Uuid);

impl SubvolumeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SubvolumeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SubvolumeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subvolume {
    pub id: SubvolumeId,
    pub name: String,
    pub owner: UserId,
    pub mount_path: PathBuf,
    /// Quota in bytes; 0 = unlimited.
    pub quota_bytes: u64,
    pub acl: Acl,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotId(pub Uuid);

impl SnapshotId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SnapshotId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub subvolume: SubvolumeId,
    pub name: String,
    pub mount_path: PathBuf,
    pub readonly: bool,
    pub created_at: OffsetDateTime,
}
