//! Typed model of a sync mount.

use std::fmt;
use std::str::FromStr;

use bibliotheca_core::identity::UserId;
use bibliotheca_core::store::SyncMountRow;
use bibliotheca_core::subvolume::SubvolumeId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MountId(pub Uuid);

impl MountId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for MountId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    ICloudPhotos,
    Dropbox,
    Nextcloud,
    Solid,
    GooglePhotos,
    Ipfs,
}

impl ConnectorKind {
    pub fn as_wire(self) -> &'static str {
        match self {
            ConnectorKind::ICloudPhotos => "icloud",
            ConnectorKind::Dropbox => "dropbox",
            ConnectorKind::Nextcloud => "nextcloud",
            ConnectorKind::Solid => "solid",
            ConnectorKind::GooglePhotos => "gphotos",
            ConnectorKind::Ipfs => "ipfs",
        }
    }
}

impl FromStr for ConnectorKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "icloud" | "icloud_photos" => ConnectorKind::ICloudPhotos,
            "dropbox" => ConnectorKind::Dropbox,
            "nextcloud" | "webdav" => ConnectorKind::Nextcloud,
            "solid" => ConnectorKind::Solid,
            "gphotos" | "google_photos" => ConnectorKind::GooglePhotos,
            "ipfs" => ConnectorKind::Ipfs,
            other => {
                return Err(Error::InvalidArgument(format!(
                    "unknown connector: {other}"
                )))
            }
        })
    }
}

impl fmt::Display for ConnectorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Pull,
    Push,
    Both,
}

impl Direction {
    pub fn as_wire(self) -> &'static str {
        match self {
            Direction::Pull => "pull",
            Direction::Push => "push",
            Direction::Both => "both",
        }
    }
}

impl FromStr for Direction {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "pull" => Direction::Pull,
            "push" => Direction::Push,
            "both" => Direction::Both,
            other => {
                return Err(Error::InvalidArgument(format!(
                    "unknown direction: {other}"
                )))
            }
        })
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// Input shape used to create a new mount.
#[derive(Debug, Clone)]
pub struct MountSpec {
    pub name: String,
    pub kind: ConnectorKind,
    pub direction: Direction,
    pub interval_secs: u32,
    pub quota_bytes: u64,
    pub owner: UserId,
    pub config_json: String,
    pub credentials_id: Option<String>,
}

/// Strongly-typed projection of a row from the `sync_mounts` table.
#[derive(Debug, Clone)]
pub struct SyncMount {
    pub id: MountId,
    pub name: String,
    pub kind: ConnectorKind,
    pub subvolume_id: SubvolumeId,
    pub townos_name: String,
    pub direction: Direction,
    pub interval_secs: u32,
    pub enabled: bool,
    pub paused: bool,
    pub quota_bytes: u64,
    pub cursor_blob: Option<Vec<u8>>,
    pub config_json: String,
    pub credentials_id: Option<String>,
    pub last_sync_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub backoff_until: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// Non-secret snapshot of a mount suitable for gRPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMountSnapshot {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub subvolume_id: String,
    pub townos_name: String,
    pub direction: String,
    pub interval_secs: u32,
    pub enabled: bool,
    pub paused: bool,
    pub quota_bytes: u64,
    pub last_sync_at: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
}

impl SyncMount {
    pub fn from_row(row: SyncMountRow) -> Result<Self> {
        let kind = ConnectorKind::from_str(&row.kind)?;
        let direction = Direction::from_str(&row.direction)?;
        Ok(SyncMount {
            id: MountId(
                Uuid::parse_str(&row.id)
                    .map_err(|e| Error::InvalidArgument(format!("mount id: {e}")))?,
            ),
            name: row.name,
            kind,
            subvolume_id: SubvolumeId(
                Uuid::parse_str(&row.subvolume_id)
                    .map_err(|e| Error::InvalidArgument(format!("subvolume id: {e}")))?,
            ),
            townos_name: row.townos_name,
            direction,
            interval_secs: row.interval_secs,
            enabled: row.enabled,
            paused: row.paused,
            quota_bytes: row.quota_bytes,
            cursor_blob: row.cursor_blob,
            config_json: row.config_json,
            credentials_id: row.credentials_id,
            last_sync_at: row
                .last_sync_at
                .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok()),
            last_error: row.last_error,
            backoff_until: row
                .backoff_until
                .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok()),
            created_at: OffsetDateTime::from_unix_timestamp(row.created_at)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        })
    }

    pub fn snapshot(&self) -> SyncMountSnapshot {
        SyncMountSnapshot {
            id: self.id.to_string(),
            name: self.name.clone(),
            kind: self.kind.to_string(),
            subvolume_id: self.subvolume_id.to_string(),
            townos_name: self.townos_name.clone(),
            direction: self.direction.to_string(),
            interval_secs: self.interval_secs,
            enabled: self.enabled,
            paused: self.paused,
            quota_bytes: self.quota_bytes,
            last_sync_at: self.last_sync_at.map(|t| t.unix_timestamp()),
            last_error: self.last_error.clone(),
            created_at: self.created_at.unix_timestamp(),
        }
    }
}
