//! Share grants: unguessable URLs that let anonymous callers read a
//! single key (or a whole subvolume) without going through the usual
//! ACL machinery. The [`BibliothecaService`](crate::service::BibliothecaService)
//! owns the CRUD surface and the atomic use-limit / expiry check; the
//! HTTP interface merely looks tokens up and serves bytes through the
//! normal `DataStore` path read.
//!
//! Design decisions:
//!
//! - **Token shape**: URL-safe base64 of `token_bytes` random bytes
//!   (default 32). Never leaves the control plane unencrypted — the
//!   CLI prints it once at create time and stores nothing on disk.
//! - **Expiry**: optional wall-clock Unix timestamp; `None` = never.
//! - **Use limit**: optional integer; `None` = unlimited. Successful
//!   GETs increment atomically via
//!   [`Store::consume_share_use`](crate::store::Store::consume_share_use).
//! - **Revocation**: soft — flipping a bit rather than deleting the
//!   row, so the audit trail in `share_events` stays readable.
//! - **Scope**: pinned to one subvolume at create time. Optionally
//!   pinned to one exact key; otherwise the token is good for any
//!   key inside the subvolume (path traversal still forbidden — the
//!   HTTP handler runs every key through `resolve_key`).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::identity::UserId;
use crate::store::ShareGrantRow;
use crate::subvolume::SubvolumeId;

/// Typed wrapper around a share id (the row's primary key, not the
/// public token).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareId(pub Uuid);

impl ShareId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ShareId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ShareId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Rich view of a share grant, built from a [`ShareGrantRow`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareGrant {
    pub id: ShareId,
    pub token: String,
    pub subvolume_id: SubvolumeId,
    /// Pinned key, or `None` if the share covers the whole subvolume.
    pub key: Option<String>,
    pub created_by: UserId,
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub use_limit: Option<u64>,
    pub uses: u64,
    pub revoked: bool,
    pub note: String,
}

impl ShareGrant {
    pub fn from_row(row: ShareGrantRow) -> crate::Result<Self> {
        let id = Uuid::parse_str(&row.id)
            .map_err(|e| crate::Error::InvalidArgument(format!("share id: {e}")))?;
        let sv = Uuid::parse_str(&row.subvolume_id)
            .map_err(|e| crate::Error::InvalidArgument(format!("share sv id: {e}")))?;
        let uid = Uuid::parse_str(&row.created_by)
            .map_err(|e| crate::Error::InvalidArgument(format!("share user id: {e}")))?;
        Ok(Self {
            id: ShareId(id),
            token: row.token,
            subvolume_id: SubvolumeId(sv),
            key: if row.key.is_empty() {
                None
            } else {
                Some(row.key)
            },
            created_by: UserId(uid),
            created_at: OffsetDateTime::from_unix_timestamp(row.created_at)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            expires_at: row
                .expires_at
                .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok()),
            use_limit: row.use_limit.map(|n| n.max(0) as u64),
            uses: row.uses.max(0) as u64,
            revoked: row.revoked,
            note: row.note,
        })
    }
}

/// Input parameters for [`BibliothecaService::create_share`](crate::service::BibliothecaService::create_share).
#[derive(Debug, Clone)]
pub struct CreateShareParams {
    pub subvolume_id: SubvolumeId,
    pub created_by: UserId,
    pub key: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub use_limit: Option<u64>,
    pub note: String,
}
