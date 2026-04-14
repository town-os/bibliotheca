//! Sync events: what happened, when, on which mount. Persisted to
//! `sync_events` and also streamed over the in-memory broadcast
//! channel that gRPC `TailEvents` subscribes to.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::mount::MountId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Info,
    Warn,
    Error,
    NeedTwoFactor,
}

impl EventLevel {
    pub fn as_wire(self) -> &'static str {
        match self {
            EventLevel::Info => "info",
            EventLevel::Warn => "warn",
            EventLevel::Error => "error",
            EventLevel::NeedTwoFactor => "need_2fa",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEvent {
    pub mount_id: MountId,
    pub ts: OffsetDateTime,
    pub level: EventLevel,
    pub kind: String,
    pub message: String,
    pub details: serde_json::Value,
}

impl SyncEvent {
    pub fn now(
        mount_id: MountId,
        level: EventLevel,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            mount_id,
            ts: OffsetDateTime::now_utc(),
            level,
            kind: kind.into(),
            message: message.into(),
            details: serde_json::Value::Object(Default::default()),
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}
