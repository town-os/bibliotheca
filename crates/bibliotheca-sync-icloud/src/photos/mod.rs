//! CloudKit Photos container operations.

pub mod delete;
pub mod fetch;
pub mod list;
pub mod upload;

use serde::{Deserialize, Serialize};

/// Opaque cursor stored on the mount's `cursor_blob` for
/// incremental Photos pulls. We serialize it as JSON for
/// readability; Apple's real CloudKit syncToken is just a bag of
/// bytes we echo back on the next request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhotosCursor {
    #[serde(default)]
    pub sync_token: Option<String>,
}
