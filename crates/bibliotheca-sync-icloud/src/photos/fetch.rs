//! Asset byte fetch. `RemoteObject.id` packs
//! `<recordName>::<downloadURL>`; we follow the URL.

use bibliotheca_sync_core::error::Result;
use bibliotheca_sync_core::trait_::RemoteObject;
use bytes::Bytes;

use crate::cloudkit::CloudKitClient;

pub async fn fetch(client: &CloudKitClient, obj: &RemoteObject) -> Result<Bytes> {
    let url = obj
        .id
        .split_once("::")
        .map(|(_, u)| u.to_string())
        .unwrap_or_else(|| obj.id.clone());
    if url.is_empty() {
        return Ok(Bytes::new());
    }
    client.get_bytes(&url).await
}
