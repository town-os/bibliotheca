//! CPLAsset delete via `records/modify` `operationType=delete`.

use bibliotheca_sync_core::error::Result;
use bibliotheca_sync_core::trait_::RemoteObject;
use serde_json::json;

use crate::cloudkit::zones::ZONE_PRIMARY;
use crate::cloudkit::CloudKitClient;

pub async fn delete(client: &CloudKitClient, obj: &RemoteObject) -> Result<()> {
    let record_name = obj
        .id
        .split_once("::")
        .map(|(r, _)| r.to_string())
        .unwrap_or_else(|| obj.id.clone());
    let body = json!({
        "operations": [
            {
                "operationType": "forceDelete",
                "record": { "recordName": record_name, "recordType": "CPLAsset" }
            }
        ],
        "zoneID": { "zoneName": ZONE_PRIMARY }
    });
    let _ = client.post_json("records/modify", &body).await?;
    Ok(())
}
