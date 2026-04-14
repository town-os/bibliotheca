//! Two-phase CPLAsset upload.
//!
//! The real CloudKit asset-upload protocol is:
//!
//! 1. `records/modify` with `operationType=create` on a new
//!    CPLAsset record whose asset fields reference placeholder
//!    `uploadURLs`. Apple returns a `pendingAsset` with an
//!    upload URL.
//! 2. `PUT` the bytes to the upload URL. Apple returns a
//!    confirmation blob containing a `fileChecksum`, `size`, etc.
//! 3. A second `records/modify` with `operationType=update` that
//!    commits the asset fields to the uploaded blob.
//!
//! This module orchestrates those three calls through
//! `CloudKitClient`. It deliberately keeps the wire types in
//! `serde_json::Value` form because Apple has rewritten the
//! envelope shape at least twice in the last three years — a
//! typed model would ossify before the ink dries.

use bibliotheca_sync_core::error::{Error, Result};
use bibliotheca_sync_core::trait_::{RemoteObject, UploadHints};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::cloudkit::zones::ZONE_PRIMARY;
use crate::cloudkit::CloudKitClient;

pub async fn upload(
    client: &CloudKitClient,
    key: &str,
    bytes: &[u8],
    _hints: UploadHints,
) -> Result<RemoteObject> {
    let filename = key.rsplit('/').next().unwrap_or(key).to_string();
    let record_name = format!(
        "asset-{:x}",
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );

    // Phase 1: create a placeholder record.
    let create_body = json!({
        "operations": [
            {
                "operationType": "create",
                "record": {
                    "recordName": record_name,
                    "recordType": "CPLAsset",
                    "fields": {
                        "filenameEnc": { "value": filename },
                        "assetDate": { "value": OffsetDateTime::now_utc().unix_timestamp() * 1000 },
                    }
                }
            }
        ],
        "zoneID": { "zoneName": ZONE_PRIMARY }
    });
    let create_resp = client.post_json("records/modify", &create_body).await?;

    // Pull the upload URL out of the pendingAssets.
    let upload_url = find_upload_url(&create_resp)
        .ok_or_else(|| Error::Fatal("cloudkit records/modify did not return upload URL".into()))?;
    let confirmation = client.put_bytes(&upload_url, bytes).await?;

    // Phase 2: commit by updating the record with the confirmed
    // asset reference. Apple expects the confirmation blob to be
    // echoed back verbatim under the `resJPEGFullRes.value` key.
    let commit_body = json!({
        "operations": [
            {
                "operationType": "update",
                "record": {
                    "recordName": record_name,
                    "recordType": "CPLAsset",
                    "fields": {
                        "resJPEGFullRes": { "value": confirmation }
                    }
                }
            }
        ],
        "zoneID": { "zoneName": ZONE_PRIMARY }
    });
    let _ = client.post_json("records/modify", &commit_body).await?;

    Ok(RemoteObject {
        id: format!("{record_name}::"),
        key: key.to_string(),
        size: bytes.len() as u64,
        etag: Some(record_name),
        modified: OffsetDateTime::now_utc(),
        is_dir: false,
    })
}

fn find_upload_url(resp: &Value) -> Option<String> {
    resp.get("records")
        .and_then(|r| r.as_array())
        .and_then(|a| a.first())
        .and_then(|r| r.get("pendingAssets"))
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|a| a.get("uploadURL"))
        .and_then(|u| u.as_str())
        .map(|s| s.to_string())
}
