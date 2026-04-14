//! `records/query` against `CPLAsset` in the Photos zone.

use bibliotheca_sync_core::error::{Error, Result};
use bibliotheca_sync_core::trait_::{Change, ListPage, RemoteObject};
use serde_json::json;
use time::OffsetDateTime;

use super::PhotosCursor;
use crate::cloudkit::zones::{RECORD_TYPE_CPL_ASSET, ZONE_PRIMARY};
use crate::cloudkit::CloudKitClient;

pub async fn list_since(client: &CloudKitClient, cursor: Option<&[u8]>) -> Result<ListPage> {
    let parsed: PhotosCursor = cursor
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_default();

    let body = json!({
        "zoneID": { "zoneName": ZONE_PRIMARY },
        "desiredKeys": [
            "filenameEnc",
            "assetDate",
            "resJPEGFullRes",
            "originalRes",
            "mediaType"
        ],
        "query": {
            "recordType": RECORD_TYPE_CPL_ASSET,
            "filterBy": []
        },
        "syncToken": parsed.sync_token,
        "resultsLimit": 100
    });
    let resp = client.post_json("records/query", &body).await?;

    let mut changes = Vec::new();
    if let Some(records) = resp.get("records").and_then(|r| r.as_array()) {
        for record in records {
            let Some(obj) = record_to_remote_object(record) else {
                continue;
            };
            changes.push(Change::Upsert(obj));
        }
    }
    let next_token = resp
        .get("syncToken")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let more = resp
        .get("moreComing")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let cursor_blob = serde_json::to_vec(&PhotosCursor {
        sync_token: next_token,
    })
    .map_err(Error::from)?;
    Ok(ListPage {
        changes,
        next_cursor: Some(cursor_blob),
        more,
    })
}

fn record_to_remote_object(record: &serde_json::Value) -> Option<RemoteObject> {
    let record_name = record
        .get("recordName")
        .and_then(|v| v.as_str())?
        .to_string();
    let fields = record.get("fields")?;
    let filename = fields
        .get("filenameEnc")
        .and_then(|f| f.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("photo.jpg")
        .to_string();
    let asset_date = fields
        .get("assetDate")
        .and_then(|f| f.get("value"))
        .and_then(|v| v.as_i64())
        .and_then(|ms| OffsetDateTime::from_unix_timestamp(ms / 1000).ok())
        .unwrap_or_else(OffsetDateTime::now_utc);
    let download = fields
        .get("resJPEGFullRes")
        .and_then(|f| f.get("value"))
        .and_then(|v| v.get("downloadURL"))
        .and_then(|u| u.as_str())
        .unwrap_or("")
        .to_string();
    let size = fields
        .get("resJPEGFullRes")
        .and_then(|f| f.get("value"))
        .and_then(|v| v.get("size"))
        .and_then(|s| s.as_u64())
        .unwrap_or(0);
    Some(RemoteObject {
        id: format!("{record_name}::{download}"),
        key: format!("{record_name}/{filename}"),
        size,
        etag: Some(record_name),
        modified: asset_date,
        is_dir: false,
    })
}
