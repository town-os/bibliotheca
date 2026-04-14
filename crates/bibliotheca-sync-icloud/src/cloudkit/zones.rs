//! Hard-coded CloudKit zone constants for the Photos container.
//!
//! Every `records/query` and `records/modify` call against
//! `com.apple.photos.cloud` targets the `PrimarySync` zone in the
//! user's private database. Asset metadata lives in `CPLAsset`
//! records; thumbnails and full-resolution originals are
//! referenced through signed URLs embedded in the record fields.

pub const RECORD_TYPE_CPL_ASSET: &str = "CPLAsset";
pub const RECORD_TYPE_CPL_MASTER: &str = "CPLMaster";
pub const RECORD_TYPE_DELETED: &str = "CPLAssetAndMasterDeletedByExpungedDate";

pub const ZONE_PRIMARY: &str = "PrimarySync";

/// Field names inside a `CPLAsset` record we care about for sync.
pub mod fields {
    pub const FILENAME: &str = "filenameEnc";
    pub const ASSET_DATE: &str = "assetDate";
    pub const RESOURCE: &str = "resJPEGFullRes";
    pub const RESOURCE_ORIGINAL: &str = "originalRes";
    pub const MEDIA_TYPE: &str = "mediaType";
}
