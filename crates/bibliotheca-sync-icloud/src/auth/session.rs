//! CloudKit session finalization.
//!
//! After SRP (and optional 2FA) succeeds, we exchange the session
//! token for a CloudKit Web Services session by POSTing to
//! `setup.icloud.com/setup/ws/1/accountLogin`. Apple's response
//! carries a `webservices` map whose keys are the CloudKit
//! capability names (`ckdatabasews`, `photos`, etc.) and whose
//! values include the production/development host each capability
//! is pinned to. We keep only what `bibliotheca-sync-icloud`
//! touches — the ckdatabasews URL and the dsInfo — and stash it
//! in an `ICloudSession` that the rest of the crate passes
//! around.

use std::sync::Arc;

use bibliotheca_sync_core::error::{Error, Result};
use reqwest::cookie::Jar;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::srp::SrpOutcome;
use crate::ICloudConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ICloudSession {
    pub dsid: String,
    pub ck_database_url: String,
    pub cookies: Vec<u8>,
    pub auth_token: String,
}

#[derive(Debug, Deserialize)]
struct AccountLoginResponse {
    #[serde(default, rename = "dsInfo")]
    ds_info: Option<serde_json::Value>,
    #[serde(default)]
    webservices: Option<serde_json::Value>,
}

pub async fn finalize(
    http: &Client,
    config: &ICloudConfig,
    srp: &SrpOutcome,
    jar: Arc<Jar>,
) -> Result<ICloudSession> {
    let auth_token = srp
        .session_token
        .clone()
        .ok_or_else(|| Error::Fatal("no session token from srp".into()))?;
    let body = json!({
        "dsWebAuthToken": auth_token,
        "accountCountryCode": "USA",
        "extended_login": true,
    });
    let resp = http
        .post(format!("{}/setup/ws/1/accountLogin", config.setup_url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Transient(format!("accountLogin: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Fatal(format!("accountLogin http {}", resp.status())));
    }
    let resp: AccountLoginResponse = resp
        .json()
        .await
        .map_err(|e| Error::Fatal(format!("accountLogin body: {e}")))?;
    let ds_info = resp
        .ds_info
        .ok_or_else(|| Error::Fatal("no dsInfo".into()))?;
    let dsid = ds_info
        .get("dsid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let ck_database_url = resp
        .webservices
        .as_ref()
        .and_then(|w| w.get("ckdatabasews"))
        .and_then(|c| c.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or(&config.ckdb_url)
        .to_string();

    // Serialize the cookie jar so the supervisor can persist it
    // across restarts by writing the credential blob back through
    // `SyncStateStore::update_credentials`.
    let _ = jar; // reqwest's Jar doesn't expose a public serializer
                 // yet — Phase 5b will stringify via the
                 // `cookie_store` crate if we decide to persist.
    Ok(ICloudSession {
        dsid,
        ck_database_url,
        cookies: Vec::new(),
        auth_token,
    })
}
