//! Anisette-v3 HTTP client.
//!
//! Calls out to an externally-hosted `anisette-v3-server` (the same
//! one projects like `icloudpd` and the Pypush community use) at
//! `POST /v3/get_anisette_data`. Returns the opaque headers Apple
//! requires on every iCloud auth request.
//!
//! Self-generating anisette requires secrets burned into Apple
//! devices and is explicitly out of scope — we point at an
//! external provider via the mount's credential blob.

use bibliotheca_sync_core::error::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct AnisetteData {
    #[serde(rename = "X-Apple-I-MD")]
    pub md: String,
    #[serde(rename = "X-Apple-I-MD-M")]
    pub md_m: String,
    #[serde(rename = "X-Apple-I-MD-RINFO")]
    #[serde(default)]
    pub md_rinfo: String,
    #[serde(rename = "X-Apple-I-MD-LU")]
    #[serde(default)]
    pub md_lu: String,
    #[serde(rename = "X-Apple-I-SRL-NO")]
    #[serde(default)]
    pub srl_no: String,
    #[serde(rename = "X-Mme-Device-Id")]
    #[serde(default)]
    pub device_id: String,
    #[serde(rename = "X-Apple-I-Client-Time")]
    #[serde(default)]
    pub client_time: String,
    #[serde(rename = "X-Apple-Locale")]
    #[serde(default)]
    pub locale: String,
    #[serde(rename = "X-Apple-I-TimeZone")]
    #[serde(default)]
    pub time_zone: String,
}

impl AnisetteData {
    pub fn as_headers(&self) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("X-Apple-I-MD".into(), self.md.clone());
        h.insert("X-Apple-I-MD-M".into(), self.md_m.clone());
        if !self.md_rinfo.is_empty() {
            h.insert("X-Apple-I-MD-RINFO".into(), self.md_rinfo.clone());
        }
        if !self.md_lu.is_empty() {
            h.insert("X-Apple-I-MD-LU".into(), self.md_lu.clone());
        }
        if !self.srl_no.is_empty() {
            h.insert("X-Apple-I-SRL-NO".into(), self.srl_no.clone());
        }
        if !self.device_id.is_empty() {
            h.insert("X-Mme-Device-Id".into(), self.device_id.clone());
        }
        if !self.client_time.is_empty() {
            h.insert("X-Apple-I-Client-Time".into(), self.client_time.clone());
        }
        if !self.locale.is_empty() {
            h.insert("X-Apple-Locale".into(), self.locale.clone());
        }
        if !self.time_zone.is_empty() {
            h.insert("X-Apple-I-TimeZone".into(), self.time_zone.clone());
        }
        h
    }
}

pub async fn fetch(http: &reqwest::Client, anisette_url: &str) -> Result<AnisetteData> {
    let url = format!(
        "{}/v3/get_anisette_data",
        anisette_url.trim_end_matches('/')
    );
    let resp = http
        .post(&url)
        .send()
        .await
        .map_err(|e| Error::Transient(format!("anisette: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Fatal(format!("anisette server {}", resp.status())));
    }
    let data = resp
        .json::<AnisetteData>()
        .await
        .map_err(|e| Error::Fatal(format!("anisette body: {e}")))?;
    Ok(data)
}
