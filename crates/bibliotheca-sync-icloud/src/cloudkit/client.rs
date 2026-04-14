//! Thin CloudKit Web Services POST client.
//!
//! Every RPC against `ckdatabasews.icloud.com` is a POST that
//! carries an `X-CloudKit-UserId` + `X-CloudKit-AuthToken` header
//! pair derived from the session. The URL shape is:
//!
//! ```text
//! /database/1/{container}/{env}/{scope}/{operation}
//! ```
//!
//! For Photos, `container = com.apple.photos.cloud`,
//! `env = production`, and `scope = private`. Operations we use
//! are `records/query` and `records/modify`.

use bibliotheca_sync_core::error::{Error, Result};
use bytes::Bytes;
use reqwest::Client;
use serde::Serialize;

use crate::auth::ICloudSession;
use crate::ICloudConfig;

pub struct CloudKitClient {
    http: Client,
    config: ICloudConfig,
    session: ICloudSession,
}

impl CloudKitClient {
    pub fn new(config: ICloudConfig, session: ICloudSession) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("cloudkit reqwest"),
            config,
            session,
        }
    }

    pub fn config(&self) -> &ICloudConfig {
        &self.config
    }

    pub fn session(&self) -> &ICloudSession {
        &self.session
    }

    fn url_for(&self, op: &str) -> String {
        format!(
            "{}/database/1/{}/production/private/{op}",
            self.session.ck_database_url.trim_end_matches('/'),
            self.config.container
        )
    }

    pub async fn post_json<Req: Serialize>(
        &self,
        op: &str,
        body: &Req,
    ) -> Result<serde_json::Value> {
        let url = self.url_for(op);
        let resp = self
            .http
            .post(&url)
            .header("X-CloudKit-UserId", &self.session.dsid)
            .header("X-CloudKit-AuthToken", &self.session.auth_token)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("cloudkit {op}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Transient(format!(
                "cloudkit {op} http {status}: {text}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| Error::Transient(format!("cloudkit {op} body: {e}")))
    }

    pub async fn get_bytes(&self, url: &str) -> Result<Bytes> {
        let resp = self
            .http
            .get(url)
            .header("X-CloudKit-UserId", &self.session.dsid)
            .header("X-CloudKit-AuthToken", &self.session.auth_token)
            .send()
            .await
            .map_err(|e| Error::Transient(format!("cloudkit asset fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Transient(format!(
                "cloudkit asset http {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map_err(|e| Error::Transient(format!("cloudkit asset body: {e}")))
    }

    pub async fn put_bytes(&self, url: &str, bytes: &[u8]) -> Result<serde_json::Value> {
        let resp = self
            .http
            .put(url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| Error::Transient(format!("cloudkit asset put: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Transient(format!(
                "cloudkit asset put http {}",
                resp.status()
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .or_else(|_| Ok(serde_json::Value::Null))
    }
}
