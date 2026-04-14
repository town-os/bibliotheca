//! /storage/* client.

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{Filesystem, TownosClient};

#[derive(Debug, Serialize)]
struct CreateRequest<'a> {
    name: &'a str,
    quota: u64,
}

#[derive(Debug, Serialize)]
struct ModifyRequest<'a> {
    name: &'a str,
    filesystem: Filesystem,
    #[serde(skip_serializing_if = "Option::is_none")]
    _unused: Option<&'a ()>,
}

#[derive(Debug, Serialize)]
struct NameRequest<'a> {
    name: &'a str,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    entries: Vec<Filesystem>,
}

async fn do_post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    client: &TownosClient,
    path: &str,
    body: &T,
) -> Result<R> {
    let url = client
        .base_url()
        .join(path)
        .map_err(|e| Error::Townos(format!("url: {e}")))?;
    for attempt in 0..2 {
        let token = client.authenticate().await?;
        let resp = client
            .http()
            .post(url.clone())
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED && attempt == 0 {
            client.invalidate_token();
            continue;
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Townos(format!("{path} http {status}: {text}")));
        }
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            // Some endpoints return an empty body on success. R
            // must be `()` or `serde_json::Value::Null` in that case.
            let null = serde_json::Value::Null;
            return serde_json::from_value(null).map_err(Error::from);
        }
        return serde_json::from_slice(&bytes).map_err(Error::from);
    }
    Err(Error::Townos("exhausted reauth retries".into()))
}

async fn do_post_empty<T: serde::Serialize>(
    client: &TownosClient,
    path: &str,
    body: &T,
) -> Result<()> {
    let _: serde_json::Value = do_post(client, path, body).await?;
    Ok(())
}

pub async fn create(client: &TownosClient, name: &str, quota: u64) -> Result<String> {
    do_post_empty(client, "storage/create", &CreateRequest { name, quota }).await?;
    Ok(name.to_string())
}

pub async fn modify(
    client: &TownosClient,
    current_name: &str,
    new_name: Option<&str>,
    new_quota: Option<u64>,
) -> Result<()> {
    let fs = Filesystem {
        name: new_name.unwrap_or(current_name).to_string(),
        quota: new_quota.unwrap_or(0),
        state: None,
    };
    let body = serde_json::json!({
        "name": current_name,
        "filesystem": fs,
    });
    do_post_empty(client, "storage/modify", &body).await
}

pub async fn remove(client: &TownosClient, name: &str) -> Result<()> {
    do_post_empty(client, "storage/remove", &NameRequest { name }).await
}

pub async fn list(client: &TownosClient, prefix: &str) -> Result<Vec<Filesystem>> {
    let body = serde_json::json!({ "name": prefix });
    let resp: ListResponse = do_post(client, "storage", &body).await?;
    Ok(resp.entries)
}

// Suppress dead-code on the unused helper struct above so we can
// keep the Serde import paths clean.
#[allow(dead_code)]
fn _touch_modify_request(_: ModifyRequest<'_>) {}
