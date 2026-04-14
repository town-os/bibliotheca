//! /account/authenticate client.

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};

use super::TownosCreds;

#[derive(Debug, Serialize)]
struct LoginRequest<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    token: String,
    #[serde(default)]
    #[allow(dead_code)]
    account: Option<serde_json::Value>,
}

pub async fn login(http: &Client, base_url: &Url, creds: &TownosCreds) -> Result<String> {
    let url = base_url
        .join("account/authenticate")
        .map_err(|e| Error::Townos(format!("url: {e}")))?;
    let resp = http
        .post(url)
        .json(&LoginRequest {
            username: &creds.username,
            password: &creds.password,
        })
        .send()
        .await?;
    let status = resp.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(Error::Townos("authentication failed".into()));
    }
    if !status.is_success() {
        return Err(Error::Townos(format!("login http {status}")));
    }
    let body: LoginResponse = resp.json().await?;
    if body.token.is_empty() {
        return Err(Error::Townos("empty token in login response".into()));
    }
    Ok(body.token)
}
