//! SRP-6a login against Apple's `idmsa.apple.com/appleauth/auth`.
//!
//! The real flow is:
//!
//! 1. `POST /signin/init` with `a` (client public) → Apple returns
//!    `B` (server public), `salt`, `iteration`, and `protocol`
//!    (always `s2k` or `s2k_fo`).
//! 2. Derive the SRP key using PBKDF2-HMAC-SHA256 over the Apple
//!    ID password + salt, then the SRP-6a client proof via the
//!    `srp` crate.
//! 3. `POST /signin/complete` with `M1` (client proof) → Apple
//!    returns either `hsa2` (2FA) or an auth session token.
//!
//! This module performs those three requests and returns an
//! [`SrpOutcome`] describing what happened. The calling
//! `ICloudAuth::login` decides whether to propagate the 2FA signal
//! or proceed to CloudKit.

use base64::Engine;
use bibliotheca_sync_core::error::{Error, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use srp::client::SrpClient;
use srp::groups::G_2048;

use super::anisette::AnisetteData;
use crate::{ICloudConfig, ICloudCreds};

#[derive(Debug, Clone)]
pub struct SrpOutcome {
    pub needs_two_factor: bool,
    pub session_token: Option<String>,
    pub session_id: Option<String>,
    pub scnt: Option<String>,
}

#[derive(Debug, Serialize)]
struct SigninInit<'a> {
    a: String,
    #[serde(rename = "accountName")]
    account_name: &'a str,
    protocols: Vec<&'a str>,
}

#[derive(Debug, Deserialize)]
struct SigninInitResponse {
    #[serde(rename = "b")]
    b: Option<String>,
    #[serde(rename = "c")]
    c: Option<String>,
    #[serde(rename = "salt")]
    salt: Option<String>,
    #[serde(rename = "iteration")]
    iteration: Option<u32>,
    #[serde(rename = "protocol")]
    protocol: Option<String>,
    #[serde(rename = "authType")]
    auth_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct SigninComplete<'a> {
    #[serde(rename = "accountName")]
    account_name: &'a str,
    #[serde(rename = "m1")]
    m1: String,
    #[serde(rename = "m2")]
    m2: String,
    c: String,
    #[serde(rename = "rememberMe")]
    remember_me: bool,
    #[serde(rename = "trustTokens")]
    trust_tokens: Vec<String>,
}

pub async fn perform(
    http: &Client,
    config: &ICloudConfig,
    creds: &ICloudCreds,
    anisette: &AnisetteData,
) -> Result<SrpOutcome> {
    // Phase 1: init
    let client = SrpClient::<Sha256>::new(&G_2048);
    let a_bytes: [u8; 32] = rand::random();
    let a_pub = client.compute_public_ephemeral(&a_bytes);
    let init = SigninInit {
        a: base64::engine::general_purpose::STANDARD.encode(&a_pub),
        account_name: &creds.apple_id,
        protocols: vec!["s2k", "s2k_fo"],
    };
    let init_resp = http
        .post(format!("{}/appleauth/auth/signin/init", config.auth_url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header("X-Apple-OAuth-Client-Id", apple_oauth_client_id())
        .header("X-Apple-OAuth-Require-Grant-Code", "true")
        .header("X-Apple-Widget-Key", apple_widget_key())
        .headers(anisette_headers(anisette))
        .json(&init)
        .send()
        .await
        .map_err(|e| Error::Transient(format!("signin/init: {e}")))?;
    let status = init_resp.status();
    if !status.is_success() {
        return Err(Error::Fatal(format!("signin/init http {status}")));
    }
    let init_body: SigninInitResponse = init_resp
        .json()
        .await
        .map_err(|e| Error::Fatal(format!("signin/init body: {e}")))?;

    let b_b64 = init_body
        .b
        .ok_or_else(|| Error::Fatal("signin/init missing b".into()))?;
    let salt_b64 = init_body
        .salt
        .ok_or_else(|| Error::Fatal("signin/init missing salt".into()))?;
    let iterations = init_body
        .iteration
        .ok_or_else(|| Error::Fatal("signin/init missing iteration".into()))?;
    let c_token = init_body
        .c
        .ok_or_else(|| Error::Fatal("signin/init missing c".into()))?;
    let protocol = init_body.protocol.unwrap_or_else(|| "s2k".into());

    let b_bytes = base64::engine::general_purpose::STANDARD
        .decode(b_b64.as_bytes())
        .map_err(|e| Error::Fatal(format!("b64 b: {e}")))?;
    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(salt_b64.as_bytes())
        .map_err(|e| Error::Fatal(format!("b64 salt: {e}")))?;

    // Apple's PBKDF2 input is a SHA-256 (or double-SHA-256 for
    // `s2k_fo`) hash of the password.
    let pwd_pre = hash_password(&creds.password, &protocol);
    let mut pbkdf2_out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(&pwd_pre, &salt_bytes, iterations, &mut pbkdf2_out);

    let verifier = client
        .process_reply(
            &a_bytes,
            creds.apple_id.as_bytes(),
            &pbkdf2_out,
            &salt_bytes,
            &b_bytes,
        )
        .map_err(|e| Error::Fatal(format!("srp process_reply: {e:?}")))?;
    let m1 = verifier.proof().to_vec();

    // Phase 2: complete.
    let complete = SigninComplete {
        account_name: &creds.apple_id,
        m1: base64::engine::general_purpose::STANDARD.encode(&m1),
        m2: String::new(), // Apple echoes M2 back in the response
        c: c_token,
        remember_me: true,
        trust_tokens: creds
            .trust_token
            .as_ref()
            .map(|t| vec![t.clone()])
            .unwrap_or_default(),
    };
    let complete_resp = http
        .post(format!(
            "{}/appleauth/auth/signin/complete",
            config.auth_url
        ))
        .header("Content-Type", "application/json")
        .header("X-Apple-OAuth-Client-Id", apple_oauth_client_id())
        .header("X-Apple-Widget-Key", apple_widget_key())
        .headers(anisette_headers(anisette))
        .json(&complete)
        .send()
        .await
        .map_err(|e| Error::Transient(format!("signin/complete: {e}")))?;
    let status = complete_resp.status();
    let headers = complete_resp.headers().clone();
    let auth_type = init_body.auth_type.unwrap_or_default();
    let needs_two_factor = auth_type == "hsa2";

    let session_id = headers
        .get("X-Apple-ID-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let scnt = headers
        .get("scnt")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let session_token = headers
        .get("X-Apple-Session-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if !status.is_success() && status.as_u16() != 409 {
        // 409 is Apple's "two-factor required" response code.
        return Err(Error::Fatal(format!("signin/complete http {status}")));
    }

    Ok(SrpOutcome {
        needs_two_factor: needs_two_factor || status.as_u16() == 409,
        session_token,
        session_id,
        scnt,
    })
}

fn hash_password(password: &str, protocol: &str) -> Vec<u8> {
    use sha2::Digest;
    let first = Sha256::digest(password.as_bytes());
    if protocol == "s2k_fo" {
        // Apple's `s2k_fo` pre-hashes twice then hex-encodes the
        // second digest. This detail is stable since mid-2023.
        let hex_first = hex::encode(first);
        Sha256::digest(hex_first.as_bytes()).to_vec()
    } else {
        first.to_vec()
    }
}

fn anisette_headers(a: &AnisetteData) -> reqwest::header::HeaderMap {
    super::srp_headers(a)
}

fn apple_oauth_client_id() -> &'static str {
    // Public constants pyicloud uses; Apple keys them on the web
    // auth widget for icloud.com.
    "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"
}

fn apple_widget_key() -> &'static str {
    "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"
}
