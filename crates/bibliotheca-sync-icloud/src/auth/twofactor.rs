//! hsa2 two-factor verification.
//!
//! When SRP returns `authType: hsa2`, the real connector path
//! pauses the mount and emits a `need_2fa` event. The operator
//! runs `bibliothecactl sync twofactor submit <id> <code>`, which
//! routes into `Supervisor::submit_twofactor` and fills the
//! per-worker oneshot. This module owns the "send `verify` + bank
//! the trust token" flow once a code is in hand.

use bibliotheca_sync_core::error::{Error, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::anisette::AnisetteData;
use crate::ICloudConfig;

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    #[serde(rename = "securityCode")]
    security_code: SecurityCode<'a>,
}

#[derive(Debug, Serialize)]
struct SecurityCode<'a> {
    code: &'a str,
}

#[derive(Debug, Deserialize)]
struct TrustResponse {
    #[serde(default, rename = "trustToken")]
    trust_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TwoFactorOutcome {
    pub trust_token: Option<String>,
}

pub async fn verify(
    http: &Client,
    config: &ICloudConfig,
    anisette: &AnisetteData,
    session_id: &str,
    scnt: &str,
    code: &str,
) -> Result<TwoFactorOutcome> {
    let body = VerifyRequest {
        security_code: SecurityCode { code },
    };
    let verify_resp = http
        .post(format!(
            "{}/appleauth/auth/verify/trusteddevice/securitycode",
            config.auth_url
        ))
        .header("scnt", scnt)
        .header("X-Apple-ID-Session-Id", session_id)
        .header("Content-Type", "application/json")
        .headers(super::srp_headers(anisette))
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Transient(format!("2fa verify: {e}")))?;
    if !verify_resp.status().is_success() {
        return Err(Error::Fatal(format!(
            "2fa verify http {}",
            verify_resp.status()
        )));
    }

    // Trust the device — this returns the trust_token we persist
    // back into the credential blob so future logins skip 2FA.
    let trust_resp = http
        .get(format!("{}/appleauth/auth/2sv/trust", config.auth_url))
        .header("scnt", scnt)
        .header("X-Apple-ID-Session-Id", session_id)
        .headers(super::srp_headers(anisette))
        .send()
        .await
        .map_err(|e| Error::Transient(format!("2fa trust: {e}")))?;
    let trust_token = if trust_resp.status().is_success() {
        trust_resp
            .json::<TrustResponse>()
            .await
            .ok()
            .and_then(|r| r.trust_token)
    } else {
        None
    };
    Ok(TwoFactorOutcome { trust_token })
}
