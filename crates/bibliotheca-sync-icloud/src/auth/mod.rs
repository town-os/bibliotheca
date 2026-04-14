//! iCloud authentication flow.
//!
//! Isolated inside this submodule so that when Apple changes the
//! SRP-6a handshake or the accountLogin payload shape (it happens
//! every six to twelve months), the diff stays local. The rest of
//! the crate reads only the outputs: an opaque `ICloudSession`
//! bearing session cookies, a DS info blob, and the CloudKit
//! endpoint map.

pub mod anisette;
pub mod session;
pub mod srp;
pub mod twofactor;

use anisette::AnisetteData;

/// Build a reqwest HeaderMap from anisette data — used by both
/// the srp and twofactor modules.
pub(crate) fn srp_headers(a: &AnisetteData) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    for (k, v) in a.as_headers() {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(&v),
        ) {
            h.insert(name, val);
        }
    }
    h
}

use std::sync::Arc;

use bibliotheca_sync_core::error::{Error, Result};
use reqwest::cookie::Jar;

use crate::{ICloudConfig, ICloudCreds};

pub use session::ICloudSession;

pub struct ICloudAuth {
    config: ICloudConfig,
    creds: ICloudCreds,
}

impl ICloudAuth {
    pub fn new(config: ICloudConfig, creds: ICloudCreds) -> Self {
        Self { config, creds }
    }

    pub async fn login(&self) -> Result<ICloudSession> {
        let jar = Arc::new(Jar::default());
        let http = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Fatal(format!("build http: {e}")))?;

        let anisette = anisette::fetch(&http, &self.creds.anisette_url).await?;

        let srp_outcome = srp::perform(&http, &self.config, &self.creds, &anisette).await?;

        // A `hsa2` response is the sentinel for "operator must
        // supply a 2FA code". The supervisor surfaces this through
        // its event stream; for now we propagate the flag and let
        // the calling `ensure_session` bail. Phase 5b wires the
        // oneshot bridge through here.
        if srp_outcome.needs_two_factor {
            return Err(Error::NeedsTwoFactor);
        }

        let session = session::finalize(&http, &self.config, &srp_outcome, jar.clone()).await?;
        Ok(session)
    }
}
