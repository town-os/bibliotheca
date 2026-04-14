//! `AnisetteProvider` trait and the test-only `MockProvider`.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// The eight headers Apple's auth flow expects on every iCloud
/// request. Field names match the JSON shape returned by
/// `anisette-v3-server` so a client switching between the two is a
/// pure URL swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnisetteHeaders {
    #[serde(rename = "X-Apple-I-MD")]
    pub md: String,
    #[serde(rename = "X-Apple-I-MD-M")]
    pub md_m: String,
    #[serde(rename = "X-Apple-I-MD-RINFO", default)]
    pub md_rinfo: String,
    #[serde(rename = "X-Apple-I-MD-LU", default)]
    pub md_lu: String,
    #[serde(rename = "X-Mme-Device-Id", default)]
    pub device_id: String,
    #[serde(rename = "X-Apple-I-Client-Time", default)]
    pub client_time: String,
    #[serde(rename = "X-Apple-Locale", default)]
    pub locale: String,
    #[serde(rename = "X-Apple-I-TimeZone", default)]
    pub time_zone: String,
}

/// Snapshot of a provider's current operational state, surfaced
/// through the HTTP `/status` endpoint and the daemon's gRPC
/// `AnisetteAdmin::Status` RPC.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderStatus {
    pub kind: String,
    pub upstreams: Vec<UpstreamHealth>,
    pub last_success_at: Option<i64>,
    pub cached_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamHealth {
    pub url: String,
    pub ok_count: u64,
    pub err_count: u64,
    pub last_error: Option<String>,
}

/// Trait every anisette provider implements. Concrete
/// implementations are [`crate::proxy::ProxyProvider`] (production)
/// and [`MockProvider`] (tests).
#[async_trait]
pub trait AnisetteProvider: Send + Sync + 'static {
    async fn get(&self) -> Result<AnisetteHeaders>;
    fn status(&self) -> ProviderStatus;
    fn reset(&self);

    /// Add a peer URL to the upstream pool at runtime. Providers
    /// that don't manage a peer list (e.g. `MockProvider`) return
    /// `Error::NotSupported`. Adding a URL already in the pool
    /// returns `Error::AlreadyExists`.
    fn add_upstream(&self, _url: &str) -> Result<()> {
        Err(crate::error::Error::NotSupported(
            "provider does not manage a dynamic upstream pool".into(),
        ))
    }

    /// Remove a peer URL from the upstream pool. Returns
    /// `Error::NotFound` if the URL wasn't there; providers that
    /// don't manage a pool return `Error::NotSupported`.
    fn remove_upstream(&self, _url: &str) -> Result<()> {
        Err(crate::error::Error::NotSupported(
            "provider does not manage a dynamic upstream pool".into(),
        ))
    }

    /// Current upstream URLs. Empty for providers that don't
    /// manage a pool.
    fn upstreams(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Test-only provider. Returns deterministic headers and counts
/// calls so integration tests can assert the HTTP surface without
/// reaching for a real upstream.
#[derive(Clone, Default)]
pub struct MockProvider {
    inner: Arc<Mutex<MockInner>>,
}

#[derive(Default)]
struct MockInner {
    calls: u64,
    last_success_at: Option<i64>,
    force_error: bool,
}

impl MockProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn force_error(&self, force: bool) {
        self.inner.lock().force_error = force;
    }

    pub fn calls(&self) -> u64 {
        self.inner.lock().calls
    }
}

#[async_trait]
impl AnisetteProvider for MockProvider {
    async fn get(&self) -> Result<AnisetteHeaders> {
        let mut g = self.inner.lock();
        if g.force_error {
            return Err(crate::error::Error::AllUpstreamsDown);
        }
        g.calls += 1;
        g.last_success_at = Some(time::OffsetDateTime::now_utc().unix_timestamp());
        Ok(AnisetteHeaders {
            md: format!("mock-md-{}", g.calls),
            md_m: "mock-md-m".into(),
            md_rinfo: "17106176".into(),
            md_lu: "mock-md-lu".into(),
            device_id: "mock-device-id".into(),
            client_time: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            locale: "en_US".into(),
            time_zone: "UTC".into(),
        })
    }

    fn status(&self) -> ProviderStatus {
        let g = self.inner.lock();
        ProviderStatus {
            kind: "mock".into(),
            upstreams: vec![UpstreamHealth {
                url: "mock://".into(),
                ok_count: g.calls,
                err_count: 0,
                last_error: None,
            }],
            last_success_at: g.last_success_at,
            cached_until: None,
        }
    }

    fn reset(&self) {
        *self.inner.lock() = MockInner::default();
    }
}
