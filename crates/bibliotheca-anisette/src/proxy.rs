//! The real [`AnisetteProvider`] implementation: a round-robin
//! proxy over one or more upstream `POST /v3/get_anisette_data`
//! endpoints with failover + optional short-TTL caching.
//!
//! Upstream URLs can be any anisette-v3-compatible server — a
//! self-hosted one on the LAN, or a public community server like
//! `ani.sidestore.io`. The proxy does not talk to Apple directly;
//! that's the upstream's job.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tracing::{debug, warn};
use url::Url;

use crate::error::{Error, Result};
use crate::provider::{AnisetteHeaders, AnisetteProvider, ProviderStatus, UpstreamHealth};

/// Runtime configuration for the proxy provider.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Ordered list of upstream anisette servers. The proxy
    /// round-robins across healthy entries and marks one as
    /// "unhealthy" for [`ProxyConfig::backoff_secs`] seconds on
    /// the first failure.
    pub upstreams: Vec<Url>,
    /// Cache a successful `AnisetteHeaders` response for this
    /// many seconds so a burst of sync cycles doesn't hammer the
    /// upstream. Apple's OTPs are valid for roughly 30 s; 20 s is
    /// a safe default. Set to 0 to disable caching.
    pub cache_ttl_secs: u64,
    /// Per-request timeout. Upstream servers sometimes wedge for
    /// tens of seconds; we'd rather fail over fast.
    pub request_timeout_secs: u64,
    /// How long to mark an upstream as down after a failed call
    /// before considering it again.
    pub backoff_secs: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            cache_ttl_secs: 20,
            request_timeout_secs: 10,
            backoff_secs: 60,
        }
    }
}

pub struct ProxyProvider {
    http: reqwest::Client,
    config: ProxyConfig,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    next_upstream: usize,
    upstreams: Vec<UpstreamState>,
    cached: Option<CachedResponse>,
    last_success_at: Option<i64>,
}

#[derive(Clone)]
struct UpstreamState {
    url: String,
    ok: u64,
    err: u64,
    last_error: Option<String>,
    unhealthy_until: Option<i64>,
}

#[derive(Clone)]
struct CachedResponse {
    headers: AnisetteHeaders,
    expires_at: i64,
}

impl ProxyProvider {
    pub fn new(config: ProxyConfig) -> Result<Self> {
        if config.upstreams.is_empty() {
            return Err(Error::NoUpstreams);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .build()?;
        let upstreams = config
            .upstreams
            .iter()
            .map(|u| UpstreamState {
                url: u.to_string(),
                ok: 0,
                err: 0,
                last_error: None,
                unhealthy_until: None,
            })
            .collect();
        Ok(Self {
            http,
            config,
            state: Arc::new(Mutex::new(State {
                next_upstream: 0,
                upstreams,
                cached: None,
                last_success_at: None,
            })),
        })
    }

    fn pick_upstream(&self) -> Option<(usize, String)> {
        let mut g = self.state.lock();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let n = g.upstreams.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            let idx = g.next_upstream % n;
            g.next_upstream = g.next_upstream.wrapping_add(1);
            let healthy = g.upstreams[idx]
                .unhealthy_until
                .map(|t| t <= now)
                .unwrap_or(true);
            if healthy {
                return Some((idx, g.upstreams[idx].url.clone()));
            }
        }
        // All upstreams backing off — fall back to the round-robin
        // winner anyway; the caller will propagate the error.
        let idx = g.next_upstream % n;
        g.next_upstream = g.next_upstream.wrapping_add(1);
        Some((idx, g.upstreams[idx].url.clone()))
    }

    fn record_success(&self, idx: usize, headers: &AnisetteHeaders) {
        let mut g = self.state.lock();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if let Some(u) = g.upstreams.get_mut(idx) {
            u.ok += 1;
            u.unhealthy_until = None;
            u.last_error = None;
        }
        g.last_success_at = Some(now);
        if self.config.cache_ttl_secs > 0 {
            g.cached = Some(CachedResponse {
                headers: headers.clone(),
                expires_at: now + self.config.cache_ttl_secs as i64,
            });
        }
    }

    fn record_failure(&self, idx: usize, err: &Error) {
        let mut g = self.state.lock();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if let Some(u) = g.upstreams.get_mut(idx) {
            u.err += 1;
            u.last_error = Some(err.to_string());
            u.unhealthy_until = Some(now + self.config.backoff_secs as i64);
        }
    }

    fn cached(&self) -> Option<AnisetteHeaders> {
        let g = self.state.lock();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        g.cached
            .as_ref()
            .filter(|c| c.expires_at > now)
            .map(|c| c.headers.clone())
    }

    async fn try_upstream(&self, url: &str) -> Result<AnisetteHeaders> {
        let endpoint = format!("{}/v3/get_anisette_data", url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&endpoint)
            .header("User-Agent", "bibliotheca-anisette/0.1")
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::UpstreamStatus {
                upstream: url.to_string(),
                status: status.as_u16(),
            });
        }
        let headers: AnisetteHeaders = resp
            .json()
            .await
            .map_err(|e| Error::BodyParse(e.to_string()))?;
        Ok(headers)
    }
}

#[async_trait]
impl AnisetteProvider for ProxyProvider {
    async fn get(&self) -> Result<AnisetteHeaders> {
        if let Some(cached) = self.cached() {
            debug!("anisette cache hit");
            return Ok(cached);
        }
        let n = self.state.lock().upstreams.len();
        if n == 0 {
            return Err(Error::NoUpstreams);
        }
        let mut last_error: Option<Error> = None;
        for _ in 0..n {
            let Some((idx, url)) = self.pick_upstream() else {
                break;
            };
            match self.try_upstream(&url).await {
                Ok(headers) => {
                    self.record_success(idx, &headers);
                    return Ok(headers);
                }
                Err(e) => {
                    warn!(upstream = %url, error = %e, "anisette upstream failed");
                    self.record_failure(idx, &e);
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or(Error::AllUpstreamsDown))
    }

    fn status(&self) -> ProviderStatus {
        let g = self.state.lock();
        let upstreams = g
            .upstreams
            .iter()
            .map(|u| UpstreamHealth {
                url: u.url.clone(),
                ok_count: u.ok,
                err_count: u.err,
                last_error: u.last_error.clone(),
            })
            .collect();
        let cached_until = g.cached.as_ref().map(|c| c.expires_at);
        ProviderStatus {
            kind: "proxy".into(),
            upstreams,
            last_success_at: g.last_success_at,
            cached_until,
        }
    }

    fn reset(&self) {
        let mut g = self.state.lock();
        g.cached = None;
        for u in g.upstreams.iter_mut() {
            u.unhealthy_until = None;
            u.last_error = None;
        }
    }

    fn add_upstream(&self, url: &str) -> Result<()> {
        let parsed = Url::parse(url).map_err(|e| Error::InvalidUrl(e.to_string()))?;
        let canonical = parsed.to_string();
        let mut g = self.state.lock();
        if g.upstreams.iter().any(|u| u.url == canonical) {
            return Err(Error::AlreadyExists(canonical));
        }
        g.upstreams.push(UpstreamState {
            url: canonical,
            ok: 0,
            err: 0,
            last_error: None,
            unhealthy_until: None,
        });
        Ok(())
    }

    fn remove_upstream(&self, url: &str) -> Result<()> {
        let canonical = Url::parse(url)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| url.to_string());
        let mut g = self.state.lock();
        let before = g.upstreams.len();
        g.upstreams.retain(|u| u.url != canonical);
        if g.upstreams.len() == before {
            return Err(Error::NotFound(canonical));
        }
        // Reset the round-robin pointer if we've outrun the tail.
        if g.next_upstream >= g.upstreams.len() {
            g.next_upstream = 0;
        }
        Ok(())
    }

    fn upstreams(&self) -> Vec<String> {
        self.state
            .lock()
            .upstreams
            .iter()
            .map(|u| u.url.clone())
            .collect()
    }
}
