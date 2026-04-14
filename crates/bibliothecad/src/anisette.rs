//! Embedded anisette proxy boot wiring.
//!
//! When operators pass `--anisette-upstream` (repeatable) on the
//! daemon command line, `bibliothecad` spawns a tokio task that
//! serves the `bibliotheca-anisette` HTTP proxy on
//! `--anisette-listen`. `sync-icloud` mounts can then point at the
//! local address as their `anisette_url`, and the daemon
//! federates the OTP requests out to whatever operator-controlled
//! upstream anisette servers are configured.

use std::net::SocketAddr;
use std::sync::Arc;

use bibliotheca_anisette::{
    serve, AnisetteProvider, AnisetteServerConfig, ProxyConfig, ProxyProvider,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use url::Url;

#[derive(Debug, Clone)]
pub struct AnisetteBootConfig {
    pub listen: SocketAddr,
    pub upstreams: Vec<Url>,
    pub cache_ttl_secs: u64,
    pub request_timeout_secs: u64,
    pub backoff_secs: u64,
}

pub fn boot(
    cfg: Option<AnisetteBootConfig>,
    shutdown: CancellationToken,
) -> Option<Arc<dyn AnisetteProvider>> {
    let cfg = cfg?;
    if cfg.upstreams.is_empty() {
        warn!(
            "anisette proxy enabled but no upstreams configured; \
             skipping. Pass --anisette-upstream <url> to enable."
        );
        return None;
    }
    let provider = match ProxyProvider::new(ProxyConfig {
        upstreams: cfg.upstreams.clone(),
        cache_ttl_secs: cfg.cache_ttl_secs,
        request_timeout_secs: cfg.request_timeout_secs,
        backoff_secs: cfg.backoff_secs,
    }) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!(error = %e, "failed to construct anisette proxy");
            return None;
        }
    };
    let dyn_provider: Arc<dyn AnisetteProvider> = provider.clone();

    let listen = cfg.listen;
    let server_provider = dyn_provider.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            res = serve(
                server_provider,
                AnisetteServerConfig { listen },
            ) => {
                if let Err(e) = res {
                    warn!(error = %e, "anisette proxy exited");
                }
            }
        }
    });
    info!(addr = %listen, upstreams = ?cfg.upstreams, "anisette proxy enabled");
    Some(dyn_provider)
}
