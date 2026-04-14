//! Embedded anisette proxy boot wiring.
//!
//! When operators pass `--anisette-upstream` (repeatable) on the
//! daemon command line, `bibliothecad` spawns a tokio task that
//! serves the `bibliotheca-anisette` HTTP proxy on
//! `--anisette-listen`. `sync-icloud` mounts can then point at the
//! local address as their `anisette_url`, and the daemon
//! federates the OTP requests out to whatever operator-controlled
//! upstream anisette servers are configured.
//!
//! When the crate is built with the `mdns` feature, a second task
//! browses for `_bibliotheca-anisette._tcp.local.` advertisements
//! and dynamically feeds any matching peers into the provider's
//! upstream pool. Every discovered URL is also subject to the
//! usual round-robin + health-backoff behaviour.

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
    pub mdns_enabled: bool,
}

pub fn boot(
    cfg: Option<AnisetteBootConfig>,
    shutdown: CancellationToken,
) -> Option<Arc<dyn AnisetteProvider>> {
    let cfg = cfg?;
    if cfg.upstreams.is_empty() && !cfg.mdns_enabled {
        warn!(
            "anisette proxy enabled but no upstreams configured and mDNS \
             discovery disabled; skipping. Pass --anisette-upstream <url> \
             or enable the mdns feature."
        );
        return None;
    }
    // The ProxyProvider requires a non-empty upstream list at
    // construction. If the operator is leaning on mDNS discovery
    // alone, fall back to a placeholder localhost URL that gets
    // removed once the first mDNS advertisement arrives. Before
    // then, any proxy fetch will simply fail with a transient
    // error, which the sync supervisor already handles.
    let bootstrap_upstreams = if cfg.upstreams.is_empty() {
        vec![Url::parse("http://127.0.0.1:65535/").unwrap()]
    } else {
        cfg.upstreams.clone()
    };
    let provider = match ProxyProvider::new(ProxyConfig {
        upstreams: bootstrap_upstreams,
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
    let server_shutdown = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = server_shutdown.cancelled() => {}
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

    if cfg.mdns_enabled {
        spawn_mdns_browser(dyn_provider.clone(), shutdown.clone());
    }

    Some(dyn_provider)
}

#[cfg(feature = "mdns")]
fn spawn_mdns_browser(provider: Arc<dyn AnisetteProvider>, shutdown: CancellationToken) {
    use mdns_sd::{ServiceDaemon, ServiceEvent};
    const SERVICE_TYPE: &str = "_bibliotheca-anisette._tcp.local.";

    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "mdns: failed to start service daemon");
            return;
        }
    };
    let receiver = match daemon.browse(SERVICE_TYPE) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "mdns: failed to browse");
            return;
        }
    };

    tokio::spawn(async move {
        info!(service = SERVICE_TYPE, "mdns discovery enabled");
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = daemon.shutdown();
                    break;
                }
                // mdns-sd's recv is async-friendly via flume.
                maybe = async { receiver.recv_async().await } => {
                    match maybe {
                        Ok(ServiceEvent::ServiceResolved(info)) => {
                            if let Some(url) = service_to_url(&info) {
                                match provider.add_upstream(&url) {
                                    Ok(()) => info!(peer = %url, "mdns: added peer"),
                                    Err(bibliotheca_anisette::Error::AlreadyExists(_)) => {}
                                    Err(e) => warn!(peer = %url, error = %e, "mdns: add failed"),
                                }
                            }
                        }
                        Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                            // mdns-sd gives us the fullname of the
                            // removed service. Remove anything that
                            // carries that hostname — we don't
                            // track exactly which URL it was, so
                            // iterate the current list.
                            let label = fullname.split('.').next().unwrap_or("");
                            for existing in provider.upstreams() {
                                if existing.contains(label) {
                                    let _ = provider.remove_upstream(&existing);
                                    info!(peer = %existing, "mdns: removed peer");
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(error = %e, "mdns: browser channel closed");
                            break;
                        }
                    }
                }
            }
        }
    });
}

#[cfg(feature = "mdns")]
fn service_to_url(info: &mdns_sd::ServiceInfo) -> Option<String> {
    let port = info.get_port();
    let addr = info.get_addresses().iter().next()?.to_string();
    let scheme = info.get_property_val_str("scheme").unwrap_or("http");
    Some(format!("{scheme}://{addr}:{port}/"))
}

#[cfg(not(feature = "mdns"))]
fn spawn_mdns_browser(_provider: Arc<dyn AnisetteProvider>, _shutdown: CancellationToken) {
    // mdns feature disabled — silently no-op. The warning is
    // intentionally absent: operators who didn't opt in shouldn't
    // see log noise every boot.
}
