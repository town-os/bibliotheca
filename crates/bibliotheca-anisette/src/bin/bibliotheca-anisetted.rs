//! Standalone anisette proxy daemon.
//!
//! Exists as a separate binary so operators can run the proxy on
//! a different host than `bibliothecad` — useful when bibliotheca
//! itself doesn't need to sync iCloud but other peers on the same
//! VPN do, and the producer happens to sit on a third machine.

use std::net::SocketAddr;
use std::sync::Arc;

use bibliotheca_anisette::{
    serve, AnisetteProvider, AnisetteServerConfig, ProxyConfig, ProxyProvider,
};
use clap::Parser;
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;

#[derive(Debug, Parser)]
#[command(
    name = "bibliotheca-anisetted",
    version,
    about = "Anisette HTTP proxy for bibliotheca"
)]
struct Args {
    /// TCP address to bind.
    #[arg(long, default_value = "127.0.0.1:6969")]
    listen: SocketAddr,

    /// Upstream anisette server URL. Repeat for multiple; the
    /// proxy round-robins across them with per-host failover.
    /// Every upstream must be an operator-controlled endpoint;
    /// this daemon does not forward to public or third-party
    /// anisette providers.
    #[arg(long = "upstream", required = true)]
    upstreams: Vec<Url>,

    /// TTL (seconds) for cached anisette responses. Set to 0 to
    /// disable caching.
    #[arg(long, default_value_t = 20)]
    cache_ttl_secs: u64,

    /// Per-request timeout (seconds).
    #[arg(long, default_value_t = 10)]
    request_timeout_secs: u64,

    /// How long (seconds) to back off from a failed upstream.
    #[arg(long, default_value_t = 60)]
    backoff_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let provider: Arc<dyn AnisetteProvider> = Arc::new(ProxyProvider::new(ProxyConfig {
        upstreams: args.upstreams,
        cache_ttl_secs: args.cache_ttl_secs,
        request_timeout_secs: args.request_timeout_secs,
        backoff_secs: args.backoff_secs,
    })?);

    serve(
        provider,
        AnisetteServerConfig {
            listen: args.listen,
        },
    )
    .await
}
