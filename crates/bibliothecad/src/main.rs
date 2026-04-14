//! `bibliothecad` — Bibliotheca object storage daemon.
//!
//! Serves the gRPC control plane on a local Unix socket and orchestrates
//! the data-plane interface crates. Configuration is intentionally
//! command-line driven so it can be supervised by town-os's existing
//! systemd-shaped service manager.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bibliotheca_btrfs::BtrfsBackend;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;

use bibliothecad::anisette::AnisetteBootConfig;
use bibliothecad::sync::SyncBootConfig;
use bibliothecad::{anisette, control, interfaces, sync};

const DEFAULT_SYNC_QUOTA: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

#[derive(Debug, Parser)]
#[command(
    name = "bibliothecad",
    version,
    about = "Bibliotheca object storage daemon"
)]
struct Args {
    /// Unix socket path for the gRPC control plane.
    #[arg(
        long,
        env = "BIBLIOTHECA_SOCKET",
        default_value = "/run/bibliotheca/control.sock"
    )]
    socket: PathBuf,

    /// Sqlite metadata database path.
    #[arg(
        long,
        env = "BIBLIOTHECA_DB",
        default_value = "/var/lib/bibliotheca/bibliotheca.db"
    )]
    db: PathBuf,

    /// Filesystem root under which subvolumes are created.
    #[arg(
        long,
        env = "BIBLIOTHECA_ROOT",
        default_value = "/var/lib/bibliotheca/subvolumes"
    )]
    root: PathBuf,

    /// Path to the btrfs binary.
    #[arg(long, env = "BIBLIOTHECA_BTRFS_BIN", default_value = "btrfs")]
    btrfs_bin: PathBuf,

    /// Path to a JSON file with interface configuration. Optional —
    /// without it, all data-plane interfaces stay disabled (the safe
    /// default that the spec requires for HTTP).
    #[arg(long, env = "BIBLIOTHECA_INTERFACES")]
    interfaces: Option<PathBuf>,

    /// town-os systemcontroller base URL, used by the sync subsystem
    /// to procure subvolumes for mounts.
    #[arg(long, env = "BIBLIOTHECA_TOWNOS_URL")]
    townos_url: Option<Url>,

    /// town-os username to authenticate as when provisioning storage.
    #[arg(long, env = "BIBLIOTHECA_TOWNOS_USERNAME")]
    townos_username: Option<String>,

    /// File containing the town-os password. Stored out-of-band so it
    /// never appears on the command line or in process listings.
    #[arg(long, env = "BIBLIOTHECA_TOWNOS_PASSWORD_FILE")]
    townos_password_file: Option<PathBuf>,

    /// Absolute filesystem path under which town-os mounts the
    /// subvolumes it creates. A procured volume named
    /// `user/sync-alice-icloud` is accessed at
    /// `{storage_root}/user/sync-alice-icloud`.
    #[arg(
        long,
        env = "BIBLIOTHECA_TOWNOS_STORAGE_ROOT",
        default_value = "/var/lib/townos/storage"
    )]
    townos_storage_root: PathBuf,

    /// File containing the 32-byte (hex-encoded) master key used to
    /// encrypt sync connector credentials at rest. Without it, the
    /// sync subsystem refuses to start.
    #[arg(long, env = "BIBLIOTHECA_SYNC_SECRET_KEY_FILE")]
    sync_secret_key_file: Option<PathBuf>,

    /// Default quota (in bytes) applied to a new sync mount if the
    /// create request does not specify one.
    #[arg(long, default_value_t = DEFAULT_SYNC_QUOTA)]
    sync_default_quota_bytes: u64,

    /// TCP address to bind the embedded anisette proxy on. Only
    /// spawned if at least one `--anisette-upstream` is supplied.
    #[arg(
        long,
        env = "BIBLIOTHECA_ANISETTE_LISTEN",
        default_value = "127.0.0.1:6969"
    )]
    anisette_listen: SocketAddr,

    /// Upstream anisette URL. Repeatable. All upstreams must be
    /// operator-controlled endpoints — typically peer bibliotheca
    /// instances reachable over a VPN and resolved via private
    /// DNS. Without any upstreams, the proxy stays disabled and
    /// `sync-icloud` mounts must point at an `anisette_url`
    /// themselves.
    #[arg(
        long = "anisette-upstream",
        env = "BIBLIOTHECA_ANISETTE_UPSTREAMS",
        value_delimiter = ','
    )]
    anisette_upstreams: Vec<Url>,

    /// TTL (seconds) for cached anisette responses.
    #[arg(long, default_value_t = 20)]
    anisette_cache_ttl_secs: u64,

    /// Per-request timeout (seconds) for the anisette upstreams.
    #[arg(long, default_value_t = 10)]
    anisette_request_timeout_secs: u64,

    /// Backoff (seconds) for a failed anisette upstream.
    #[arg(long, default_value_t = 60)]
    anisette_backoff_secs: u64,

    /// Enable mDNS/Bonjour discovery of peer anisette servers on
    /// the local network. Requires the daemon to be built with
    /// the `mdns` feature; without it, the flag is a no-op.
    #[arg(long, default_value_t = false)]
    anisette_mdns: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    if let Some(parent) = args.db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(&args.root)?;
    if let Some(parent) = args.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = Store::open(&args.db)?;
    let backend: Arc<dyn SubvolumeBackend> =
        Arc::new(BtrfsBackend::new(args.root.clone()).with_bin(args.btrfs_bin.clone()));
    let svc = BibliothecaService::new(store.clone(), backend);

    let ifaces = interfaces::load(args.interfaces.as_deref())?;
    interfaces::spawn_enabled(svc.clone(), &ifaces);

    let shutdown = CancellationToken::new();
    let supervisor = sync::boot(
        svc.clone(),
        store,
        SyncBootConfig {
            townos_url: args.townos_url,
            townos_username: args.townos_username,
            townos_password_file: args.townos_password_file,
            townos_storage_root: args.townos_storage_root,
            secret_key_file: args.sync_secret_key_file,
            secret_key_env: Some("BIBLIOTHECA_SECRET_KEY".to_string()),
            default_quota_bytes: args.sync_default_quota_bytes,
        },
        shutdown.clone(),
    )
    .await?;

    let anisette_cfg = if args.anisette_upstreams.is_empty() && !args.anisette_mdns {
        None
    } else {
        Some(AnisetteBootConfig {
            listen: args.anisette_listen,
            upstreams: args.anisette_upstreams.clone(),
            cache_ttl_secs: args.anisette_cache_ttl_secs,
            request_timeout_secs: args.anisette_request_timeout_secs,
            backoff_secs: args.anisette_backoff_secs,
            mdns_enabled: args.anisette_mdns,
        })
    };
    let anisette_provider = anisette::boot(anisette_cfg, shutdown.clone());
    let anisette_for_ctl = anisette_provider
        .clone()
        .map(|p| (p, args.anisette_listen.to_string()));

    control::serve(svc, supervisor, anisette_for_ctl, args.socket.clone()).await?;
    shutdown.cancel();
    info!("bibliothecad shutting down");
    Ok(())
}
