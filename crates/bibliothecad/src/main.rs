//! `bibliothecad` — Bibliotheca object storage daemon.
//!
//! Configuration precedence, top to bottom:
//!
//!   1. Command line flags (highest priority)
//!   2. Environment variables (where supported)
//!   3. YAML config file (`--config /path.yml` or
//!      `/etc/bibliotheca/bibliotheca.yml`)
//!   4. Built-in defaults in `bibliotheca-config`
//!
//! Every flag below is `Option<T>` so the resolution above can
//! happen cleanly in `main` without "what was the CLI default"
//! detection. Long-standing flags keep their previous names and
//! environment-variable bindings; the file is additive.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bibliotheca_btrfs::BtrfsBackend;
use bibliotheca_config::BibliothecaConfig;
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

#[derive(Debug, Parser)]
#[command(
    name = "bibliothecad",
    version,
    about = "Bibliotheca object storage daemon"
)]
struct Args {
    /// Path to the YAML config file. Defaults to
    /// `/etc/bibliotheca/bibliotheca.yml` when unset; if that
    /// file does not exist, built-in defaults are used.
    #[arg(long, env = "BIBLIOTHECA_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_SOCKET")]
    socket: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_DB")]
    db: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_ROOT")]
    root: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_BTRFS_BIN")]
    btrfs_bin: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_INTERFACES")]
    interfaces: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_TOWNOS_URL")]
    townos_url: Option<Url>,

    #[arg(long, env = "BIBLIOTHECA_TOWNOS_USERNAME")]
    townos_username: Option<String>,

    #[arg(long, env = "BIBLIOTHECA_TOWNOS_PASSWORD_FILE")]
    townos_password_file: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_TOWNOS_STORAGE_ROOT")]
    townos_storage_root: Option<PathBuf>,

    #[arg(long, env = "BIBLIOTHECA_SYNC_SECRET_KEY_FILE")]
    sync_secret_key_file: Option<PathBuf>,

    #[arg(long)]
    sync_default_quota_bytes: Option<u64>,

    #[arg(long, env = "BIBLIOTHECA_ANISETTE_LISTEN")]
    anisette_listen: Option<SocketAddr>,

    #[arg(
        long = "anisette-upstream",
        env = "BIBLIOTHECA_ANISETTE_UPSTREAMS",
        value_delimiter = ','
    )]
    anisette_upstreams: Vec<Url>,

    #[arg(long)]
    anisette_cache_ttl_secs: Option<u64>,

    #[arg(long)]
    anisette_request_timeout_secs: Option<u64>,

    #[arg(long)]
    anisette_backoff_secs: Option<u64>,

    #[arg(long)]
    anisette_mdns: Option<bool>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let cfg = BibliothecaConfig::load_or_default(args.config.as_deref())?;

    let socket = args.socket.clone().unwrap_or(cfg.daemon.socket.clone());
    let db = args.db.clone().unwrap_or(cfg.daemon.db.clone());
    let root = args.root.clone().unwrap_or(cfg.daemon.root.clone());
    let btrfs_bin = args
        .btrfs_bin
        .clone()
        .unwrap_or(cfg.daemon.btrfs_bin.clone());
    let interfaces_path = args
        .interfaces
        .clone()
        .or_else(|| cfg.daemon.interfaces_file.clone());

    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(&root)?;
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = Store::open(&db)?;
    let backend: Arc<dyn SubvolumeBackend> =
        Arc::new(BtrfsBackend::new(root.clone()).with_bin(btrfs_bin.clone()));
    let svc = BibliothecaService::new(store.clone(), backend);

    let ifaces = interfaces::load(interfaces_path.as_deref())?;
    interfaces::spawn_enabled(svc.clone(), &ifaces);

    let shutdown = CancellationToken::new();
    let supervisor = sync::boot(
        svc.clone(),
        store,
        SyncBootConfig {
            townos_url: args.townos_url.or(cfg.sync.townos_url.clone()),
            townos_username: args.townos_username.or(cfg.sync.townos_username.clone()),
            townos_password_file: args
                .townos_password_file
                .or(cfg.sync.townos_password_file.clone()),
            townos_storage_root: args
                .townos_storage_root
                .clone()
                .unwrap_or(cfg.sync.townos_storage_root.clone()),
            secret_key_file: args
                .sync_secret_key_file
                .or(cfg.sync.secret_key_file.clone()),
            secret_key_env: Some(cfg.sync.secret_key_env.clone()),
            default_quota_bytes: args
                .sync_default_quota_bytes
                .unwrap_or(cfg.sync.default_quota_bytes),
        },
        shutdown.clone(),
    )
    .await?;

    let anisette_listen = args.anisette_listen.unwrap_or(cfg.anisette.listen);
    let anisette_upstreams = if args.anisette_upstreams.is_empty() {
        cfg.anisette.upstreams.clone()
    } else {
        args.anisette_upstreams.clone()
    };
    let anisette_mdns = args.anisette_mdns.unwrap_or(cfg.anisette.mdns_enabled);
    let anisette_enabled = cfg.anisette.enabled || !anisette_upstreams.is_empty() || anisette_mdns;

    let anisette_cfg = if anisette_enabled {
        Some(AnisetteBootConfig {
            listen: anisette_listen,
            upstreams: anisette_upstreams,
            cache_ttl_secs: args
                .anisette_cache_ttl_secs
                .unwrap_or(cfg.anisette.cache_ttl_secs),
            request_timeout_secs: args
                .anisette_request_timeout_secs
                .unwrap_or(cfg.anisette.request_timeout_secs),
            backoff_secs: args
                .anisette_backoff_secs
                .unwrap_or(cfg.anisette.backoff_secs),
            mdns_enabled: anisette_mdns,
        })
    } else {
        None
    };
    let anisette_provider = anisette::boot(anisette_cfg, shutdown.clone());
    let anisette_for_ctl = anisette_provider
        .clone()
        .map(|p| (p, anisette_listen.to_string()));

    control::serve(svc, supervisor, anisette_for_ctl, socket.clone()).await?;
    shutdown.cancel();
    info!("bibliothecad shutting down");
    Ok(())
}
