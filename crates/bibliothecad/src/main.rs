//! `bibliothecad` — Bibliotheca object storage daemon.
//!
//! Serves the gRPC control plane on a local Unix socket and orchestrates
//! the data-plane interface crates. Configuration is intentionally
//! command-line driven so it can be supervised by town-os's existing
//! systemd-shaped service manager.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use bibliotheca_btrfs::BtrfsBackend;
use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use tracing::info;
use tracing_subscriber::{prelude::*, EnvFilter};

use bibliothecad::{control, interfaces};

#[derive(Debug, Parser)]
#[command(name = "bibliothecad", version, about = "Bibliotheca object storage daemon")]
struct Args {
    /// Unix socket path for the gRPC control plane.
    #[arg(long, env = "BIBLIOTHECA_SOCKET", default_value = "/run/bibliotheca/control.sock")]
    socket: PathBuf,

    /// Sqlite metadata database path.
    #[arg(long, env = "BIBLIOTHECA_DB", default_value = "/var/lib/bibliotheca/bibliotheca.db")]
    db: PathBuf,

    /// Filesystem root under which subvolumes are created.
    #[arg(long, env = "BIBLIOTHECA_ROOT", default_value = "/var/lib/bibliotheca/subvolumes")]
    root: PathBuf,

    /// Path to the btrfs binary.
    #[arg(long, env = "BIBLIOTHECA_BTRFS_BIN", default_value = "btrfs")]
    btrfs_bin: PathBuf,

    /// Path to a JSON file with interface configuration. Optional —
    /// without it, all data-plane interfaces stay disabled (the safe
    /// default that the spec requires for HTTP).
    #[arg(long, env = "BIBLIOTHECA_INTERFACES")]
    interfaces: Option<PathBuf>,
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
    let svc = BibliothecaService::new(store, backend);

    let interfaces = interfaces::load(args.interfaces.as_deref())?;
    interfaces::spawn_enabled(svc.clone(), &interfaces);

    control::serve(svc, args.socket.clone()).await?;
    info!("bibliothecad shutting down");
    Ok(())
}
