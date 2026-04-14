//! Sync subsystem boot wiring.
//!
//! Constructs the `Supervisor` from runtime configuration (townos
//! URL + credentials, master secret key for credential encryption,
//! default quota), registers the per-connector factories that
//! phases 2–5 add, and re-attaches any mounts that were already in
//! the database from previous daemon runs.
//!
//! Returns `None` if any part of the config is missing (no secret
//! key, no townos url, etc.) — the gRPC `SyncAdmin` layer takes the
//! same `Option<Arc<Supervisor>>` and responds with `Unavailable`
//! on every RPC so that operators see a clear error rather than a
//! panic.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_sync_core::scheduler::{ConnectorRegistry, SupervisorConfig};
use bibliotheca_sync_core::{
    CredentialCipher, SecretKey, Supervisor, SyncStateStore, TownosClient, TownosConfig,
    TownosCreds,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use url::Url;

pub struct SyncBootConfig {
    pub townos_url: Option<Url>,
    pub townos_username: Option<String>,
    pub townos_password_file: Option<PathBuf>,
    pub townos_storage_root: PathBuf,
    pub secret_key_file: Option<PathBuf>,
    pub secret_key_env: Option<String>,
    pub default_quota_bytes: u64,
}

pub async fn boot(
    svc: BibliothecaService,
    store: Store,
    cfg: SyncBootConfig,
    shutdown: CancellationToken,
) -> anyhow::Result<Option<Arc<Supervisor>>> {
    let cipher = match load_secret_key(&cfg)? {
        Some(k) => Some(Arc::new(CredentialCipher::new(&k))),
        None => {
            warn!(
                "sync subsystem disabled: no secret key (set BIBLIOTHECA_SECRET_KEY \
                 or pass --sync-secret-key-file)"
            );
            None
        }
    };

    let townos = match (
        cfg.townos_url.clone(),
        cfg.townos_username.clone(),
        cfg.townos_password_file.as_deref(),
    ) {
        (Some(url), Some(username), Some(pw_file)) => {
            let password = std::fs::read_to_string(pw_file)
                .with_context(|| format!("read townos password from {}", pw_file.display()))?;
            let client = TownosClient::new(TownosConfig {
                base_url: url,
                creds: TownosCreds {
                    username,
                    password: password.trim().to_string(),
                },
                storage_root: cfg.townos_storage_root.clone(),
            })?;
            Some(Arc::new(client))
        }
        _ => {
            warn!(
                "sync subsystem disabled: townos client not configured \
                 (need --townos-url, --townos-username, --townos-password-file)"
            );
            None
        }
    };

    let state = SyncStateStore::new(store);
    let registry = ConnectorRegistry::new();
    // Register connectors that ship with the daemon. Additional
    // connector crates hook in here.
    bibliotheca_sync_ipfs::IpfsSyncConnector::register(&registry);
    bibliotheca_sync_dropbox::DropboxConnector::register(&registry);
    bibliotheca_sync_nextcloud::NextcloudConnector::register(&registry);
    bibliotheca_sync_solid::SolidConnector::register(&registry);
    bibliotheca_sync_gphotos::GooglePhotosConnector::register(&registry);
    bibliotheca_sync_icloud::ICloudConnector::register(&registry);

    let supervisor = Arc::new(Supervisor::new(
        svc,
        state,
        cipher,
        townos,
        registry,
        SupervisorConfig {
            default_quota_bytes: cfg.default_quota_bytes,
        },
        shutdown,
    ));

    if supervisor.is_enabled() {
        if let Err(e) = supervisor.boot().await {
            warn!(error = %e, "sync supervisor boot failed; mounts not started");
        } else {
            info!("sync subsystem ready");
        }
    }

    Ok(Some(supervisor))
}

fn load_secret_key(cfg: &SyncBootConfig) -> anyhow::Result<Option<SecretKey>> {
    if let Some(env_name) = &cfg.secret_key_env {
        if let Ok(hx) = std::env::var(env_name) {
            if !hx.is_empty() {
                return Ok(Some(
                    SecretKey::from_hex(&hx)
                        .map_err(|e| anyhow::anyhow!("invalid {env_name}: {e}"))?,
                ));
            }
        }
    }
    if let Some(path) = &cfg.secret_key_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read secret key file {}", path.display()))?;
        return Ok(Some(
            SecretKey::from_hex(raw.trim()).map_err(|e| anyhow::anyhow!("secret key file: {e}"))?,
        ));
    }
    Ok(None)
}
