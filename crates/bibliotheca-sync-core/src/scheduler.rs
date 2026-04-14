//! Sync supervisor: owns a set of [`MountWorker`] tokio tasks and
//! drives their lifecycles.
//!
//! # Lifecycle
//!
//! `Supervisor::new` builds an empty supervisor. `boot` loads every
//! existing `sync_mounts` row and spawns a worker per enabled,
//! non-paused mount. `create_mount`, `delete_mount`, `pause`,
//! `resume`, `trigger_sync`, and `update_mount` are the runtime
//! control surface the gRPC layer calls into.
//!
//! # Data writes
//!
//! The worker loop calls its `SyncConnector` to pull changes, then
//! writes the resulting bytes through
//! [`bibliotheca_core::data::DataStore`] so the usual ACL + quota +
//! path-traversal checks run. The sync subsystem has exactly one
//! privileged step: **subvolume procurement**, which goes through
//! [`crate::townos::TownosClient`] and
//! [`bibliotheca_core::service::BibliothecaService::adopt_subvolume`].
//! Everything else is a normal `DataStore` write.
//!
//! # Observability
//!
//! Every non-trivial event (cycle start, pulled, pushed, conflict,
//! backoff, needs 2FA, quota exceeded, error) lands in the
//! `sync_events` table and in an in-memory broadcast channel that
//! gRPC `TailEvents` subscribes to.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::data::DataStore;
use bibliotheca_core::service::BibliothecaService;
use parking_lot::Mutex;
use tokio::sync::{broadcast, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::credentials::CredentialBlob;
use crate::crypto::CredentialCipher;
use crate::error::{Error, Result};
use crate::events::{EventLevel, SyncEvent};
use crate::mount::{ConnectorKind, Direction, MountId, MountSpec, SyncMount};
use crate::retry::ExponentialBackoff;
use crate::state::SyncStateStore;
use crate::townos::TownosClient;
use crate::trait_::{ConnectorFactory, SyncConnector};

pub const EVENT_BROADCAST_CAPACITY: usize = 256;

/// Factory registry: maps a `ConnectorKind` to the function that
/// constructs the corresponding `SyncConnector` from a decrypted
/// credential blob and a config JSON string.
#[derive(Default, Clone)]
pub struct ConnectorRegistry {
    inner: Arc<Mutex<HashMap<ConnectorKind, ConnectorFactory>>>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, kind: ConnectorKind, factory: ConnectorFactory) {
        self.inner.lock().insert(kind, factory);
    }

    pub fn get(&self, kind: ConnectorKind) -> Option<ConnectorFactory> {
        self.inner.lock().get(&kind).cloned()
    }

    pub fn has(&self, kind: ConnectorKind) -> bool {
        self.inner.lock().contains_key(&kind)
    }
}

/// Configuration knobs for the supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub default_quota_bytes: u64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            default_quota_bytes: 10 * 1024 * 1024 * 1024, // 10 GiB
        }
    }
}

struct WorkerHandle {
    #[allow(dead_code)]
    spec_kind: ConnectorKind,
    cancel: CancellationToken,
    trigger: Arc<Notify>,
    twofactor_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    join: JoinHandle<()>,
}

/// The sync supervisor.
#[derive(Clone)]
pub struct Supervisor {
    svc: BibliothecaService,
    data: DataStore,
    state: SyncStateStore,
    cipher: Option<Arc<CredentialCipher>>,
    townos: Option<Arc<TownosClient>>,
    registry: ConnectorRegistry,
    cfg: SupervisorConfig,
    events_tx: broadcast::Sender<SyncEvent>,
    workers: Arc<Mutex<HashMap<MountId, WorkerHandle>>>,
    shutdown: CancellationToken,
}

impl Supervisor {
    pub fn new(
        svc: BibliothecaService,
        state: SyncStateStore,
        cipher: Option<Arc<CredentialCipher>>,
        townos: Option<Arc<TownosClient>>,
        registry: ConnectorRegistry,
        cfg: SupervisorConfig,
        shutdown: CancellationToken,
    ) -> Self {
        let data = DataStore::new(svc.clone());
        let (events_tx, _) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        Self {
            svc,
            data,
            state,
            cipher,
            townos,
            registry,
            cfg,
            events_tx,
            workers: Arc::new(Mutex::new(HashMap::new())),
            shutdown,
        }
    }

    pub fn events(&self) -> broadcast::Receiver<SyncEvent> {
        self.events_tx.subscribe()
    }

    pub fn is_enabled(&self) -> bool {
        self.cipher.is_some() && self.townos.is_some()
    }

    pub fn registry(&self) -> &ConnectorRegistry {
        &self.registry
    }

    pub fn state(&self) -> &SyncStateStore {
        &self.state
    }

    pub fn config(&self) -> &SupervisorConfig {
        &self.cfg
    }

    pub fn data_store(&self) -> &DataStore {
        &self.data
    }

    fn require_enabled(&self) -> Result<(&CredentialCipher, &TownosClient)> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| Error::SyncDisabled("secret key not configured".into()))?;
        let townos = self
            .townos
            .as_ref()
            .ok_or_else(|| Error::SyncDisabled("townos client not configured".into()))?;
        Ok((cipher.as_ref(), townos.as_ref()))
    }

    /// Re-attach workers on daemon startup.
    pub async fn boot(&self) -> Result<()> {
        if !self.is_enabled() {
            info!("sync subsystem disabled; skipping mount boot");
            return Ok(());
        }
        let mounts = self.state.list_mounts()?;
        for mount in mounts {
            if mount.enabled && !mount.paused {
                if let Err(e) = self.spawn_worker_for(&mount).await {
                    warn!(mount = %mount.name, error = %e, "failed to spawn worker at boot");
                    self.record_event(mount.id, EventLevel::Error, "spawn_failed", e.to_string());
                }
            }
        }
        Ok(())
    }

    /// Create a new mount end-to-end:
    ///
    /// 1. Procure a subvolume from town-os.
    /// 2. Adopt it into the metadata store.
    /// 3. Insert encrypted credentials.
    /// 4. Insert the mount row.
    /// 5. Spawn the worker.
    ///
    /// On any failure we roll back in reverse.
    pub async fn create_mount(
        &self,
        spec: MountSpec,
        credentials: CredentialBlob,
    ) -> Result<SyncMount> {
        let (cipher, townos) = self.require_enabled()?;

        if !self.registry.has(spec.kind) {
            return Err(Error::UnknownConnector(spec.kind.to_string()));
        }

        let quota_bytes = if spec.quota_bytes == 0 {
            self.cfg.default_quota_bytes
        } else {
            spec.quota_bytes
        };
        let townos_name = format!("user/sync-{}", spec.name);

        // 1. Procure.
        townos.create_filesystem(&townos_name, quota_bytes).await?;

        // 2. Adopt. Roll back on failure.
        let mount_path = townos.mount_path_for(&townos_name);
        let sv = match self.svc.adopt_subvolume(
            &format!("sync-{}", spec.name),
            spec.owner,
            mount_path.clone(),
            quota_bytes,
            None,
        ) {
            Ok(sv) => sv,
            Err(e) => {
                let _ = townos.remove_filesystem(&townos_name).await;
                return Err(e.into());
            }
        };

        // 3. Credentials.
        let credentials_id = match self.state.insert_credentials(cipher, &credentials) {
            Ok(id) => id,
            Err(e) => {
                let _ = self.svc.forget_subvolume(sv.id);
                let _ = townos.remove_filesystem(&townos_name).await;
                return Err(e);
            }
        };

        // 4. Mount row.
        let mount_id = MountId::new();
        let mut spec_with_creds = spec;
        spec_with_creds.quota_bytes = quota_bytes;
        spec_with_creds.credentials_id = Some(credentials_id.clone());
        if let Err(e) = self
            .state
            .insert_mount(mount_id, &spec_with_creds, sv.id, &townos_name)
        {
            let _ = self.state.delete_credentials(&credentials_id);
            let _ = self.svc.forget_subvolume(sv.id);
            let _ = townos.remove_filesystem(&townos_name).await;
            return Err(e);
        }

        let mount = self.state.get_mount(mount_id)?;

        // 5. Worker.
        if let Err(e) = self.spawn_worker_for(&mount).await {
            let _ = self.state.delete_mount(mount_id);
            let _ = self.state.delete_credentials(&credentials_id);
            let _ = self.svc.forget_subvolume(sv.id);
            let _ = townos.remove_filesystem(&townos_name).await;
            return Err(e);
        }

        self.record_event(
            mount.id,
            EventLevel::Info,
            "mount_created",
            format!("mount {} created", mount.name),
        );

        Ok(mount)
    }

    /// Tear down a mount: cancel worker, delete rows, remove
    /// the subvolume both locally and from town-os.
    pub async fn delete_mount(&self, id: MountId) -> Result<()> {
        let (_cipher, townos) = self.require_enabled()?;
        let mount = self.state.get_mount(id)?;

        // Cancel worker.
        if let Some(h) = self.workers.lock().remove(&id) {
            h.cancel.cancel();
            drop(h);
        }

        if let Some(cid) = mount.credentials_id.as_deref() {
            let _ = self.state.delete_credentials(cid);
        }
        let _ = self.state.delete_mount(id);
        let _ = self.svc.forget_subvolume(mount.subvolume_id);
        townos.remove_filesystem(&mount.townos_name).await?;

        self.record_event(
            id,
            EventLevel::Info,
            "mount_deleted",
            format!("mount {} deleted", mount.name),
        );
        Ok(())
    }

    pub async fn update_quota(&self, id: MountId, new_quota: u64) -> Result<SyncMount> {
        let (_cipher, townos) = self.require_enabled()?;
        let mount = self.state.get_mount(id)?;
        townos
            .modify_filesystem(&mount.townos_name, None, Some(new_quota))
            .await?;
        self.state.update_quota(id, new_quota)?;
        self.svc
            .update_subvolume_quota(mount.subvolume_id, new_quota)?;
        self.record_event(
            id,
            EventLevel::Info,
            "quota_updated",
            format!("quota set to {new_quota} bytes"),
        );
        self.state.get_mount(id)
    }

    pub async fn update_interval(&self, id: MountId, interval_secs: u32) -> Result<SyncMount> {
        self.state.update_interval(id, interval_secs)?;
        self.state.get_mount(id)
    }

    pub async fn update_direction(&self, id: MountId, direction: Direction) -> Result<SyncMount> {
        self.state.update_direction(id, direction)?;
        self.state.get_mount(id)
    }

    pub async fn pause(&self, id: MountId) -> Result<SyncMount> {
        self.state.set_paused(id, true)?;
        if let Some(h) = self.workers.lock().remove(&id) {
            h.cancel.cancel();
        }
        self.record_event(id, EventLevel::Info, "paused", "mount paused");
        self.state.get_mount(id)
    }

    pub async fn resume(&self, id: MountId) -> Result<SyncMount> {
        self.state.set_paused(id, false)?;
        let mount = self.state.get_mount(id)?;
        self.spawn_worker_for(&mount).await?;
        self.record_event(id, EventLevel::Info, "resumed", "mount resumed");
        Ok(mount)
    }

    pub async fn trigger_sync(&self, id: MountId) -> Result<()> {
        let guard = self.workers.lock();
        if let Some(handle) = guard.get(&id) {
            handle.trigger.notify_one();
            Ok(())
        } else {
            Err(Error::NotFound(format!("no active worker for {id}")))
        }
    }

    pub fn submit_twofactor(&self, id: MountId, code: String) -> Result<()> {
        let mut guard = self.workers.lock();
        let handle = guard
            .get_mut(&id)
            .ok_or_else(|| Error::NotFound(format!("no active worker for {id}")))?;
        let sender = handle.twofactor_tx.lock().take();
        match sender {
            Some(tx) => tx
                .send(code)
                .map_err(|_| Error::Fatal("2FA channel closed".into())),
            None => Err(Error::InvalidArgument(
                "mount is not waiting for a 2FA code".into(),
            )),
        }
    }

    pub async fn rotate_master_key(&self, new_key_hex: &str) -> Result<usize> {
        let old_cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| Error::SyncDisabled("no cipher loaded".into()))?
            .clone();
        let new_key = crate::crypto::SecretKey::from_hex(new_key_hex)?;
        let new_cipher = Arc::new(CredentialCipher::new(&new_key));
        self.state.rotate_master_key(&old_cipher, &new_cipher)
    }

    async fn spawn_worker_for(&self, mount: &SyncMount) -> Result<()> {
        let factory = self
            .registry
            .get(mount.kind)
            .ok_or_else(|| Error::UnknownConnector(mount.kind.to_string()))?;

        let cipher = self
            .cipher
            .clone()
            .ok_or_else(|| Error::SyncDisabled("no cipher".into()))?;
        let cred_id = mount
            .credentials_id
            .clone()
            .ok_or_else(|| Error::Fatal(format!("mount {} has no credentials", mount.name)))?;
        let blob = self.state.get_credentials(cipher.as_ref(), &cred_id)?;
        let connector: Arc<dyn SyncConnector> = factory(&blob, &mount.config_json)?;

        let cancel = self.shutdown.child_token();
        let trigger = Arc::new(Notify::new());
        let twofactor_tx = Arc::new(Mutex::new(None));

        let ctx = WorkerContext {
            mount_id: mount.id,
            subvolume_id: mount.subvolume_id,
            supervisor_events: self.events_tx.clone(),
            state: self.state.clone(),
            svc: self.svc.clone(),
            data: self.data.clone(),
            connector,
            interval: Duration::from_secs(mount.interval_secs.max(1) as u64),
            trigger: trigger.clone(),
            cancel: cancel.clone(),
            twofactor_tx: twofactor_tx.clone(),
        };

        let join = tokio::spawn(ctx.run());
        self.workers.lock().insert(
            mount.id,
            WorkerHandle {
                spec_kind: mount.kind,
                cancel,
                trigger,
                twofactor_tx,
                join,
            },
        );
        Ok(())
    }

    pub async fn shutdown(&self) {
        let handles: Vec<_> = {
            let mut w = self.workers.lock();
            w.drain().collect()
        };
        for (_id, h) in handles {
            h.cancel.cancel();
            let _ = h.join.await;
        }
    }

    fn record_event(
        &self,
        mount_id: MountId,
        level: EventLevel,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) {
        let ev = SyncEvent::now(mount_id, level, kind, message);
        let _ = self.state.insert_event(&ev);
        let _ = self.events_tx.send(ev);
    }
}

struct WorkerContext {
    mount_id: MountId,
    subvolume_id: bibliotheca_core::subvolume::SubvolumeId,
    supervisor_events: broadcast::Sender<SyncEvent>,
    state: SyncStateStore,
    svc: BibliothecaService,
    data: DataStore,
    connector: Arc<dyn SyncConnector>,
    interval: Duration,
    trigger: Arc<Notify>,
    cancel: CancellationToken,
    twofactor_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
}

impl WorkerContext {
    async fn run(self) {
        let mut backoff = ExponentialBackoff::default();
        let mut next_delay = self.interval;
        let _ = self.subvolume_id; // retained for later quota checks
        let _ = self.twofactor_tx.clone(); // kept for iCloud; unused in v1
        let _ = self.svc.clone(); // ditto
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    return;
                }
                _ = self.trigger.notified() => {}
                _ = tokio::time::sleep(next_delay) => {}
            }

            self.emit(EventLevel::Info, "cycle_start", "starting sync cycle");
            match self.run_cycle().await {
                Ok(summary) => {
                    backoff.reset();
                    next_delay = self.interval;
                    let _ = self.state.update_status(
                        self.mount_id,
                        Some(time::OffsetDateTime::now_utc().unix_timestamp()),
                        None,
                        None,
                    );
                    self.emit_details(
                        EventLevel::Info,
                        "cycle_done",
                        format!(
                            "pulled={} pushed={} conflicts={}",
                            summary.pulled, summary.pushed, summary.conflicts
                        ),
                        serde_json::json!({
                            "pulled": summary.pulled,
                            "pushed": summary.pushed,
                            "conflicts": summary.conflicts,
                        }),
                    );
                }
                Err(err) if err.is_transient() => {
                    let delay = backoff.next_delay();
                    next_delay = delay;
                    let until =
                        time::OffsetDateTime::now_utc().unix_timestamp() + delay.as_secs() as i64;
                    let _ = self.state.update_status(
                        self.mount_id,
                        None,
                        Some(&err.to_string()),
                        Some(until),
                    );
                    self.emit(EventLevel::Warn, "backoff", err.to_string());
                }
                Err(err) => {
                    let _ =
                        self.state
                            .update_status(self.mount_id, None, Some(&err.to_string()), None);
                    let _ = self.state.set_paused(self.mount_id, true);
                    self.emit(EventLevel::Error, "fatal", err.to_string());
                    return;
                }
            }
        }
    }

    async fn run_cycle(&self) -> Result<CycleSummary> {
        let mount = self.state.get_mount(self.mount_id)?;
        let page = self
            .connector
            .list_since(mount.cursor_blob.as_deref())
            .await?;

        let mut pulled = 0usize;
        let conflicts = 0usize;

        // Pull direction in v1: apply everything remote says.
        for change in page.changes {
            match change {
                crate::trait_::Change::Upsert(obj) => {
                    self.apply_pull(&mount.name, &mount, &obj).await?;
                    pulled += 1;
                }
                crate::trait_::Change::Delete { key, .. } => {
                    match self.data.delete(
                        &subvolume_name(&mount),
                        &key,
                        Some(mount_owner(&self.svc, &mount)?),
                        false,
                    ) {
                        Ok(()) | Err(bibliotheca_core::error::Error::NotFound(_)) => {}
                        Err(e) => return Err(Error::from(e)),
                    }
                }
            }
        }

        self.state
            .update_cursor(self.mount_id, page.next_cursor.as_deref())?;
        Ok(CycleSummary {
            pulled,
            pushed: 0,
            conflicts,
        })
    }

    async fn apply_pull(
        &self,
        _mount_name: &str,
        mount: &SyncMount,
        obj: &crate::trait_::RemoteObject,
    ) -> Result<()> {
        let bytes = self.connector.fetch(obj).await?;
        let sv_name = subvolume_name(mount);
        let owner = mount_owner(&self.svc, mount)?;
        match self
            .data
            .put(&sv_name, &obj.key, Some(owner), false, &bytes)
        {
            Ok(meta) => {
                let row = bibliotheca_core::store::SyncObjectRow {
                    mount_id: self.mount_id.to_string(),
                    remote_id: obj.id.clone(),
                    key: obj.key.clone(),
                    size: meta.size,
                    etag: obj.etag.clone(),
                    remote_mtime: obj.modified.unix_timestamp(),
                    local_mtime: meta.modified.unix_timestamp(),
                    local_hash: None,
                    remote_hash: obj.etag.clone(),
                    last_action: "pull".into(),
                    last_synced_at: time::OffsetDateTime::now_utc().unix_timestamp(),
                };
                self.state.upsert_object(&row)?;
                Ok(())
            }
            Err(bibliotheca_core::error::Error::InvalidArgument(msg)) if msg.contains("quota") => {
                Err(Error::QuotaExceeded)
            }
            Err(e) => Err(Error::from(e)),
        }
    }

    fn emit(&self, level: EventLevel, kind: impl Into<String>, message: impl Into<String>) {
        let ev = SyncEvent::now(self.mount_id, level, kind, message);
        let _ = self.state.insert_event(&ev);
        let _ = self.supervisor_events.send(ev);
    }

    fn emit_details(
        &self,
        level: EventLevel,
        kind: impl Into<String>,
        message: impl Into<String>,
        details: serde_json::Value,
    ) {
        let ev = SyncEvent::now(self.mount_id, level, kind, message).with_details(details);
        let _ = self.state.insert_event(&ev);
        let _ = self.supervisor_events.send(ev);
    }
}

#[derive(Debug)]
struct CycleSummary {
    pulled: usize,
    pushed: usize,
    conflicts: usize,
}

fn subvolume_name(mount: &SyncMount) -> String {
    format!("sync-{}", mount.name)
}

fn mount_owner(
    svc: &BibliothecaService,
    mount: &SyncMount,
) -> Result<bibliotheca_core::identity::UserId> {
    let sv = svc
        .store()
        .get_subvolume(mount.subvolume_id)
        .map_err(Error::from)?;
    Ok(sv.owner)
}

// Keep the PathBuf import warm for future use sites.
#[allow(dead_code)]
fn _touch_pathbuf(_: PathBuf) {}
