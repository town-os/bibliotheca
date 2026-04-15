//! Subvolume archival: snapshot + tarball builders, verification,
//! restore, and a retention lifecycle task.
//!
//! There are two archive kinds:
//!
//! - **`snapshot`**: asks the btrfs backend to create a read-only
//!   snapshot in a daemon-managed path. Zero-copy, instant. The
//!   archive row records the snapshot's mount path; verification
//!   reads the contents and re-computes the manifest.
//! - **`tarball`**: walks the subvolume tree and streams every file
//!   into a plain tar file under the configured archive root.
//!   Slower, higher-overhead, but portable — operators can copy
//!   them off-host or feed them to external backup pipelines.
//!
//! Both kinds share a manifest: `(key, size, sha256)` rows written
//! to `archive_manifests` at creation time and compared against on
//! verify. A non-matching hash surfaces as a verification failure
//! and the caller can then decide whether to treat the archive as
//! compromised.
//!
//! The lifecycle task iterates policies every
//! `archive.lifecycle_interval_secs` seconds, deletes expired
//! archives, and creates fresh ones for subvolumes whose policy
//! says it's time. A minimum-age safety net (from config) keeps
//! newborn data from being auto-archived into oblivion.

#![deny(unsafe_code)]
#![deny(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_config::ArchiveConfig;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::UserId;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::{ArchiveEntry, ArchiveRow, SubvolumePolicyRow};
use bibliotheca_core::subvolume::{Subvolume, SubvolumeId};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("archive kind {0} is not supported (expected 'snapshot' or 'tarball')")]
    UnsupportedKind(String),
    #[error("archive {0} is immutable and cannot be deleted without --force")]
    Immutable(String),
    #[error("verification failed for archive {archive}: {reason}")]
    VerifyFailed { archive: String, reason: String },
    #[error("restore would overwrite existing key {0}")]
    RestoreConflict(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Public view of an archive.
#[derive(Debug, Clone)]
pub struct Archive {
    pub id: String,
    pub subvolume_id: SubvolumeId,
    pub name: String,
    pub kind: ArchiveKind,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub object_count: u64,
    pub sha256: String,
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub retention_days: Option<u64>,
    pub immutable: bool,
    pub note: String,
    pub created_by: Option<UserId>,
}

impl Archive {
    fn from_row(row: ArchiveRow) -> Result<Self> {
        let kind = ArchiveKind::parse(&row.kind)?;
        Ok(Self {
            id: row.id,
            subvolume_id: SubvolumeId(
                Uuid::parse_str(&row.subvolume_id)
                    .map_err(|e| Error::Other(format!("archive sv id: {e}")))?,
            ),
            name: row.name,
            kind,
            path: PathBuf::from(row.path),
            size_bytes: row.size_bytes.max(0) as u64,
            object_count: row.object_count.max(0) as u64,
            sha256: row.sha256,
            created_at: OffsetDateTime::from_unix_timestamp(row.created_at)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            expires_at: row
                .expires_at
                .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok()),
            retention_days: row.retention_days.map(|d| d.max(0) as u64),
            immutable: row.immutable,
            note: row.note,
            created_by: row
                .created_by
                .and_then(|s| Uuid::parse_str(&s).ok().map(UserId)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Snapshot,
    Tarball,
}

impl ArchiveKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "snapshot" => Ok(Self::Snapshot),
            "tarball" => Ok(Self::Tarball),
            other => Err(Error::UnsupportedKind(other.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Tarball => "tarball",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateArchiveParams {
    pub subvolume_id: SubvolumeId,
    pub name: String,
    pub kind: ArchiveKind,
    pub retention_days: Option<u64>,
    pub note: String,
    pub created_by: Option<UserId>,
}

pub struct ArchiveService {
    svc: BibliothecaService,
    cfg: ArchiveConfig,
}

impl ArchiveService {
    pub fn new(svc: BibliothecaService, cfg: ArchiveConfig) -> Self {
        Self { svc, cfg }
    }

    pub fn config(&self) -> &ArchiveConfig {
        &self.cfg
    }

    pub async fn create(&self, params: CreateArchiveParams) -> Result<Archive> {
        let sv = self.svc.get_subvolume(&params.subvolume_id.to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let expires_at = params
            .retention_days
            .or(self.cfg.default_retention_days)
            .map(|d| now + time::Duration::days(d as i64));

        let (path, manifest, total_size, sha256) = match params.kind {
            ArchiveKind::Snapshot => self.build_snapshot(&sv, &params.name, &id).await?,
            ArchiveKind::Tarball => self.build_tarball(&sv, &params.name, &id)?,
        };

        let row = ArchiveRow {
            id: id.clone(),
            subvolume_id: sv.id.to_string(),
            name: params.name.clone(),
            kind: params.kind.as_str().to_string(),
            path: path.to_string_lossy().into_owned(),
            size_bytes: total_size as i64,
            object_count: manifest.len() as i64,
            sha256,
            created_at: now.unix_timestamp(),
            expires_at: expires_at.map(|t| t.unix_timestamp()),
            retention_days: params.retention_days.map(|d| d as i64),
            immutable: true,
            note: params.note,
            created_by: params.created_by.map(|u| u.to_string()),
        };
        self.svc.store().insert_archive(&row)?;
        self.svc.store().insert_archive_manifest(&id, &manifest)?;
        Archive::from_row(row)
    }

    async fn build_snapshot(
        &self,
        sv: &Subvolume,
        name: &str,
        id: &str,
    ) -> Result<(PathBuf, Vec<ArchiveEntry>, u64, String)> {
        // The control-plane service already knows how to create a
        // snapshot; we lean on it so the btrfs backend is called
        // the same way production does. The snapshot name has to
        // fit `[^/]+`, so we combine the requested name with a
        // short id suffix.
        let snap_name = format!("archive-{name}-{}", &id[..8]);
        let snap = self.svc.create_snapshot(sv.id, &snap_name, true).await?;
        let (entries, total) = walk_manifest(&snap.mount_path)?;
        let manifest_hash = hash_manifest(&entries);
        Ok((snap.mount_path, entries, total, manifest_hash))
    }

    fn build_tarball(
        &self,
        sv: &Subvolume,
        name: &str,
        id: &str,
    ) -> Result<(PathBuf, Vec<ArchiveEntry>, u64, String)> {
        let sv_root = self.cfg.root.join(&sv.name);
        std::fs::create_dir_all(&sv_root)?;
        let file_name = format!("{name}-{}.tar", &id[..8]);
        let path = sv_root.join(&file_name);
        let (entries, total) = walk_manifest(&sv.mount_path)?;
        {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            let mut builder = tar::Builder::new(BufWriter::new(file));
            for entry in &entries {
                let abs = sv.mount_path.join(&entry.key);
                let mut f = File::open(&abs)?;
                let md = f.metadata()?;
                let mut header = tar::Header::new_gnu();
                header.set_size(md.len());
                header.set_mode(0o644);
                header.set_mtime(
                    md.modified()
                        .ok()
                        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                );
                header.set_cksum();
                builder.append_data(&mut header, &entry.key, &mut f)?;
            }
            builder.finish()?;
        }
        let bytes_sha = hash_file(&path)?;
        Ok((path, entries, total, bytes_sha))
    }

    pub fn list(&self, sv: Option<SubvolumeId>) -> Result<Vec<Archive>> {
        self.svc
            .store()
            .list_archives(sv)?
            .into_iter()
            .map(Archive::from_row)
            .collect()
    }

    pub fn get(&self, id: &str) -> Result<Archive> {
        Archive::from_row(self.svc.store().get_archive_by_id(id)?)
    }

    pub fn manifest(&self, id: &str) -> Result<Vec<ArchiveEntry>> {
        Ok(self.svc.store().list_archive_manifest(id)?)
    }

    pub async fn delete(&self, id: &str, force: bool) -> Result<()> {
        let row = self.svc.store().get_archive_by_id(id)?;
        if row.immutable && !force {
            return Err(Error::Immutable(row.id));
        }
        // Physical removal.
        match ArchiveKind::parse(&row.kind)? {
            ArchiveKind::Snapshot => {
                // Snapshot deletion requires the snapshot id from
                // the store. We look it up by mount path.
                let snapshots = self.svc.list_snapshots(SubvolumeId(
                    Uuid::parse_str(&row.subvolume_id)
                        .map_err(|e| Error::Other(format!("sv id: {e}")))?,
                ))?;
                for snap in snapshots {
                    if snap.mount_path.as_path() == Path::new(&row.path) {
                        self.svc.delete_snapshot_forced(snap.id).await?;
                        break;
                    }
                }
            }
            ArchiveKind::Tarball => {
                let p = PathBuf::from(&row.path);
                if p.exists() {
                    std::fs::remove_file(&p)?;
                }
            }
        }
        self.svc.store().delete_archive(id)?;
        Ok(())
    }

    pub fn verify(&self, id: &str) -> Result<VerifyReport> {
        let row = self.svc.store().get_archive_by_id(id)?;
        let recorded: Vec<ArchiveEntry> = self.svc.store().list_archive_manifest(id)?;
        let mut mismatches: Vec<String> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        let mut checked = 0u64;

        match ArchiveKind::parse(&row.kind)? {
            ArchiveKind::Snapshot => {
                let root = PathBuf::from(&row.path);
                if !root.exists() {
                    return Err(Error::VerifyFailed {
                        archive: row.id,
                        reason: "snapshot path missing".into(),
                    });
                }
                for entry in &recorded {
                    let abs = root.join(&entry.key);
                    if !abs.exists() {
                        missing.push(entry.key.clone());
                        continue;
                    }
                    let actual = hash_file(&abs).map_err(Error::from)?;
                    if actual != entry.sha256 {
                        mismatches.push(entry.key.clone());
                    }
                    checked += 1;
                }
            }
            ArchiveKind::Tarball => {
                let path = PathBuf::from(&row.path);
                if !path.exists() {
                    return Err(Error::VerifyFailed {
                        archive: row.id,
                        reason: "tarball file missing".into(),
                    });
                }
                let full_hash = hash_file(&path).map_err(Error::from)?;
                if full_hash != row.sha256 {
                    return Err(Error::VerifyFailed {
                        archive: row.id,
                        reason: format!(
                            "tarball sha256 mismatch (expected {}, got {full_hash})",
                            row.sha256
                        ),
                    });
                }
                // Per-entry verification: stream the tar and hash
                // every member's bytes against the recorded
                // manifest.
                let f = File::open(&path)?;
                let mut ar = tar::Archive::new(f);
                let mut recorded_map = std::collections::HashMap::new();
                for e in &recorded {
                    recorded_map.insert(e.key.clone(), e.sha256.clone());
                }
                for member in ar.entries()? {
                    let mut member = member?;
                    let key = member.path()?.to_string_lossy().into_owned();
                    let mut buf = Vec::new();
                    member.read_to_end(&mut buf)?;
                    let h = hex::encode(Sha256::digest(&buf));
                    match recorded_map.get(&key) {
                        Some(expected) if *expected == h => {
                            checked += 1;
                        }
                        Some(_) => mismatches.push(key),
                        None => {
                            // Extra file in the tarball that
                            // wasn't in the recorded manifest.
                            mismatches.push(key);
                        }
                    }
                }
            }
        }

        Ok(VerifyReport {
            archive_id: row.id,
            total: recorded.len() as u64,
            checked,
            mismatches,
            missing,
        })
    }

    pub fn restore(&self, id: &str, target_sv: SubvolumeId, overwrite: bool) -> Result<u64> {
        let row = self.svc.store().get_archive_by_id(id)?;
        let manifest = self.svc.store().list_archive_manifest(id)?;
        let target = self.svc.get_subvolume(&target_sv.to_string())?;
        let owner = target.owner;
        let data = bibliotheca_core::data::DataStore::new(self.svc.clone());
        let mut restored = 0u64;

        match ArchiveKind::parse(&row.kind)? {
            ArchiveKind::Snapshot => {
                let root = PathBuf::from(&row.path);
                for entry in &manifest {
                    if !overwrite
                        && data
                            .head(&target.name, &entry.key, Some(owner), false)
                            .is_ok()
                    {
                        return Err(Error::RestoreConflict(entry.key.clone()));
                    }
                    let abs = root.join(&entry.key);
                    let bytes = std::fs::read(&abs)?;
                    data.put(&target.name, &entry.key, Some(owner), false, &bytes)?;
                    restored += 1;
                }
            }
            ArchiveKind::Tarball => {
                let f = File::open(&row.path)?;
                let mut ar = tar::Archive::new(f);
                for member in ar.entries()? {
                    let mut member = member?;
                    let key = member.path()?.to_string_lossy().into_owned();
                    if !overwrite && data.head(&target.name, &key, Some(owner), false).is_ok() {
                        return Err(Error::RestoreConflict(key));
                    }
                    let mut buf = Vec::new();
                    member.read_to_end(&mut buf)?;
                    data.put(&target.name, &key, Some(owner), false, &buf)?;
                    restored += 1;
                }
            }
        }
        Ok(restored)
    }

    // ---- policies ----

    pub fn set_policy(&self, row: SubvolumePolicyRow) -> Result<()> {
        self.svc.store().upsert_subvolume_policy(&row)?;
        Ok(())
    }

    pub fn get_policy(&self, sv: SubvolumeId) -> Result<Option<SubvolumePolicyRow>> {
        Ok(self.svc.store().get_subvolume_policy(sv)?)
    }

    pub fn list_policies(&self) -> Result<Vec<SubvolumePolicyRow>> {
        Ok(self.svc.store().list_subvolume_policies()?)
    }

    pub fn delete_policy(&self, sv: SubvolumeId) -> Result<()> {
        self.svc.store().delete_subvolume_policy(sv)?;
        Ok(())
    }

    // ---- lifecycle ----

    pub async fn run_lifecycle_once(&self) -> Result<LifecycleReport> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut expired_removed = 0u64;
        let mut archives_created = 0u64;

        // 1. Remove expired archives.
        let expired = self.svc.store().list_expired_archives(now)?;
        for row in expired {
            // Lifecycle may delete immutable archives: that's the
            // whole point of retention. Skip force=false.
            if let Err(e) = self.delete_immutable_internal(&row).await {
                warn!(archive = %row.id, error = %e, "lifecycle: delete failed");
                continue;
            }
            expired_removed += 1;
        }

        // 2. Drive policies.
        let policies = self.svc.store().list_subvolume_policies()?;
        for policy in policies {
            if !policy.enabled {
                continue;
            }
            let sv_id = SubvolumeId(
                Uuid::parse_str(&policy.subvolume_id)
                    .map_err(|e| Error::Other(format!("policy sv id: {e}")))?,
            );
            let sv = match self.svc.get_subvolume(&sv_id.to_string()) {
                Ok(sv) => sv,
                Err(e) => {
                    warn!(sv = %sv_id, error = %e, "lifecycle: skipping missing sv");
                    continue;
                }
            };
            // Minimum age safety net.
            let min_age = policy.min_age_days.max(self.cfg.min_archive_age_days);
            let age_secs = now - sv.created_at.unix_timestamp();
            if age_secs < (min_age as i64) * 86400 {
                continue;
            }
            // Interval gate.
            let due = match policy.last_run_at {
                None => true,
                Some(last) => now - last >= policy.archive_interval_secs as i64,
            };
            if !due {
                continue;
            }
            let name = format!("auto-{}", now);
            let kind = match ArchiveKind::parse(&policy.kind) {
                Ok(k) => k,
                Err(e) => {
                    warn!(sv = %sv.name, error = %e, "lifecycle: bad policy kind");
                    continue;
                }
            };
            let retention = policy.retention_days.map(|d| d as u64);
            match self
                .create(CreateArchiveParams {
                    subvolume_id: sv.id,
                    name,
                    kind,
                    retention_days: retention,
                    note: "automatic".into(),
                    created_by: None,
                })
                .await
            {
                Ok(_) => {
                    archives_created += 1;
                    let _ = self
                        .svc
                        .store()
                        .update_subvolume_policy_last_run(sv.id, now);
                }
                Err(e) => {
                    warn!(sv = %sv.name, error = %e, "lifecycle: create failed");
                }
            }
        }

        Ok(LifecycleReport {
            expired_removed,
            archives_created,
        })
    }

    async fn delete_immutable_internal(&self, row: &ArchiveRow) -> Result<()> {
        // Same as `delete(id, force=true)` but takes a row we
        // already have in hand to avoid a second fetch.
        match ArchiveKind::parse(&row.kind)? {
            ArchiveKind::Snapshot => {
                let snapshots = self.svc.list_snapshots(SubvolumeId(
                    Uuid::parse_str(&row.subvolume_id)
                        .map_err(|e| Error::Other(format!("sv id: {e}")))?,
                ))?;
                for snap in snapshots {
                    if snap.mount_path.as_path() == Path::new(&row.path) {
                        self.svc.delete_snapshot_forced(snap.id).await?;
                        break;
                    }
                }
            }
            ArchiveKind::Tarball => {
                let p = PathBuf::from(&row.path);
                if p.exists() {
                    std::fs::remove_file(&p)?;
                }
            }
        }
        self.svc.store().delete_archive(&row.id)?;
        Ok(())
    }

    pub fn spawn_lifecycle(self: Arc<Self>, shutdown: CancellationToken) {
        if self.cfg.lifecycle_interval_secs == 0 {
            info!("archive lifecycle disabled");
            return;
        }
        let interval = Duration::from_secs(self.cfg.lifecycle_interval_secs);
        tokio::spawn(async move {
            info!(
                interval_secs = self.cfg.lifecycle_interval_secs,
                "archive lifecycle started"
            );
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        match self.run_lifecycle_once().await {
                            Ok(rep) => info!(
                                expired = rep.expired_removed,
                                created = rep.archives_created,
                                "archive lifecycle pass"
                            ),
                            Err(e) => warn!(error = %e, "archive lifecycle pass failed"),
                        }
                    }
                }
            }
        });
    }
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub archive_id: String,
    pub total: u64,
    pub checked: u64,
    pub mismatches: Vec<String>,
    pub missing: Vec<String>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.mismatches.is_empty() && self.missing.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LifecycleReport {
    pub expired_removed: u64,
    pub archives_created: u64,
}

fn walk_manifest(root: &Path) -> std::io::Result<(Vec<ArchiveEntry>, u64)> {
    let mut entries = Vec::new();
    let mut total = 0u64;
    walk_dir(root, root, &mut |abs: &Path,
                               rel: &Path|
     -> std::io::Result<()> {
        if abs.is_file() {
            let bytes = std::fs::read(abs)?;
            let hash = hex::encode(Sha256::digest(&bytes));
            let size = bytes.len() as u64;
            total += size;
            entries.push(ArchiveEntry {
                key: rel.to_string_lossy().into_owned(),
                size,
                sha256: hash,
            });
        }
        Ok(())
    })?;
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    Ok((entries, total))
}

fn walk_dir(
    root: &Path,
    cur: &Path,
    visitor: &mut dyn FnMut(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if !cur.exists() {
        return Ok(());
    }
    if cur.is_file() {
        let rel = cur.strip_prefix(root).unwrap_or(cur).to_path_buf();
        visitor(cur, &rel)?;
        return Ok(());
    }
    for entry in std::fs::read_dir(cur)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(root, &path, visitor)?;
        } else {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            visitor(&path, &rel)?;
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_manifest(entries: &[ArchiveEntry]) -> String {
    let mut hasher = Sha256::new();
    for e in entries {
        hasher.update(e.key.as_bytes());
        hasher.update([0u8]);
        hasher.update(e.sha256.as_bytes());
        hasher.update([0u8]);
        hasher.update(e.size.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

// Silence unused-import warnings on the Write import when tracing
// indirectly pulls in a BufWriter flush-on-drop path we never call
// by hand.
#[allow(dead_code)]
fn _touch_write_trait(_: &mut dyn Write) {}
