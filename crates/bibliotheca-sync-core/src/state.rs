//! Strongly-typed wrapper around the raw sync DAOs in
//! `bibliotheca-core::store`.

use bibliotheca_core::store::{
    Store, SyncCredentialsRow, SyncEventRow, SyncMountRow, SyncObjectRow,
};

use crate::credentials::CredentialBlob;
use crate::crypto::CredentialCipher;
use crate::error::{Error, Result};
use crate::events::SyncEvent;
use crate::mount::{Direction, MountId, MountSpec, SyncMount};

#[derive(Clone)]
pub struct SyncStateStore {
    store: Store,
}

impl SyncStateStore {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub fn raw(&self) -> &Store {
        &self.store
    }

    // ---- credentials ----

    /// Insert an encrypted credential blob. Returns the row id which
    /// becomes `sync_mounts.credentials_id`.
    ///
    /// The DAO generates the row id so we do a two-step dance:
    /// 1) insert a placeholder with a zeroed ciphertext to mint the
    ///    id,
    /// 2) encrypt the real blob using that id as AAD,
    /// 3) rotate the row with the real nonce + ciphertext.
    pub fn insert_credentials(
        &self,
        cipher: &CredentialCipher,
        blob: &CredentialBlob,
    ) -> Result<String> {
        let kind = blob.discriminant().as_wire();
        let placeholder_nonce = [0u8; 12];
        let placeholder_ct = [0u8; 1];
        let id = self
            .store
            .insert_sync_credentials(kind, &placeholder_nonce, &placeholder_ct)?;
        let (nonce, ct) = cipher.encrypt(id.as_bytes(), blob)?;
        self.store.rotate_sync_credentials(&id, &nonce, &ct)?;
        Ok(id)
    }

    pub fn get_credentials(&self, cipher: &CredentialCipher, id: &str) -> Result<CredentialBlob> {
        let row: SyncCredentialsRow = self.store.get_sync_credentials(id)?;
        cipher.decrypt(id.as_bytes(), &row.nonce, &row.ciphertext)
    }

    pub fn update_credentials(
        &self,
        cipher: &CredentialCipher,
        id: &str,
        blob: &CredentialBlob,
    ) -> Result<()> {
        let (nonce, ct) = cipher.encrypt(id.as_bytes(), blob)?;
        self.store.rotate_sync_credentials(id, &nonce, &ct)?;
        Ok(())
    }

    pub fn delete_credentials(&self, id: &str) -> Result<()> {
        self.store.delete_sync_credentials(id).map_err(Error::from)
    }

    pub fn rotate_master_key(
        &self,
        old: &CredentialCipher,
        new: &CredentialCipher,
    ) -> Result<usize> {
        let rows = self.store.list_sync_credentials()?;
        let mut count = 0;
        for row in rows {
            let blob = old.decrypt(row.id.as_bytes(), &row.nonce, &row.ciphertext)?;
            let (nonce, ct) = new.encrypt(row.id.as_bytes(), &blob)?;
            self.store.rotate_sync_credentials(&row.id, &nonce, &ct)?;
            count += 1;
        }
        Ok(count)
    }

    // ---- mounts ----

    pub fn insert_mount(
        &self,
        id: MountId,
        spec: &MountSpec,
        subvolume_id: bibliotheca_core::subvolume::SubvolumeId,
        townos_name: &str,
    ) -> Result<()> {
        let row = SyncMountRow {
            id: id.to_string(),
            name: spec.name.clone(),
            kind: spec.kind.as_wire().to_string(),
            subvolume_id: subvolume_id.to_string(),
            townos_name: townos_name.to_string(),
            direction: spec.direction.as_wire().to_string(),
            interval_secs: spec.interval_secs,
            enabled: true,
            paused: false,
            quota_bytes: spec.quota_bytes,
            cursor_blob: None,
            config_json: spec.config_json.clone(),
            credentials_id: spec.credentials_id.clone(),
            last_sync_at: None,
            last_error: None,
            backoff_until: None,
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        };
        self.store.insert_sync_mount(&row)?;
        Ok(())
    }

    pub fn get_mount(&self, id: MountId) -> Result<SyncMount> {
        let row = self.store.get_sync_mount(&id.to_string())?;
        SyncMount::from_row(row)
    }

    pub fn get_mount_by_name(&self, name: &str) -> Result<SyncMount> {
        let row = self.store.get_sync_mount_by_name(name)?;
        SyncMount::from_row(row)
    }

    pub fn list_mounts(&self) -> Result<Vec<SyncMount>> {
        self.store
            .list_sync_mounts()?
            .into_iter()
            .map(SyncMount::from_row)
            .collect()
    }

    pub fn update_cursor(&self, id: MountId, cursor: Option<&[u8]>) -> Result<()> {
        self.store
            .update_sync_mount_cursor(&id.to_string(), cursor)
            .map_err(Error::from)
    }

    pub fn update_status(
        &self,
        id: MountId,
        last_sync_at: Option<i64>,
        last_error: Option<&str>,
        backoff_until: Option<i64>,
    ) -> Result<()> {
        self.store
            .update_sync_mount_status(&id.to_string(), last_sync_at, last_error, backoff_until)
            .map_err(Error::from)
    }

    pub fn update_quota(&self, id: MountId, quota_bytes: u64) -> Result<()> {
        self.store
            .update_sync_mount_quota(&id.to_string(), quota_bytes)
            .map_err(Error::from)
    }

    pub fn set_paused(&self, id: MountId, paused: bool) -> Result<()> {
        self.store
            .set_sync_mount_paused(&id.to_string(), paused)
            .map_err(Error::from)
    }

    pub fn update_interval(&self, id: MountId, interval_secs: u32) -> Result<()> {
        self.store
            .update_sync_mount_interval(&id.to_string(), interval_secs)
            .map_err(Error::from)
    }

    pub fn update_direction(&self, id: MountId, direction: Direction) -> Result<()> {
        self.store
            .update_sync_mount_direction(&id.to_string(), direction.as_wire())
            .map_err(Error::from)
    }

    pub fn delete_mount(&self, id: MountId) -> Result<()> {
        self.store
            .delete_sync_mount(&id.to_string())
            .map_err(Error::from)
    }

    // ---- objects ----

    pub fn upsert_object(&self, row: &SyncObjectRow) -> Result<()> {
        self.store.upsert_sync_object(row).map_err(Error::from)
    }

    pub fn list_objects(&self, mount: MountId) -> Result<Vec<SyncObjectRow>> {
        self.store
            .list_sync_objects(&mount.to_string())
            .map_err(Error::from)
    }

    pub fn delete_object(&self, mount: MountId, remote_id: &str) -> Result<()> {
        self.store
            .delete_sync_object(&mount.to_string(), remote_id)
            .map_err(Error::from)
    }

    // ---- events ----

    pub fn insert_event(&self, ev: &SyncEvent) -> Result<i64> {
        let row = SyncEventRow {
            id: 0,
            mount_id: ev.mount_id.to_string(),
            ts: ev.ts.unix_timestamp(),
            level: ev.level.as_wire().to_string(),
            kind: ev.kind.clone(),
            message: ev.message.clone(),
            details_json: ev.details.to_string(),
        };
        self.store.insert_sync_event(&row).map_err(Error::from)
    }

    pub fn recent_events(
        &self,
        mount: MountId,
        since_ts: i64,
        limit: u32,
    ) -> Result<Vec<SyncEventRow>> {
        self.store
            .recent_sync_events(&mount.to_string(), since_ts, limit)
            .map_err(Error::from)
    }
}
