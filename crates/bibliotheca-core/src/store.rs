//! Sqlite-backed metadata store: users, groups, memberships, subvolumes,
//! snapshots and ACLs. The store is wrapped behind a parking_lot Mutex so
//! it can be shared across the async control plane without bringing in a
//! separate connection pool — this is a single-host daemon and the
//! control-plane traffic is low-volume.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::acl::{Acl, Permission, Principal};
use crate::error::{Error, Result};
use crate::identity::{Group, GroupId, User, UserId};
use crate::subvolume::{Snapshot, SnapshotId, Subvolume, SubvolumeId};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS subvolumes (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    owner_id     TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    mount_path   TEXT NOT NULL,
    quota_bytes  INTEGER NOT NULL DEFAULT 0,
    acl_json     TEXT NOT NULL DEFAULT '{"entries":[]}',
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id           TEXT PRIMARY KEY,
    subvolume_id TEXT NOT NULL REFERENCES subvolumes(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    mount_path   TEXT NOT NULL,
    readonly     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    UNIQUE (subvolume_id, name)
);

CREATE TABLE IF NOT EXISTS kv_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_credentials (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    rotated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_mounts (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL,
    subvolume_id    TEXT NOT NULL UNIQUE
                    REFERENCES subvolumes(id) ON DELETE CASCADE,
    townos_name     TEXT NOT NULL,
    direction       TEXT NOT NULL,
    interval_secs   INTEGER NOT NULL DEFAULT 300,
    enabled         INTEGER NOT NULL DEFAULT 1,
    paused          INTEGER NOT NULL DEFAULT 0,
    quota_bytes     INTEGER NOT NULL DEFAULT 0,
    cursor_blob     BLOB,
    config_json     TEXT NOT NULL DEFAULT '{}',
    credentials_id  TEXT REFERENCES sync_credentials(id) ON DELETE SET NULL,
    last_sync_at    INTEGER,
    last_error      TEXT,
    backoff_until   INTEGER,
    created_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sync_mounts_enabled_idx
    ON sync_mounts(enabled, paused);

CREATE TABLE IF NOT EXISTS sync_objects (
    mount_id       TEXT NOT NULL
                   REFERENCES sync_mounts(id) ON DELETE CASCADE,
    remote_id      TEXT NOT NULL,
    key            TEXT NOT NULL,
    size           INTEGER NOT NULL,
    etag           TEXT,
    remote_mtime   INTEGER NOT NULL,
    local_mtime    INTEGER NOT NULL,
    local_hash     TEXT,
    remote_hash    TEXT,
    last_action    TEXT NOT NULL,
    last_synced_at INTEGER NOT NULL,
    PRIMARY KEY (mount_id, remote_id)
);

CREATE INDEX IF NOT EXISTS sync_objects_key_idx
    ON sync_objects(mount_id, key);

CREATE TABLE IF NOT EXISTS sync_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mount_id     TEXT NOT NULL
                 REFERENCES sync_mounts(id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    level        TEXT NOT NULL,
    kind         TEXT NOT NULL,
    message      TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS sync_events_mount_ts_idx
    ON sync_events(mount_id, ts DESC);

CREATE TABLE IF NOT EXISTS share_grants (
    id              TEXT PRIMARY KEY,
    token           TEXT NOT NULL UNIQUE,
    subvolume_id    TEXT NOT NULL REFERENCES subvolumes(id) ON DELETE CASCADE,
    -- Empty string means "whole subvolume, key comes from the URL path".
    -- A non-empty value pins the share to exactly one key.
    key             TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    -- Nullable: null means no expiry.
    expires_at      INTEGER,
    -- Nullable: null means unlimited uses.
    use_limit       INTEGER,
    uses            INTEGER NOT NULL DEFAULT 0,
    revoked         INTEGER NOT NULL DEFAULT 0,
    note            TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS share_grants_token_idx
    ON share_grants(token);
CREATE INDEX IF NOT EXISTS share_grants_sv_idx
    ON share_grants(subvolume_id);

CREATE TABLE IF NOT EXISTS share_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id    TEXT NOT NULL REFERENCES share_grants(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    action      TEXT NOT NULL,              -- create|use|revoke|expire|deny
    remote_ip   TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    key         TEXT NOT NULL DEFAULT '',
    status      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS share_events_share_ts_idx
    ON share_events(share_id, ts DESC);

CREATE TABLE IF NOT EXISTS archives (
    id               TEXT PRIMARY KEY,
    subvolume_id     TEXT NOT NULL REFERENCES subvolumes(id) ON DELETE RESTRICT,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,          -- 'snapshot' | 'tarball'
    path             TEXT NOT NULL,          -- snapshot mount path OR tarball file path
    size_bytes       INTEGER NOT NULL DEFAULT 0,
    object_count     INTEGER NOT NULL DEFAULT 0,
    sha256           TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER,                -- null = never
    retention_days   INTEGER,                -- what was requested (informational)
    immutable        INTEGER NOT NULL DEFAULT 1,
    note             TEXT NOT NULL DEFAULT '',
    created_by       TEXT REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (subvolume_id, name)
);

CREATE INDEX IF NOT EXISTS archives_sv_idx
    ON archives(subvolume_id);
CREATE INDEX IF NOT EXISTS archives_expires_idx
    ON archives(expires_at);

CREATE TABLE IF NOT EXISTS archive_manifests (
    archive_id   TEXT NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    key          TEXT NOT NULL,
    size         INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    PRIMARY KEY (archive_id, key)
);

CREATE TABLE IF NOT EXISTS subvolume_policies (
    subvolume_id       TEXT PRIMARY KEY
                       REFERENCES subvolumes(id) ON DELETE CASCADE,
    kind               TEXT NOT NULL,          -- 'snapshot' | 'tarball'
    retention_days     INTEGER,                -- null = archives live forever
    archive_interval_secs  INTEGER NOT NULL DEFAULT 86400,
    min_age_days       INTEGER NOT NULL DEFAULT 1,
    enabled            INTEGER NOT NULL DEFAULT 1,
    last_run_at        INTEGER,
    created_at         INTEGER NOT NULL
);
"#;

#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    // ------- users -------

    pub fn create_user(&self, name: &str, display_name: &str, password_hash: &str) -> Result<User> {
        let id = UserId::new();
        let now = OffsetDateTime::now_utc();
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO users (id, name, display_name, password_hash, created_at, disabled)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![
                id.to_string(),
                name,
                display_name,
                password_hash,
                now.unix_timestamp()
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::AlreadyExists(format!("user {name}"))
            }
            other => other.into(),
        })?;
        Ok(User {
            id,
            name: name.into(),
            display_name: display_name.into(),
            created_at: now,
            disabled: false,
        })
    }

    pub fn get_user_by_id(&self, id: UserId) -> Result<User> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT id, name, display_name, created_at, disabled FROM users WHERE id = ?1",
                params![id.to_string()],
                row_to_user,
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("user {id}")))
    }

    pub fn get_user_by_name(&self, name: &str) -> Result<User> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT id, name, display_name, created_at, disabled FROM users WHERE name = ?1",
                params![name],
                row_to_user,
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("user {name}")))
    }

    pub fn list_users(&self, limit: u32, offset: u32) -> Result<Vec<User>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, display_name, created_at, disabled FROM users
             ORDER BY name LIMIT ?1 OFFSET ?2",
        )?;
        let limit = if limit == 0 {
            i64::MAX
        } else {
            i64::from(limit)
        };
        let rows = stmt
            .query_map(params![limit, i64::from(offset)], row_to_user)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_user(&self, id: UserId) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute("DELETE FROM users WHERE id = ?1", params![id.to_string()])?;
        if n == 0 {
            return Err(Error::NotFound(format!("user {id}")));
        }
        Ok(())
    }

    pub fn set_password(&self, id: UserId, password_hash: &str) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![password_hash, id.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("user {id}")));
        }
        Ok(())
    }

    pub fn get_password_hash(&self, id: UserId) -> Result<String> {
        let conn = self.inner.lock();
        let row: Option<String> = conn
            .query_row(
                "SELECT password_hash FROM users WHERE id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("user {id}")))
    }

    // ------- groups -------

    pub fn create_group(&self, name: &str, description: &str) -> Result<Group> {
        let id = GroupId::new();
        let now = OffsetDateTime::now_utc();
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO groups (id, name, description, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id.to_string(), name, description, now.unix_timestamp()],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::AlreadyExists(format!("group {name}"))
            }
            other => other.into(),
        })?;
        Ok(Group {
            id,
            name: name.into(),
            description: description.into(),
            created_at: now,
        })
    }

    pub fn get_group_by_id(&self, id: GroupId) -> Result<Group> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT id, name, description, created_at FROM groups WHERE id = ?1",
                params![id.to_string()],
                row_to_group,
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("group {id}")))
    }

    pub fn get_group_by_name(&self, name: &str) -> Result<Group> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT id, name, description, created_at FROM groups WHERE name = ?1",
                params![name],
                row_to_group,
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("group {name}")))
    }

    pub fn list_groups(&self, limit: u32, offset: u32) -> Result<Vec<Group>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, created_at FROM groups ORDER BY name LIMIT ?1 OFFSET ?2",
        )?;
        let limit = if limit == 0 {
            i64::MAX
        } else {
            i64::from(limit)
        };
        let rows = stmt
            .query_map(params![limit, i64::from(offset)], row_to_group)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_group(&self, id: GroupId) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute("DELETE FROM groups WHERE id = ?1", params![id.to_string()])?;
        if n == 0 {
            return Err(Error::NotFound(format!("group {id}")));
        }
        Ok(())
    }

    pub fn add_user_to_group(&self, user: UserId, group: GroupId) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?1, ?2)",
            params![group.to_string(), user.to_string()],
        )?;
        Ok(())
    }

    pub fn remove_user_from_group(&self, user: UserId, group: GroupId) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
            params![group.to_string(), user.to_string()],
        )?;
        Ok(())
    }

    pub fn groups_for_user(&self, user: UserId) -> Result<HashSet<GroupId>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare("SELECT group_id FROM group_members WHERE user_id = ?1")?;
        let rows = stmt
            .query_map(params![user.to_string()], |r| {
                let s: String = r.get(0)?;
                Ok(s)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut out = HashSet::new();
        for s in rows {
            if let Ok(uuid) = Uuid::parse_str(&s) {
                out.insert(GroupId(uuid));
            }
        }
        Ok(out)
    }

    pub fn group_ids_for_user(&self, user: UserId) -> Result<Vec<GroupId>> {
        let mut v: Vec<GroupId> = self.groups_for_user(user)?.into_iter().collect();
        v.sort_by_key(|g| g.0);
        Ok(v)
    }

    pub fn users_in_group(&self, group: GroupId) -> Result<Vec<UserId>> {
        let conn = self.inner.lock();
        let mut stmt =
            conn.prepare("SELECT user_id FROM group_members WHERE group_id = ?1 ORDER BY user_id")?;
        let rows = stmt
            .query_map(params![group.to_string()], |r| {
                let s: String = r.get(0)?;
                Ok(s)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for s in rows {
            if let Ok(uuid) = Uuid::parse_str(&s) {
                out.push(UserId(uuid));
            }
        }
        Ok(out)
    }

    // ------- subvolumes -------

    pub fn create_subvolume(
        &self,
        name: &str,
        owner: UserId,
        mount_path: PathBuf,
        quota_bytes: u64,
        acl: &Acl,
    ) -> Result<Subvolume> {
        let id = SubvolumeId::new();
        let now = OffsetDateTime::now_utc();
        let acl_json = serde_json::to_string(acl).map_err(|e| Error::Backend(e.to_string()))?;
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO subvolumes (id, name, owner_id, mount_path, quota_bytes, acl_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id.to_string(),
                name,
                owner.to_string(),
                mount_path.display().to_string(),
                quota_bytes as i64,
                acl_json,
                now.unix_timestamp()
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::AlreadyExists(format!("subvolume {name}"))
            }
            other => other.into(),
        })?;
        Ok(Subvolume {
            id,
            name: name.into(),
            owner,
            mount_path,
            quota_bytes,
            acl: acl.clone(),
            created_at: now,
        })
    }

    pub fn get_subvolume(&self, id: SubvolumeId) -> Result<Subvolume> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT id, name, owner_id, mount_path, quota_bytes, acl_json, created_at
                 FROM subvolumes WHERE id = ?1",
                params![id.to_string()],
                row_to_subvolume,
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("subvolume {id}")))
    }

    pub fn get_subvolume_by_name(&self, name: &str) -> Result<Subvolume> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT id, name, owner_id, mount_path, quota_bytes, acl_json, created_at
                 FROM subvolumes WHERE name = ?1",
                params![name],
                row_to_subvolume,
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("subvolume {name}")))
    }

    pub fn list_subvolumes(
        &self,
        owner: Option<UserId>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Subvolume>> {
        let conn = self.inner.lock();
        let limit = if limit == 0 {
            i64::MAX
        } else {
            i64::from(limit)
        };
        let offset = i64::from(offset);
        let rows: Vec<Subvolume> = match owner {
            Some(o) => {
                let mut stmt = conn.prepare(
                    "SELECT id, name, owner_id, mount_path, quota_bytes, acl_json, created_at
                     FROM subvolumes WHERE owner_id = ?1 ORDER BY name LIMIT ?2 OFFSET ?3",
                )?;
                let iter =
                    stmt.query_map(params![o.to_string(), limit, offset], row_to_subvolume)?;
                iter.collect::<std::result::Result<Vec<_>, _>>()?
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id, name, owner_id, mount_path, quota_bytes, acl_json, created_at
                     FROM subvolumes ORDER BY name LIMIT ?1 OFFSET ?2",
                )?;
                let iter = stmt.query_map(params![limit, offset], row_to_subvolume)?;
                iter.collect::<std::result::Result<Vec<_>, _>>()?
            }
        };
        Ok(rows)
    }

    pub fn delete_subvolume(&self, id: SubvolumeId) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "DELETE FROM subvolumes WHERE id = ?1",
            params![id.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("subvolume {id}")));
        }
        Ok(())
    }

    pub fn set_quota(&self, id: SubvolumeId, bytes: u64) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE subvolumes SET quota_bytes = ?1 WHERE id = ?2",
            params![bytes as i64, id.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("subvolume {id}")));
        }
        Ok(())
    }

    pub fn set_acl(&self, id: SubvolumeId, acl: &Acl) -> Result<()> {
        let acl_json = serde_json::to_string(acl).map_err(|e| Error::Backend(e.to_string()))?;
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE subvolumes SET acl_json = ?1 WHERE id = ?2",
            params![acl_json, id.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("subvolume {id}")));
        }
        Ok(())
    }

    // ------- snapshots -------

    pub fn create_snapshot(
        &self,
        subvolume: SubvolumeId,
        name: &str,
        mount_path: PathBuf,
        readonly: bool,
    ) -> Result<Snapshot> {
        let id = SnapshotId::new();
        let now = OffsetDateTime::now_utc();
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO snapshots (id, subvolume_id, name, mount_path, readonly, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.to_string(),
                subvolume.to_string(),
                name,
                mount_path.display().to_string(),
                i64::from(readonly),
                now.unix_timestamp()
            ],
        )?;
        Ok(Snapshot {
            id,
            subvolume,
            name: name.into(),
            mount_path,
            readonly,
            created_at: now,
        })
    }

    pub fn list_snapshots(&self, subvolume: SubvolumeId) -> Result<Vec<Snapshot>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, subvolume_id, name, mount_path, readonly, created_at
             FROM snapshots WHERE subvolume_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map(params![subvolume.to_string()], row_to_snapshot)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_snapshot(&self, id: SnapshotId) -> Result<Snapshot> {
        let conn = self.inner.lock();
        conn.query_row(
            "SELECT id, subvolume_id, name, mount_path, readonly, created_at
             FROM snapshots WHERE id = ?1",
            params![id.0.to_string()],
            row_to_snapshot,
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("snapshot {}", id.0)))
    }

    pub fn delete_snapshot(&self, id: SnapshotId) -> Result<Snapshot> {
        let conn = self.inner.lock();
        let snap = conn
            .query_row(
                "SELECT id, subvolume_id, name, mount_path, readonly, created_at
                 FROM snapshots WHERE id = ?1",
                params![id.0.to_string()],
                row_to_snapshot,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("snapshot {}", id.0)))?;
        conn.execute(
            "DELETE FROM snapshots WHERE id = ?1",
            params![id.0.to_string()],
        )?;
        Ok(snap)
    }

    // ------- sync DAOs -------
    //
    // These are thin, string-typed row accessors. The sync-core crate
    // wraps them with strongly-typed enums and ergonomic builders;
    // keeping the raw surface in `Store` avoids a circular dependency
    // (sync-core would otherwise need to reach into bibliotheca-core
    // for the sqlite handle).

    pub fn insert_sync_credentials(
        &self,
        kind: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO sync_credentials (id, kind, nonce, ciphertext, created_at, rotated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![id, kind, nonce, ciphertext, now],
        )?;
        Ok(id)
    }

    pub fn get_sync_credentials(&self, id: &str) -> Result<SyncCredentialsRow> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT id, kind, nonce, ciphertext FROM sync_credentials WHERE id = ?1",
                params![id],
                |r| {
                    Ok(SyncCredentialsRow {
                        id: r.get::<_, String>(0)?,
                        kind: r.get::<_, String>(1)?,
                        nonce: r.get::<_, Vec<u8>>(2)?,
                        ciphertext: r.get::<_, Vec<u8>>(3)?,
                    })
                },
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("sync credentials {id}")))
    }

    pub fn rotate_sync_credentials(&self, id: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<()> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_credentials SET nonce = ?1, ciphertext = ?2, rotated_at = ?3 WHERE id = ?4",
            params![nonce, ciphertext, now, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync credentials {id}")));
        }
        Ok(())
    }

    pub fn list_sync_credentials(&self) -> Result<Vec<SyncCredentialsRow>> {
        let conn = self.inner.lock();
        let mut stmt =
            conn.prepare("SELECT id, kind, nonce, ciphertext FROM sync_credentials ORDER BY id")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SyncCredentialsRow {
                    id: r.get::<_, String>(0)?,
                    kind: r.get::<_, String>(1)?,
                    nonce: r.get::<_, Vec<u8>>(2)?,
                    ciphertext: r.get::<_, Vec<u8>>(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_sync_credentials(&self, id: &str) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute("DELETE FROM sync_credentials WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn insert_sync_mount(&self, row: &SyncMountRow) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO sync_mounts
              (id, name, kind, subvolume_id, townos_name, direction,
               interval_secs, enabled, paused, quota_bytes, cursor_blob,
               config_json, credentials_id, last_sync_at, last_error,
               backoff_until, created_at)
             VALUES
              (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               ?14, ?15, ?16, ?17)",
            params![
                row.id,
                row.name,
                row.kind,
                row.subvolume_id,
                row.townos_name,
                row.direction,
                row.interval_secs as i64,
                i64::from(row.enabled),
                i64::from(row.paused),
                row.quota_bytes as i64,
                row.cursor_blob,
                row.config_json,
                row.credentials_id,
                row.last_sync_at,
                row.last_error,
                row.backoff_until,
                row.created_at,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::AlreadyExists(format!("sync mount {}", row.name))
            }
            other => other.into(),
        })?;
        Ok(())
    }

    pub fn get_sync_mount(&self, id: &str) -> Result<SyncMountRow> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(SYNC_MOUNT_SELECT_BY_ID, params![id], sync_mount_row_from)
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("sync mount {id}")))
    }

    pub fn get_sync_mount_by_name(&self, name: &str) -> Result<SyncMountRow> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                SYNC_MOUNT_SELECT_BY_NAME,
                params![name],
                sync_mount_row_from,
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("sync mount {name}")))
    }

    pub fn list_sync_mounts(&self) -> Result<Vec<SyncMountRow>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(SYNC_MOUNT_SELECT_ALL)?;
        let rows = stmt
            .query_map([], sync_mount_row_from)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn update_sync_mount_cursor(&self, id: &str, cursor: Option<&[u8]>) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_mounts SET cursor_blob = ?1 WHERE id = ?2",
            params![cursor, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn update_sync_mount_status(
        &self,
        id: &str,
        last_sync_at: Option<i64>,
        last_error: Option<&str>,
        backoff_until: Option<i64>,
    ) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_mounts SET last_sync_at = COALESCE(?1, last_sync_at),
                                     last_error = ?2,
                                     backoff_until = ?3
              WHERE id = ?4",
            params![last_sync_at, last_error, backoff_until, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn update_sync_mount_quota(&self, id: &str, quota_bytes: u64) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_mounts SET quota_bytes = ?1 WHERE id = ?2",
            params![quota_bytes as i64, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn set_sync_mount_paused(&self, id: &str, paused: bool) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_mounts SET paused = ?1 WHERE id = ?2",
            params![i64::from(paused), id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn update_sync_mount_config(&self, id: &str, config_json: &str) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_mounts SET config_json = ?1 WHERE id = ?2",
            params![config_json, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn update_sync_mount_interval(&self, id: &str, interval_secs: u32) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_mounts SET interval_secs = ?1 WHERE id = ?2",
            params![interval_secs as i64, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn update_sync_mount_direction(&self, id: &str, direction: &str) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE sync_mounts SET direction = ?1 WHERE id = ?2",
            params![direction, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn delete_sync_mount(&self, id: &str) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute("DELETE FROM sync_mounts WHERE id = ?1", params![id])?;
        if n == 0 {
            return Err(Error::NotFound(format!("sync mount {id}")));
        }
        Ok(())
    }

    pub fn upsert_sync_object(&self, row: &SyncObjectRow) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO sync_objects
              (mount_id, remote_id, key, size, etag, remote_mtime, local_mtime,
               local_hash, remote_hash, last_action, last_synced_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(mount_id, remote_id) DO UPDATE SET
                key = excluded.key,
                size = excluded.size,
                etag = excluded.etag,
                remote_mtime = excluded.remote_mtime,
                local_mtime = excluded.local_mtime,
                local_hash = excluded.local_hash,
                remote_hash = excluded.remote_hash,
                last_action = excluded.last_action,
                last_synced_at = excluded.last_synced_at",
            params![
                row.mount_id,
                row.remote_id,
                row.key,
                row.size as i64,
                row.etag,
                row.remote_mtime,
                row.local_mtime,
                row.local_hash,
                row.remote_hash,
                row.last_action,
                row.last_synced_at,
            ],
        )?;
        Ok(())
    }

    pub fn list_sync_objects(&self, mount_id: &str) -> Result<Vec<SyncObjectRow>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(SYNC_OBJECT_SELECT_ALL)?;
        let rows = stmt
            .query_map(params![mount_id], sync_object_row_from)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_sync_object(&self, mount_id: &str, remote_id: &str) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "DELETE FROM sync_objects WHERE mount_id = ?1 AND remote_id = ?2",
            params![mount_id, remote_id],
        )?;
        Ok(())
    }

    pub fn insert_sync_event(&self, ev: &SyncEventRow) -> Result<i64> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO sync_events (mount_id, ts, level, kind, message, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ev.mount_id,
                ev.ts,
                ev.level,
                ev.kind,
                ev.message,
                ev.details_json,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn recent_sync_events(
        &self,
        mount_id: &str,
        since_ts: i64,
        limit: u32,
    ) -> Result<Vec<SyncEventRow>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, mount_id, ts, level, kind, message, details_json
               FROM sync_events
              WHERE mount_id = ?1 AND ts >= ?2
              ORDER BY ts ASC, id ASC
              LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![mount_id, since_ts, limit as i64], |r| {
                Ok(SyncEventRow {
                    id: r.get::<_, i64>(0)?,
                    mount_id: r.get::<_, String>(1)?,
                    ts: r.get::<_, i64>(2)?,
                    level: r.get::<_, String>(3)?,
                    kind: r.get::<_, String>(4)?,
                    message: r.get::<_, String>(5)?,
                    details_json: r.get::<_, String>(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ------- share grants -------

    pub fn insert_share_grant(&self, row: &ShareGrantRow) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO share_grants
                (id, token, subvolume_id, key, created_by, created_at,
                 expires_at, use_limit, uses, revoked, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.id,
                row.token,
                row.subvolume_id,
                row.key,
                row.created_by,
                row.created_at,
                row.expires_at,
                row.use_limit,
                row.uses,
                row.revoked as i64,
                row.note,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::AlreadyExists(format!("share {}", row.id))
            }
            other => other.into(),
        })?;
        Ok(())
    }

    pub fn get_share_grant_by_id(&self, id: &str) -> Result<ShareGrantRow> {
        let conn = self.inner.lock();
        conn.query_row(
            "SELECT id, token, subvolume_id, key, created_by, created_at,
                    expires_at, use_limit, uses, revoked, note
             FROM share_grants WHERE id = ?1",
            params![id],
            row_to_share_grant,
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("share {id}")))
    }

    pub fn get_share_grant_by_token(&self, token: &str) -> Result<ShareGrantRow> {
        let conn = self.inner.lock();
        conn.query_row(
            "SELECT id, token, subvolume_id, key, created_by, created_at,
                    expires_at, use_limit, uses, revoked, note
             FROM share_grants WHERE token = ?1",
            params![token],
            row_to_share_grant,
        )
        .optional()?
        .ok_or_else(|| Error::NotFound("share token".into()))
    }

    pub fn list_share_grants(
        &self,
        subvolume_id: Option<SubvolumeId>,
    ) -> Result<Vec<ShareGrantRow>> {
        let conn = self.inner.lock();
        if let Some(sv) = subvolume_id {
            let mut stmt = conn.prepare(
                "SELECT id, token, subvolume_id, key, created_by, created_at,
                        expires_at, use_limit, uses, revoked, note
                 FROM share_grants WHERE subvolume_id = ?1
                 ORDER BY created_at DESC",
            )?;
            let rows = stmt
                .query_map(params![sv.to_string()], row_to_share_grant)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, token, subvolume_id, key, created_by, created_at,
                        expires_at, use_limit, uses, revoked, note
                 FROM share_grants ORDER BY created_at DESC",
            )?;
            let rows = stmt
                .query_map([], row_to_share_grant)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    pub fn revoke_share_grant(&self, id: &str) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "UPDATE share_grants SET revoked = 1 WHERE id = ?1",
            params![id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("share {id}")));
        }
        Ok(())
    }

    pub fn delete_share_grant(&self, id: &str) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute("DELETE FROM share_grants WHERE id = ?1", params![id])?;
        if n == 0 {
            return Err(Error::NotFound(format!("share {id}")));
        }
        Ok(())
    }

    /// Atomically increment `uses` iff the grant is still usable.
    /// Returns the updated row on success, or an error describing
    /// why the token is no longer valid (revoked, expired, exhausted).
    pub fn consume_share_use(&self, token: &str, now: i64) -> Result<ShareGrantRow> {
        let conn = self.inner.lock();
        let row: ShareGrantRow = conn
            .query_row(
                "SELECT id, token, subvolume_id, key, created_by, created_at,
                        expires_at, use_limit, uses, revoked, note
                 FROM share_grants WHERE token = ?1",
                params![token],
                row_to_share_grant,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound("share token".into()))?;
        if row.revoked {
            return Err(Error::PermissionDenied);
        }
        if let Some(exp) = row.expires_at {
            if now >= exp {
                return Err(Error::InvalidArgument("share expired".into()));
            }
        }
        if let Some(cap) = row.use_limit {
            if row.uses >= cap {
                return Err(Error::InvalidArgument("share exhausted".into()));
            }
        }
        conn.execute(
            "UPDATE share_grants SET uses = uses + 1 WHERE id = ?1",
            params![row.id],
        )?;
        let updated = ShareGrantRow {
            uses: row.uses + 1,
            ..row
        };
        Ok(updated)
    }

    pub fn insert_share_event(&self, ev: &ShareEventRow) -> Result<i64> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO share_events (share_id, ts, action, remote_ip, user_agent, key, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ev.share_id,
                ev.ts,
                ev.action,
                ev.remote_ip,
                ev.user_agent,
                ev.key,
                ev.status as i64,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn recent_share_events(&self, share_id: &str, limit: u32) -> Result<Vec<ShareEventRow>> {
        let conn = self.inner.lock();
        let limit = if limit == 0 { 500 } else { limit };
        let mut stmt = conn.prepare(
            "SELECT id, share_id, ts, action, remote_ip, user_agent, key, status
               FROM share_events
              WHERE share_id = ?1
              ORDER BY ts DESC, id DESC
              LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![share_id, limit as i64], |r| {
                Ok(ShareEventRow {
                    id: r.get::<_, i64>(0)?,
                    share_id: r.get::<_, String>(1)?,
                    ts: r.get::<_, i64>(2)?,
                    action: r.get::<_, String>(3)?,
                    remote_ip: r.get::<_, String>(4)?,
                    user_agent: r.get::<_, String>(5)?,
                    key: r.get::<_, String>(6)?,
                    status: r.get::<_, i64>(7)?.max(0) as u32,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ------- archives -------

    pub fn insert_archive(&self, row: &ArchiveRow) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO archives
                (id, subvolume_id, name, kind, path, size_bytes, object_count,
                 sha256, created_at, expires_at, retention_days, immutable,
                 note, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                row.id,
                row.subvolume_id,
                row.name,
                row.kind,
                row.path,
                row.size_bytes,
                row.object_count,
                row.sha256,
                row.created_at,
                row.expires_at,
                row.retention_days,
                row.immutable as i64,
                row.note,
                row.created_by,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::AlreadyExists(format!("archive {}", row.name))
            }
            other => other.into(),
        })?;
        Ok(())
    }

    pub fn insert_archive_manifest(
        &self,
        archive_id: &str,
        entries: &[ArchiveEntry],
    ) -> Result<()> {
        let mut conn = self.inner.lock();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO archive_manifests (archive_id, key, size, sha256)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for e in entries {
                stmt.execute(params![archive_id, e.key, e.size as i64, e.sha256])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_archive_manifest(&self, archive_id: &str) -> Result<Vec<ArchiveEntry>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT key, size, sha256 FROM archive_manifests
             WHERE archive_id = ?1 ORDER BY key",
        )?;
        let rows = stmt
            .query_map(params![archive_id], |r| {
                Ok(ArchiveEntry {
                    key: r.get::<_, String>(0)?,
                    size: r.get::<_, i64>(1)?.max(0) as u64,
                    sha256: r.get::<_, String>(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_archive_by_id(&self, id: &str) -> Result<ArchiveRow> {
        let conn = self.inner.lock();
        conn.query_row(
            "SELECT id, subvolume_id, name, kind, path, size_bytes, object_count,
                    sha256, created_at, expires_at, retention_days, immutable,
                    note, created_by
             FROM archives WHERE id = ?1",
            params![id],
            row_to_archive,
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("archive {id}")))
    }

    pub fn get_archive_by_name(&self, subvolume_id: SubvolumeId, name: &str) -> Result<ArchiveRow> {
        let conn = self.inner.lock();
        conn.query_row(
            "SELECT id, subvolume_id, name, kind, path, size_bytes, object_count,
                    sha256, created_at, expires_at, retention_days, immutable,
                    note, created_by
             FROM archives WHERE subvolume_id = ?1 AND name = ?2",
            params![subvolume_id.to_string(), name],
            row_to_archive,
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("archive {name}")))
    }

    pub fn list_archives(&self, subvolume_id: Option<SubvolumeId>) -> Result<Vec<ArchiveRow>> {
        let conn = self.inner.lock();
        if let Some(sv) = subvolume_id {
            let mut stmt = conn.prepare(
                "SELECT id, subvolume_id, name, kind, path, size_bytes, object_count,
                        sha256, created_at, expires_at, retention_days, immutable,
                        note, created_by
                 FROM archives WHERE subvolume_id = ?1
                 ORDER BY created_at DESC",
            )?;
            let rows = stmt
                .query_map(params![sv.to_string()], row_to_archive)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, subvolume_id, name, kind, path, size_bytes, object_count,
                        sha256, created_at, expires_at, retention_days, immutable,
                        note, created_by
                 FROM archives ORDER BY created_at DESC",
            )?;
            let rows = stmt
                .query_map([], row_to_archive)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    pub fn count_archives_for_subvolume(&self, subvolume_id: SubvolumeId) -> Result<u64> {
        let conn = self.inner.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM archives WHERE subvolume_id = ?1",
            params![subvolume_id.to_string()],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    pub fn delete_archive(&self, id: &str) -> Result<ArchiveRow> {
        let mut conn = self.inner.lock();
        let tx = conn.transaction()?;
        let row: ArchiveRow = tx
            .query_row(
                "SELECT id, subvolume_id, name, kind, path, size_bytes, object_count,
                        sha256, created_at, expires_at, retention_days, immutable,
                        note, created_by
                 FROM archives WHERE id = ?1",
                params![id],
                row_to_archive,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("archive {id}")))?;
        tx.execute("DELETE FROM archives WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(row)
    }

    pub fn list_expired_archives(&self, now: i64) -> Result<Vec<ArchiveRow>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, subvolume_id, name, kind, path, size_bytes, object_count,
                    sha256, created_at, expires_at, retention_days, immutable,
                    note, created_by
             FROM archives
             WHERE expires_at IS NOT NULL AND expires_at <= ?1",
        )?;
        let rows = stmt
            .query_map(params![now], row_to_archive)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ------- subvolume policies -------

    pub fn upsert_subvolume_policy(&self, row: &SubvolumePolicyRow) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO subvolume_policies
                (subvolume_id, kind, retention_days, archive_interval_secs,
                 min_age_days, enabled, last_run_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(subvolume_id) DO UPDATE SET
                 kind = excluded.kind,
                 retention_days = excluded.retention_days,
                 archive_interval_secs = excluded.archive_interval_secs,
                 min_age_days = excluded.min_age_days,
                 enabled = excluded.enabled",
            params![
                row.subvolume_id,
                row.kind,
                row.retention_days,
                row.archive_interval_secs as i64,
                row.min_age_days as i64,
                row.enabled as i64,
                row.last_run_at,
                row.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_subvolume_policy(&self, sv: SubvolumeId) -> Result<Option<SubvolumePolicyRow>> {
        let conn = self.inner.lock();
        let row = conn
            .query_row(
                "SELECT subvolume_id, kind, retention_days, archive_interval_secs,
                        min_age_days, enabled, last_run_at, created_at
                 FROM subvolume_policies WHERE subvolume_id = ?1",
                params![sv.to_string()],
                row_to_policy,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_subvolume_policies(&self) -> Result<Vec<SubvolumePolicyRow>> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT subvolume_id, kind, retention_days, archive_interval_secs,
                    min_age_days, enabled, last_run_at, created_at
             FROM subvolume_policies ORDER BY subvolume_id",
        )?;
        let rows = stmt
            .query_map([], row_to_policy)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_subvolume_policy(&self, sv: SubvolumeId) -> Result<()> {
        let conn = self.inner.lock();
        let n = conn.execute(
            "DELETE FROM subvolume_policies WHERE subvolume_id = ?1",
            params![sv.to_string()],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("policy for {sv}")));
        }
        Ok(())
    }

    pub fn update_subvolume_policy_last_run(&self, sv: SubvolumeId, ts: i64) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "UPDATE subvolume_policies SET last_run_at = ?1 WHERE subvolume_id = ?2",
            params![ts, sv.to_string()],
        )?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        let conn = self.inner.lock();
        Ok(conn
            .query_row(
                "SELECT value FROM kv_meta WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.inner.lock();
        conn.execute(
            "INSERT INTO kv_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Helper used by ACL evaluation in the data-plane: resolves a
    /// (subvolume, user) pair into the boolean check result.
    pub fn check_permission(
        &self,
        subvolume: SubvolumeId,
        user: Option<UserId>,
        wanted: Permission,
        public_allowed: bool,
    ) -> Result<bool> {
        let sv = self.get_subvolume(subvolume)?;
        let groups = match user {
            Some(u) => self.groups_for_user(u)?,
            None => HashSet::new(),
        };
        // Owner always has admin.
        if user == Some(sv.owner) {
            return Ok(true);
        }
        Ok(sv.acl.check(user, &groups, wanted, public_allowed))
    }
}

fn row_to_user(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let id: String = r.get(0)?;
    let created: i64 = r.get(3)?;
    let disabled: i64 = r.get(4)?;
    Ok(User {
        id: UserId(parse_uuid(&id)?),
        name: r.get(1)?,
        display_name: r.get(2)?,
        created_at: OffsetDateTime::from_unix_timestamp(created)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        disabled: disabled != 0,
    })
}

fn row_to_group(r: &rusqlite::Row<'_>) -> rusqlite::Result<Group> {
    let id: String = r.get(0)?;
    let created: i64 = r.get(3)?;
    Ok(Group {
        id: GroupId(parse_uuid(&id)?),
        name: r.get(1)?,
        description: r.get(2)?,
        created_at: OffsetDateTime::from_unix_timestamp(created)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
    })
}

fn row_to_subvolume(r: &rusqlite::Row<'_>) -> rusqlite::Result<Subvolume> {
    let id: String = r.get(0)?;
    let owner: String = r.get(2)?;
    let mount: String = r.get(3)?;
    let quota: i64 = r.get(4)?;
    let acl_json: String = r.get(5)?;
    let created: i64 = r.get(6)?;
    let acl: Acl = serde_json::from_str(&acl_json).unwrap_or_default();
    let _ = Principal::Public; // keep import warm
    Ok(Subvolume {
        id: SubvolumeId(parse_uuid(&id)?),
        name: r.get(1)?,
        owner: UserId(parse_uuid(&owner)?),
        mount_path: PathBuf::from(mount),
        quota_bytes: quota.max(0) as u64,
        acl,
        created_at: OffsetDateTime::from_unix_timestamp(created)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
    })
}

fn row_to_snapshot(r: &rusqlite::Row<'_>) -> rusqlite::Result<Snapshot> {
    let id: String = r.get(0)?;
    let sv: String = r.get(1)?;
    let mount: String = r.get(3)?;
    let ro: i64 = r.get(4)?;
    let created: i64 = r.get(5)?;
    Ok(Snapshot {
        id: SnapshotId(parse_uuid(&id)?),
        subvolume: SubvolumeId(parse_uuid(&sv)?),
        name: r.get(2)?,
        mount_path: PathBuf::from(mount),
        readonly: ro != 0,
        created_at: OffsetDateTime::from_unix_timestamp(created)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
    })
}

fn parse_uuid(s: &str) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

// ---------- sync DAO row types ----------

#[derive(Debug, Clone)]
pub struct SyncCredentialsRow {
    pub id: String,
    pub kind: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SyncMountRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub subvolume_id: String,
    pub townos_name: String,
    pub direction: String,
    pub interval_secs: u32,
    pub enabled: bool,
    pub paused: bool,
    pub quota_bytes: u64,
    pub cursor_blob: Option<Vec<u8>>,
    pub config_json: String,
    pub credentials_id: Option<String>,
    pub last_sync_at: Option<i64>,
    pub last_error: Option<String>,
    pub backoff_until: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct SyncObjectRow {
    pub mount_id: String,
    pub remote_id: String,
    pub key: String,
    pub size: u64,
    pub etag: Option<String>,
    pub remote_mtime: i64,
    pub local_mtime: i64,
    pub local_hash: Option<String>,
    pub remote_hash: Option<String>,
    pub last_action: String,
    pub last_synced_at: i64,
}

#[derive(Debug, Clone)]
pub struct SyncEventRow {
    pub id: i64,
    pub mount_id: String,
    pub ts: i64,
    pub level: String,
    pub kind: String,
    pub message: String,
    pub details_json: String,
}

#[derive(Debug, Clone)]
pub struct ShareGrantRow {
    pub id: String,
    pub token: String,
    pub subvolume_id: String,
    pub key: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub use_limit: Option<i64>,
    pub uses: i64,
    pub revoked: bool,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct ShareEventRow {
    pub id: i64,
    pub share_id: String,
    pub ts: i64,
    pub action: String,
    pub remote_ip: String,
    pub user_agent: String,
    pub key: String,
    pub status: u32,
}

fn row_to_share_grant(r: &rusqlite::Row<'_>) -> rusqlite::Result<ShareGrantRow> {
    Ok(ShareGrantRow {
        id: r.get::<_, String>(0)?,
        token: r.get::<_, String>(1)?,
        subvolume_id: r.get::<_, String>(2)?,
        key: r.get::<_, String>(3)?,
        created_by: r.get::<_, String>(4)?,
        created_at: r.get::<_, i64>(5)?,
        expires_at: r.get::<_, Option<i64>>(6)?,
        use_limit: r.get::<_, Option<i64>>(7)?,
        uses: r.get::<_, i64>(8)?,
        revoked: r.get::<_, i64>(9)? != 0,
        note: r.get::<_, String>(10)?,
    })
}

#[derive(Debug, Clone)]
pub struct ArchiveRow {
    pub id: String,
    pub subvolume_id: String,
    pub name: String,
    pub kind: String,
    pub path: String,
    pub size_bytes: i64,
    pub object_count: i64,
    pub sha256: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub retention_days: Option<i64>,
    pub immutable: bool,
    pub note: String,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub key: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct SubvolumePolicyRow {
    pub subvolume_id: String,
    pub kind: String,
    pub retention_days: Option<i64>,
    pub archive_interval_secs: u64,
    pub min_age_days: u64,
    pub enabled: bool,
    pub last_run_at: Option<i64>,
    pub created_at: i64,
}

fn row_to_archive(r: &rusqlite::Row<'_>) -> rusqlite::Result<ArchiveRow> {
    Ok(ArchiveRow {
        id: r.get::<_, String>(0)?,
        subvolume_id: r.get::<_, String>(1)?,
        name: r.get::<_, String>(2)?,
        kind: r.get::<_, String>(3)?,
        path: r.get::<_, String>(4)?,
        size_bytes: r.get::<_, i64>(5)?,
        object_count: r.get::<_, i64>(6)?,
        sha256: r.get::<_, String>(7)?,
        created_at: r.get::<_, i64>(8)?,
        expires_at: r.get::<_, Option<i64>>(9)?,
        retention_days: r.get::<_, Option<i64>>(10)?,
        immutable: r.get::<_, i64>(11)? != 0,
        note: r.get::<_, String>(12)?,
        created_by: r.get::<_, Option<String>>(13)?,
    })
}

fn row_to_policy(r: &rusqlite::Row<'_>) -> rusqlite::Result<SubvolumePolicyRow> {
    Ok(SubvolumePolicyRow {
        subvolume_id: r.get::<_, String>(0)?,
        kind: r.get::<_, String>(1)?,
        retention_days: r.get::<_, Option<i64>>(2)?,
        archive_interval_secs: r.get::<_, i64>(3)?.max(0) as u64,
        min_age_days: r.get::<_, i64>(4)?.max(0) as u64,
        enabled: r.get::<_, i64>(5)? != 0,
        last_run_at: r.get::<_, Option<i64>>(6)?,
        created_at: r.get::<_, i64>(7)?,
    })
}

const SYNC_MOUNT_COLS: &str = "id, name, kind, subvolume_id, townos_name, direction,
    interval_secs, enabled, paused, quota_bytes, cursor_blob, config_json,
    credentials_id, last_sync_at, last_error, backoff_until, created_at";

const SYNC_MOUNT_SELECT_BY_ID: &str = "SELECT id, name, kind, subvolume_id, townos_name, direction,
    interval_secs, enabled, paused, quota_bytes, cursor_blob, config_json,
    credentials_id, last_sync_at, last_error, backoff_until, created_at
    FROM sync_mounts WHERE id = ?1";

const SYNC_MOUNT_SELECT_BY_NAME: &str =
    "SELECT id, name, kind, subvolume_id, townos_name, direction,
    interval_secs, enabled, paused, quota_bytes, cursor_blob, config_json,
    credentials_id, last_sync_at, last_error, backoff_until, created_at
    FROM sync_mounts WHERE name = ?1";

const SYNC_MOUNT_SELECT_ALL: &str = "SELECT id, name, kind, subvolume_id, townos_name, direction,
    interval_secs, enabled, paused, quota_bytes, cursor_blob, config_json,
    credentials_id, last_sync_at, last_error, backoff_until, created_at
    FROM sync_mounts ORDER BY name";

const SYNC_OBJECT_SELECT_ALL: &str = "SELECT mount_id, remote_id, key, size, etag,
    remote_mtime, local_mtime, local_hash, remote_hash, last_action, last_synced_at
    FROM sync_objects WHERE mount_id = ?1 ORDER BY key";

fn sync_mount_row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<SyncMountRow> {
    Ok(SyncMountRow {
        id: r.get::<_, String>(0)?,
        name: r.get::<_, String>(1)?,
        kind: r.get::<_, String>(2)?,
        subvolume_id: r.get::<_, String>(3)?,
        townos_name: r.get::<_, String>(4)?,
        direction: r.get::<_, String>(5)?,
        interval_secs: r.get::<_, i64>(6)?.max(0) as u32,
        enabled: r.get::<_, i64>(7)? != 0,
        paused: r.get::<_, i64>(8)? != 0,
        quota_bytes: r.get::<_, i64>(9)?.max(0) as u64,
        cursor_blob: r.get::<_, Option<Vec<u8>>>(10)?,
        config_json: r.get::<_, String>(11)?,
        credentials_id: r.get::<_, Option<String>>(12)?,
        last_sync_at: r.get::<_, Option<i64>>(13)?,
        last_error: r.get::<_, Option<String>>(14)?,
        backoff_until: r.get::<_, Option<i64>>(15)?,
        created_at: r.get::<_, i64>(16)?,
    })
}

fn sync_object_row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<SyncObjectRow> {
    Ok(SyncObjectRow {
        mount_id: r.get::<_, String>(0)?,
        remote_id: r.get::<_, String>(1)?,
        key: r.get::<_, String>(2)?,
        size: r.get::<_, i64>(3)?.max(0) as u64,
        etag: r.get::<_, Option<String>>(4)?,
        remote_mtime: r.get::<_, i64>(5)?,
        local_mtime: r.get::<_, i64>(6)?,
        local_hash: r.get::<_, Option<String>>(7)?,
        remote_hash: r.get::<_, Option<String>>(8)?,
        last_action: r.get::<_, String>(9)?,
        last_synced_at: r.get::<_, i64>(10)?,
    })
}

// silence dead_code on SYNC_MOUNT_COLS (we keep it as documentation
// of the column ordering, referenced by the row parser above).
#[allow(dead_code)]
const _SYNC_MOUNT_COLS_USED: &str = SYNC_MOUNT_COLS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_round_trip() {
        let s = Store::open_in_memory().unwrap();
        let u = s.create_user("alice", "Alice", "hash").unwrap();
        let got = s.get_user_by_name("alice").unwrap();
        assert_eq!(got.id.0, u.id.0);
    }

    #[test]
    fn group_membership() {
        let s = Store::open_in_memory().unwrap();
        let u = s.create_user("alice", "Alice", "h").unwrap();
        let g = s.create_group("staff", "").unwrap();
        s.add_user_to_group(u.id, g.id).unwrap();
        let groups = s.groups_for_user(u.id).unwrap();
        assert!(groups.contains(&g.id));
    }

    #[test]
    fn users_in_group_returns_members() {
        let s = Store::open_in_memory().unwrap();
        let alice = s.create_user("alice", "Alice", "h").unwrap();
        let bob = s.create_user("bob", "Bob", "h").unwrap();
        let _carol = s.create_user("carol", "Carol", "h").unwrap();
        let staff = s.create_group("staff", "").unwrap();
        s.add_user_to_group(alice.id, staff.id).unwrap();
        s.add_user_to_group(bob.id, staff.id).unwrap();
        let members = s.users_in_group(staff.id).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&alice.id));
        assert!(members.contains(&bob.id));
    }
}
