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
