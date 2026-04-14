//! Data-plane helper shared by the transport crates.
//!
//! Each protocol maps incoming requests onto
//! `(subvolume, object_key, principal, permission)` and then delegates
//! the byte-moving here. Centralizing the path-traversal guard and the
//! ACL evaluation means the transports only have to speak their wire
//! format — they never get to skip the authorization check or write
//! outside a subvolume mount.

use std::path::{Component, Path, PathBuf};

use serde::{Serialize, Serializer};
use time::OffsetDateTime;

use crate::acl::Permission;
use crate::error::{Error, Result};
use crate::identity::UserId;
use crate::service::BibliothecaService;
use crate::subvolume::Subvolume;

/// Metadata describing an object inside a subvolume.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectMeta {
    /// Key relative to the subvolume root, always forward-slash separated.
    pub key: String,
    pub size: u64,
    #[serde(serialize_with = "serialize_unix")]
    pub modified: OffsetDateTime,
    pub is_dir: bool,
}

fn serialize_unix<S: Serializer>(
    ts: &OffsetDateTime,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_i64(ts.unix_timestamp())
}

/// Thin wrapper around [`BibliothecaService`] that exposes ACL-checked
/// object CRUD against subvolume mount paths. Transports use this
/// instead of touching the filesystem directly.
#[derive(Clone)]
pub struct DataStore {
    svc: BibliothecaService,
}

impl DataStore {
    pub fn new(svc: BibliothecaService) -> Self {
        Self { svc }
    }

    pub fn service(&self) -> &BibliothecaService {
        &self.svc
    }

    pub fn subvolume(&self, name: &str) -> Result<Subvolume> {
        self.svc.get_subvolume(name)
    }

    /// List subvolumes the given user owns. Used by list-buckets on the
    /// bucket-shaped interfaces (S3, GCS).
    pub fn owned_subvolumes(&self, user: UserId) -> Result<Vec<Subvolume>> {
        self.svc.list_subvolumes(Some(user), 0, 0)
    }

    /// Convenience: authenticate with an HTTP Basic-style username +
    /// password pair.
    pub fn authenticate_basic(
        &self,
        user: &str,
        pass: &str,
    ) -> Result<Option<crate::identity::User>> {
        self.svc.verify_user_password(user, pass)
    }

    fn authorize(
        &self,
        sv: &Subvolume,
        user: Option<UserId>,
        wanted: Permission,
        public_allowed: bool,
    ) -> Result<()> {
        if self
            .svc
            .check_permission(sv.id, user, wanted, public_allowed)?
        {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Read an object's bytes.
    pub fn get(
        &self,
        sv_name: &str,
        key: &str,
        user: Option<UserId>,
        public_allowed: bool,
    ) -> Result<Vec<u8>> {
        let sv = self.subvolume(sv_name)?;
        self.authorize(&sv, user, Permission::Read, public_allowed)?;
        let abs = resolve_key(&sv.mount_path, key)?;
        if !abs.exists() {
            return Err(Error::NotFound(format!("{sv_name}/{key}")));
        }
        if abs.is_dir() {
            return Err(Error::InvalidArgument("target is a directory".into()));
        }
        std::fs::read(&abs).map_err(Error::from)
    }

    /// Look up metadata for an object without reading its body.
    pub fn head(
        &self,
        sv_name: &str,
        key: &str,
        user: Option<UserId>,
        public_allowed: bool,
    ) -> Result<ObjectMeta> {
        let sv = self.subvolume(sv_name)?;
        self.authorize(&sv, user, Permission::Read, public_allowed)?;
        let abs = resolve_key(&sv.mount_path, key)?;
        let md = match std::fs::metadata(&abs) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound(format!("{sv_name}/{key}")))
            }
            Err(e) => return Err(e.into()),
        };
        Ok(ObjectMeta {
            key: key.trim_start_matches('/').to_string(),
            size: md.len(),
            modified: md
                .modified()
                .ok()
                .map(OffsetDateTime::from)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            is_dir: md.is_dir(),
        })
    }

    /// Write (or overwrite) an object with the given bytes.
    pub fn put(
        &self,
        sv_name: &str,
        key: &str,
        user: Option<UserId>,
        public_allowed: bool,
        bytes: &[u8],
    ) -> Result<ObjectMeta> {
        let sv = self.subvolume(sv_name)?;
        self.authorize(&sv, user, Permission::Write, public_allowed)?;
        if sv.quota_bytes > 0 && (bytes.len() as u64) > sv.quota_bytes {
            return Err(Error::InvalidArgument(
                "object exceeds subvolume quota".into(),
            ));
        }
        let abs = resolve_key(&sv.mount_path, key)?;
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, bytes)?;
        self.head(sv_name, key, user, public_allowed)
    }

    /// Delete an object, or an empty directory.
    pub fn delete(
        &self,
        sv_name: &str,
        key: &str,
        user: Option<UserId>,
        public_allowed: bool,
    ) -> Result<()> {
        let sv = self.subvolume(sv_name)?;
        self.authorize(&sv, user, Permission::Delete, public_allowed)?;
        let abs = resolve_key(&sv.mount_path, key)?;
        if !abs.exists() {
            return Err(Error::NotFound(format!("{sv_name}/{key}")));
        }
        if abs.is_dir() {
            std::fs::remove_dir_all(&abs)?;
        } else {
            std::fs::remove_file(&abs)?;
        }
        Ok(())
    }

    /// Create a directory (collection) inside the subvolume.
    pub fn mkdir(
        &self,
        sv_name: &str,
        key: &str,
        user: Option<UserId>,
        public_allowed: bool,
    ) -> Result<ObjectMeta> {
        let sv = self.subvolume(sv_name)?;
        self.authorize(&sv, user, Permission::Write, public_allowed)?;
        let abs = resolve_key(&sv.mount_path, key)?;
        if abs.exists() {
            return Err(Error::AlreadyExists(format!("{sv_name}/{key}")));
        }
        std::fs::create_dir_all(&abs)?;
        self.head(sv_name, key, user, public_allowed)
    }

    /// List immediate children of a prefix. `prefix = ""` lists the
    /// subvolume root.
    pub fn list(
        &self,
        sv_name: &str,
        prefix: &str,
        user: Option<UserId>,
        public_allowed: bool,
    ) -> Result<Vec<ObjectMeta>> {
        let sv = self.subvolume(sv_name)?;
        self.authorize(&sv, user, Permission::List, public_allowed)?;
        let abs = resolve_key(&sv.mount_path, prefix)?;
        if !abs.exists() {
            return Err(Error::NotFound(format!("{sv_name}/{prefix}")));
        }
        let mut out = Vec::new();
        if abs.is_dir() {
            for entry in std::fs::read_dir(&abs)? {
                let entry = entry?;
                let md = entry.metadata()?;
                let rel = entry
                    .path()
                    .strip_prefix(&sv.mount_path)
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|_| PathBuf::from(entry.file_name()));
                let key_str = rel
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(s) => s.to_str(),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                out.push(ObjectMeta {
                    key: key_str,
                    size: md.len(),
                    modified: md
                        .modified()
                        .ok()
                        .map(OffsetDateTime::from)
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH),
                    is_dir: md.is_dir(),
                });
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    /// Recursive list, yielding every file (no directories) under a
    /// prefix. Used by the S3/GCS "list objects" operations.
    pub fn list_recursive(
        &self,
        sv_name: &str,
        prefix: &str,
        user: Option<UserId>,
        public_allowed: bool,
    ) -> Result<Vec<ObjectMeta>> {
        let sv = self.subvolume(sv_name)?;
        self.authorize(&sv, user, Permission::List, public_allowed)?;
        let abs = resolve_key(&sv.mount_path, prefix)?;
        let mut out = Vec::new();
        if abs.is_dir() {
            walk(&sv.mount_path, &abs, &mut out)?;
        } else if abs.is_file() {
            let md = std::fs::metadata(&abs)?;
            out.push(to_meta(&sv.mount_path, &abs, &md));
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }
}

fn walk(root: &Path, cur: &Path, out: &mut Vec<ObjectMeta>) -> Result<()> {
    for entry in std::fs::read_dir(cur)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            walk(root, &path, out)?;
        } else {
            let md = entry.metadata()?;
            out.push(to_meta(root, &path, &md));
        }
    }
    Ok(())
}

fn to_meta(root: &Path, abs: &Path, md: &std::fs::Metadata) -> ObjectMeta {
    let rel = abs.strip_prefix(root).unwrap_or(abs);
    let key = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    ObjectMeta {
        key,
        size: md.len(),
        modified: md
            .modified()
            .ok()
            .map(OffsetDateTime::from)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        is_dir: false,
    }
}

/// Resolve a forward-slash object key underneath a subvolume root.
/// Rejects paths that would escape via `..`, absolute components, or
/// non-UTF8 segments, and always returns a path underneath `root`.
pub fn resolve_key(root: &Path, key: &str) -> Result<PathBuf> {
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let trimmed = key.trim_start_matches('/');
    let mut normalized = canon_root.clone();
    if trimmed.is_empty() {
        return Ok(normalized);
    }
    for segment in trimmed.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                if !normalized.pop() || !normalized.starts_with(&canon_root) {
                    return Err(Error::InvalidArgument(format!(
                        "path escapes subvolume: {key}"
                    )));
                }
            }
            other => {
                if other.contains('\\') || other.contains('\0') {
                    return Err(Error::InvalidArgument(format!(
                        "invalid path segment: {other}"
                    )));
                }
                normalized.push(other);
            }
        }
    }
    if !normalized.starts_with(&canon_root) {
        return Err(Error::InvalidArgument(format!(
            "path escapes subvolume: {key}"
        )));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SubvolumeBackend;
    use crate::store::Store;
    use crate::testing::MemoryBackend;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn harness() -> (TempDir, DataStore, BibliothecaService) {
        let tmp = TempDir::new().unwrap();
        let backend = Arc::new(MemoryBackend::new(tmp.path().join("sv")));
        let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
        let store = Store::open_in_memory().unwrap();
        let svc = BibliothecaService::new(store, dyn_backend);
        let ds = DataStore::new(svc.clone());
        (tmp, ds, svc)
    }

    #[tokio::test]
    async fn put_get_round_trip() {
        let (_tmp, ds, svc) = harness();
        let alice = svc.create_user("alice", "Alice", "pw").unwrap();
        svc.create_subvolume("photos", alice.id, 0, None)
            .await
            .unwrap();
        ds.put("photos", "foo/bar.bin", Some(alice.id), false, b"hello")
            .unwrap();
        let got = ds
            .get("photos", "foo/bar.bin", Some(alice.id), false)
            .unwrap();
        assert_eq!(got, b"hello");
        let meta = ds
            .head("photos", "foo/bar.bin", Some(alice.id), false)
            .unwrap();
        assert_eq!(meta.size, 5);
    }

    #[tokio::test]
    async fn put_denied_without_permission() {
        let (_tmp, ds, svc) = harness();
        let alice = svc.create_user("alice", "Alice", "pw").unwrap();
        let _bob = svc.create_user("bob", "Bob", "pw").unwrap();
        svc.create_subvolume("photos", alice.id, 0, None)
            .await
            .unwrap();
        let err = ds
            .put(
                "photos",
                "foo.bin",
                Some(svc.get_user("bob").unwrap().id),
                false,
                b"x",
            )
            .unwrap_err();
        assert!(matches!(err, Error::PermissionDenied));
    }

    #[tokio::test]
    async fn quota_rejects_oversized_put() {
        let (_tmp, ds, svc) = harness();
        let alice = svc.create_user("alice", "Alice", "pw").unwrap();
        svc.create_subvolume("photos", alice.id, 10, None)
            .await
            .unwrap();
        let err = ds
            .put("photos", "big.bin", Some(alice.id), false, &[0u8; 32])
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn list_is_sorted_and_recursive() {
        let (_tmp, ds, svc) = harness();
        let alice = svc.create_user("alice", "Alice", "pw").unwrap();
        svc.create_subvolume("photos", alice.id, 0, None)
            .await
            .unwrap();
        ds.put("photos", "a.txt", Some(alice.id), false, b"1")
            .unwrap();
        ds.put("photos", "nested/b.txt", Some(alice.id), false, b"2")
            .unwrap();
        ds.put("photos", "nested/c.txt", Some(alice.id), false, b"3")
            .unwrap();
        let all = ds
            .list_recursive("photos", "", Some(alice.id), false)
            .unwrap();
        let keys: Vec<_> = all.iter().map(|m| m.key.clone()).collect();
        assert_eq!(keys, vec!["a.txt", "nested/b.txt", "nested/c.txt"]);
    }

    #[test]
    fn resolve_rejects_traversal() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        assert!(resolve_key(root, "foo/bar").is_ok());
        assert!(resolve_key(root, "../etc/passwd").is_err());
        assert!(resolve_key(root, "/./foo/../../..").is_err());
    }
}
