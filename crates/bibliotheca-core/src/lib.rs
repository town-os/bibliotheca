//! Bibliotheca core: identity, ACL, and storage abstractions.
//!
//! This crate is intentionally backend-agnostic. The [`SubvolumeBackend`]
//! trait is implemented by `bibliotheca-btrfs` for the production code path,
//! and by an in-memory shim used in tests. The metadata store is
//! sqlite-backed by default; identities, group membership, ACLs, and
//! subvolume records all live there so the daemon can recover state
//! across restarts without scanning the filesystem.

pub mod acl;
pub mod backend;
pub mod data;
pub mod error;
pub mod identity;
pub mod password;
pub mod service;
pub mod store;
pub mod subvolume;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub use error::{Error, Result};
