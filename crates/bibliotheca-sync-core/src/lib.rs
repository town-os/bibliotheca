//! Core of the bibliotheca sync connector subsystem.
//!
//! This crate defines:
//!
//! - [`SyncConnector`] — the trait every connector crate implements.
//! - [`Supervisor`] — a tokio task that owns a collection of
//!   [`MountWorker`]s, each running one connector's poll/push loop.
//! - A thin typed wrapper over the sync DAOs in
//!   `bibliotheca-core::store` (see [`state::SyncStateStore`]).
//! - [`CredentialCipher`] — AES-GCM-256 encryption-at-rest for
//!   connector secrets, keyed off an operator-supplied master key.
//! - [`TownosClient`] — a minimal REST client for town-os's
//!   systemcontroller storage endpoints (auth, create, modify,
//!   remove, list). bibliotheca procures subvolumes through this
//!   interface rather than driving the btrfs backend directly, so
//!   the sync subsystem participates in town-os's tenant and quota
//!   accounting.
//!
//! Data writes by every connector go through
//! [`bibliotheca_core::data::DataStore`], not around it. The sync
//! scheduler is privileged only in one narrow way: it adopts
//! subvolumes on behalf of mounts.

#![allow(clippy::result_large_err)]

pub mod conflict;
pub mod credentials;
pub mod crypto;
pub mod error;
pub mod events;
pub mod mount;
pub mod retry;
pub mod scheduler;
pub mod state;
pub mod testing;
pub mod townos;
pub mod trait_;

pub use conflict::{Resolution, Resolver};
pub use credentials::{CredentialBlob, CredentialKind};
pub use crypto::{CredentialCipher, SecretKey};
pub use error::{Error, Result};
pub use events::{EventLevel, SyncEvent};
pub use mount::{ConnectorKind, Direction, MountId, MountSpec, SyncMount, SyncMountSnapshot};
pub use retry::ExponentialBackoff;
pub use scheduler::Supervisor;
pub use state::SyncStateStore;
pub use townos::{Filesystem as TownosFilesystem, TownosClient, TownosConfig, TownosCreds};
pub use trait_::{Change, ConnectorFactory, ListPage, RemoteObject, SyncConnector, UploadHints};
