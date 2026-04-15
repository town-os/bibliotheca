//! YAML-backed configuration for `bibliothecad` and friends.
//!
//! This crate centralizes every tunable the daemon, CLI, and
//! ancillary tools consume. All settings live in one
//! `bibliotheca.yml` file; the daemon and CLI both parse it via
//! [`BibliothecaConfig::load`]. CLI flags still exist for
//! emergency overrides and continue to take precedence over the
//! file, but the file is the authoritative source of defaults.
//!
//! The shape is intentionally flat within each section so that an
//! operator can read the file top-to-bottom without chasing enum
//! variants. Every section implements `Default` with the same
//! values the Phase 1 CLI flags shipped with, so an empty
//! `bibliotheca.yml` preserves existing behaviour.
//!
//! Paths of note:
//!
//! - Default config path is `/etc/bibliotheca/bibliotheca.yml`.
//! - If `--config` is set and the file does not exist, loading
//!   errors out (loud failure for operators who explicitly asked
//!   for a file).
//! - If `--config` is unset and the default path does not exist,
//!   loading falls back to [`BibliothecaConfig::default`] (no
//!   warning — a brand new deployment should just work).
//!
//! Every new feature that adds a configurable variable appends it
//! to one of the sections below, gets a `Default` impl, and lands
//! with a matching stanza in `examples/bibliotheca.yml`.

#![deny(unsafe_code)]
#![deny(dead_code)]
#![forbid(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/bibliotheca/bibliotheca.yml";

#[derive(Debug, Error)]
pub enum Error {
    #[error("config i/o: {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("config parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },
    #[error("config not found: {0}")]
    NotFound(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BibliothecaConfig {
    pub daemon: DaemonConfig,
    pub sync: SyncConfig,
    pub anisette: AnisetteConfig,
    pub oauth: OAuthConfig,
    pub share: ShareConfig,
    pub archive: ArchiveConfig,
}

impl BibliothecaConfig {
    /// Parse a YAML config file. Returns a wrapped `NotFound`
    /// error if the path doesn't exist — callers that want a
    /// graceful fallback should use [`Self::load_or_default`].
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(path.to_path_buf()),
            _ => Error::Io {
                path: path.to_path_buf(),
                source: e,
            },
        })?;
        let cfg: BibliothecaConfig =
            serde_yaml_ng::from_slice(&bytes).map_err(|e| Error::Parse {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(cfg)
    }

    /// Resolution rule: explicit path must exist (hard error);
    /// default path is best-effort (fall back to defaults).
    pub fn load_or_default(explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            return Self::load(path);
        }
        let default_path = Path::new(DEFAULT_CONFIG_PATH);
        match Self::load(default_path) {
            Ok(cfg) => Ok(cfg),
            Err(Error::NotFound(_)) => Ok(Self::default()),
            Err(other) => Err(other),
        }
    }

    /// Serialize to YAML. Used by tests + an eventual
    /// `bibliothecactl config show` subcommand.
    pub fn to_yaml(&self) -> String {
        // to_string is infallible for plain structs that derive
        // Serialize with no non-string keys — but we'd rather
        // surface a broken config than panic at runtime.
        serde_yaml_ng::to_string(self).unwrap_or_else(|e| format!("# error: {e}\n"))
    }
}

// ---------------------------------------------------------------------
// daemon
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DaemonConfig {
    pub socket: PathBuf,
    pub db: PathBuf,
    pub root: PathBuf,
    pub btrfs_bin: PathBuf,
    pub interfaces_file: Option<PathBuf>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from("/run/bibliotheca/control.sock"),
            db: PathBuf::from("/var/lib/bibliotheca/bibliotheca.db"),
            root: PathBuf::from("/var/lib/bibliotheca/subvolumes"),
            btrfs_bin: PathBuf::from("btrfs"),
            interfaces_file: None,
        }
    }
}

// ---------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SyncConfig {
    pub townos_url: Option<Url>,
    pub townos_username: Option<String>,
    pub townos_password_file: Option<PathBuf>,
    pub townos_storage_root: PathBuf,
    pub secret_key_file: Option<PathBuf>,
    pub secret_key_env: String,
    pub default_quota_bytes: u64,
    pub default_interval_secs: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            townos_url: None,
            townos_username: None,
            townos_password_file: None,
            townos_storage_root: PathBuf::from("/var/lib/townos/storage"),
            secret_key_file: None,
            secret_key_env: "BIBLIOTHECA_SECRET_KEY".to_string(),
            default_quota_bytes: 10 * 1024 * 1024 * 1024,
            default_interval_secs: 300,
        }
    }
}

// ---------------------------------------------------------------------
// anisette
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AnisetteConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub upstreams: Vec<Url>,
    pub cache_ttl_secs: u64,
    pub request_timeout_secs: u64,
    pub backoff_secs: u64,
    pub mdns_enabled: bool,
}

impl Default for AnisetteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:6969".parse().expect("hardcoded loopback parse"),
            upstreams: Vec::new(),
            cache_ttl_secs: 20,
            request_timeout_secs: 10,
            backoff_secs: 60,
            mdns_enabled: false,
        }
    }
}

// ---------------------------------------------------------------------
// oauth
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OAuthConfig {
    /// Host the local loopback listener binds to during the
    /// authorization-code dance. `127.0.0.1` or `[::1]`.
    pub callback_host: String,
    /// Lower bound (inclusive) of the port range the broker tries
    /// when binding the loopback listener. 0 means "any free
    /// port"; operators behind network namespaces sometimes want
    /// a specific range.
    pub callback_port_min: u16,
    pub callback_port_max: u16,
    /// Seconds the broker waits for the browser callback before
    /// giving up.
    pub callback_timeout_secs: u64,
    /// Built-in provider profiles the CLI can select via
    /// `--kind`. Operators can add their own here; keys are
    /// `dropbox`, `gphotos`, or any custom label.
    pub providers: std::collections::BTreeMap<String, OAuthProviderConfig>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "dropbox".to_string(),
            OAuthProviderConfig {
                authorize_url: "https://www.dropbox.com/oauth2/authorize".to_string(),
                token_url: "https://api.dropboxapi.com/oauth2/token".to_string(),
                scopes: vec![
                    "files.content.read".into(),
                    "files.content.write".into(),
                    "files.metadata.read".into(),
                ],
                client_id: String::new(),
                client_secret_file: None,
                pkce: true,
                extra_authorize_params: Default::default(),
            },
        );
        providers.insert(
            "gphotos".to_string(),
            OAuthProviderConfig {
                authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                token_url: "https://oauth2.googleapis.com/token".to_string(),
                scopes: vec!["https://www.googleapis.com/auth/photoslibrary".to_string()],
                client_id: String::new(),
                client_secret_file: None,
                pkce: true,
                extra_authorize_params: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert("access_type".to_string(), "offline".to_string());
                    m.insert("prompt".to_string(), "consent".to_string());
                    m
                },
            },
        );
        Self {
            callback_host: "127.0.0.1".to_string(),
            callback_port_min: 0,
            callback_port_max: 0,
            callback_timeout_secs: 600,
            providers,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OAuthProviderConfig {
    pub authorize_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub client_id: String,
    pub client_secret_file: Option<PathBuf>,
    pub pkce: bool,
    pub extra_authorize_params: std::collections::BTreeMap<String, String>,
}

impl Default for OAuthProviderConfig {
    fn default() -> Self {
        Self {
            authorize_url: String::new(),
            token_url: String::new(),
            scopes: Vec::new(),
            client_id: String::new(),
            client_secret_file: None,
            pkce: true,
            extra_authorize_params: Default::default(),
        }
    }
}

// ---------------------------------------------------------------------
// share
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ShareConfig {
    /// Public base URL prepended to every new share token when
    /// pretty-printing. Doesn't affect token lookup or validity.
    pub base_url: Option<Url>,
    /// Default TTL (seconds) applied to shares created without an
    /// explicit `--expires`. `None` = no expiry.
    pub default_ttl_secs: Option<u64>,
    /// Maximum TTL the API accepts. Requests exceeding this are
    /// rejected with `InvalidArgument`. `None` = unlimited.
    pub max_ttl_secs: Option<u64>,
    /// Default cap on the number of successful uses before a
    /// share auto-revokes. `None` = unlimited.
    pub default_use_limit: Option<u64>,
    /// Length in bytes of the random token minted for each
    /// share. 32 is the default; a larger value is fine, smaller
    /// is not recommended.
    pub token_bytes: usize,
}

impl Default for ShareConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            default_ttl_secs: Some(7 * 24 * 3600),
            max_ttl_secs: None,
            default_use_limit: None,
            token_bytes: 32,
        }
    }
}

// ---------------------------------------------------------------------
// archive
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ArchiveConfig {
    /// Absolute filesystem root for `tarball`-kind archives. One
    /// archive = one file under `<root>/<subvolume>/<archive_id>.tar`.
    pub root: PathBuf,
    /// Default archive kind when a `CreateArchive` request does
    /// not specify one.
    pub default_kind: String,
    /// Default retention (days) if a request does not specify
    /// one. `None` = archives live forever unless explicitly
    /// deleted.
    pub default_retention_days: Option<u64>,
    /// Interval (seconds) between lifecycle sweeps. Set to 0 to
    /// disable the lifecycle task entirely.
    pub lifecycle_interval_secs: u64,
    /// When a lifecycle sweep encounters a subvolume with a
    /// policy row, this is the minimum age for an auto-archive
    /// to trigger. Acts as a safety net against misconfigured
    /// policies that would archive newborn data.
    pub min_archive_age_days: u64,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/var/lib/bibliotheca/archives"),
            default_kind: "snapshot".to_string(),
            default_retention_days: Some(365),
            lifecycle_interval_secs: 3600,
            min_archive_age_days: 1,
        }
    }
}
