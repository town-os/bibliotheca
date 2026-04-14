use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("permission denied")]
    PermissionDenied,

    #[error("sync subsystem disabled: {0}")]
    SyncDisabled(String),

    #[error("connector not registered: {0}")]
    UnknownConnector(String),

    #[error("needs two-factor auth")]
    NeedsTwoFactor,

    #[error("quota exceeded")]
    QuotaExceeded,

    #[error("transient error: {0}")]
    Transient(String),

    #[error("fatal error: {0}")]
    Fatal(String),

    #[error("townos: {0}")]
    Townos(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("core: {0}")]
    Core(#[from] bibliotheca_core::error::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// True for error conditions that should trigger exponential
    /// backoff rather than pausing the mount.
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Transient(_) | Error::Http(_))
    }
}
