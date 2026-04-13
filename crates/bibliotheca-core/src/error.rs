use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("permission denied")]
    PermissionDenied,

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("backend error: {0}")]
    Backend(String),

    #[error("storage error: {0}")]
    Store(#[from] rusqlite::Error),

    #[error("password error: {0}")]
    Password(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
