use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no upstream anisette servers configured")]
    NoUpstreams,

    #[error("all upstream anisette servers are unreachable")]
    AllUpstreamsDown,

    #[error("not supported: {0}")]
    NotSupported(String),

    #[error("upstream already exists: {0}")]
    AlreadyExists(String),

    #[error("upstream not found: {0}")]
    NotFound(String),

    #[error("invalid url: {0}")]
    InvalidUrl(String),

    #[error("upstream {upstream} returned http {status}")]
    UpstreamStatus { upstream: String, status: u16 },

    #[error("upstream body parse: {0}")]
    BodyParse(String),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
