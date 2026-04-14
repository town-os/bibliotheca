//! The credential blob stored encrypted inside the sync subsystem.
//!
//! Every connector receives a [`CredentialBlob`] when it is
//! constructed. The blob's enum variant must match the connector's
//! expectation — e.g. `ICloudConnector` expects
//! `CredentialBlob::ICloud`. Mismatches are rejected at connector
//! construction time by returning
//! [`crate::error::Error::InvalidArgument`].

use serde::{Deserialize, Serialize};

/// Connector-facing projection of a decrypted credential row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialBlob {
    Basic {
        username: String,
        password: String,
    },
    Token {
        token: String,
        #[serde(default)]
        refresh_token: Option<String>,
        #[serde(default)]
        expires_at: Option<i64>,
    },
    OAuth2 {
        access_token: String,
        refresh_token: String,
        expires_at: i64,
        client_id: String,
        client_secret: String,
        token_url: String,
    },
    ICloud {
        apple_id: String,
        password: String,
        #[serde(default)]
        trust_token: Option<String>,
        #[serde(default)]
        session_cookies: Vec<u8>,
        anisette_url: String,
    },
    Ipfs {
        api_url: String,
        #[serde(default)]
        auth_header: Option<String>,
    },
}

/// Stable short identifier for the discriminant, stored in the
/// `sync_credentials.kind` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Basic,
    Token,
    OAuth2,
    ICloud,
    Ipfs,
}

impl CredentialKind {
    pub fn as_wire(self) -> &'static str {
        match self {
            CredentialKind::Basic => "basic",
            CredentialKind::Token => "token",
            CredentialKind::OAuth2 => "oauth2",
            CredentialKind::ICloud => "icloud",
            CredentialKind::Ipfs => "ipfs",
        }
    }
}

impl CredentialBlob {
    pub fn discriminant(&self) -> CredentialKind {
        match self {
            CredentialBlob::Basic { .. } => CredentialKind::Basic,
            CredentialBlob::Token { .. } => CredentialKind::Token,
            CredentialBlob::OAuth2 { .. } => CredentialKind::OAuth2,
            CredentialBlob::ICloud { .. } => CredentialKind::ICloud,
            CredentialBlob::Ipfs { .. } => CredentialKind::Ipfs,
        }
    }
}
