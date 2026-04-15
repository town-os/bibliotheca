//! OAuth 2.0 authorization-code broker for the bibliotheca CLI.
//!
//! This crate runs the three-legged OAuth dance that bootstraps a
//! refresh token for `sync-*` connectors (today: Dropbox, Google
//! Photos). The broker is deliberately small and self-contained:
//!
//! 1. Build the authorize URL from the provider profile in
//!    `bibliotheca-config`.
//! 2. Bind a localhost listener on `127.0.0.1:<port>` (loopback
//!    only — see [`OAuthConfig::callback_host`]).
//! 3. Print the URL for the operator to open in a browser; the
//!    browser will redirect to our listener on approval.
//! 4. Parse `code` + `state` + `error` out of the redirect.
//! 5. Exchange the code for access + refresh tokens by
//!    `POST`ing to the provider's token URL with PKCE.
//! 6. Return a [`OAuthOutcome`] containing the raw token fields
//!    — the caller (normally `bibliothecactl`) then ships the
//!    outcome to the daemon over gRPC, which encrypts it via the
//!    existing sync credential cipher.
//!
//! The broker never touches bibliotheca's sqlite store and never
//! calls into `sync-core`. It intentionally has no knowledge of
//! what the refresh token is going to be used for — that's a
//! later step the daemon owns. This crate's job is just to
//! survive a single three-legged handshake without leaking state
//! or client secrets into process arguments.

#![deny(unsafe_code)]
#![deny(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use bibliotheca_config::{OAuthConfig, OAuthProviderConfig};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{info, warn};
use url::Url;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unknown oauth provider: {0}")]
    UnknownProvider(String),

    #[error("provider {provider} has no client_id configured")]
    MissingClientId { provider: String },

    #[error("read client secret file {path:?}: {source}")]
    ReadSecretFile {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("bind callback listener on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("build authorize url: {0}")]
    BuildAuthorizeUrl(String),

    #[error("token exchange http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("token exchange failed: {status}: {body}")]
    TokenExchange { status: u16, body: String },

    #[error("provider returned error on redirect: {error} ({description})")]
    ProviderError { error: String, description: String },

    #[error("state mismatch on redirect: expected one, got another")]
    StateMismatch,

    #[error("oauth flow timed out after {secs}s")]
    Timeout { secs: u64 },

    #[error("oauth flow cancelled")]
    Cancelled,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Payload sent back from the browser redirect handler to the
/// waiting broker task.
#[derive(Debug, Clone)]
struct CallbackPayload {
    code: String,
    state: String,
}

/// Successful outcome of the broker flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthOutcome {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub provider: String,
}

/// PKCE verifier / challenge pair (S256).
#[derive(Debug, Clone)]
struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    fn generate() -> Self {
        // RFC 7636 says the verifier is 43-128 chars from an
        // unreserved set. We take 64 bytes of randomness and
        // url-safe-base64-encode them without padding.
        let mut buf = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut buf);
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hashed = hasher.finalize();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hashed);
        Pkce {
            verifier,
            challenge,
        }
    }
}

/// Shared state between the browser-callback axum handler and
/// the broker task awaiting the result.
struct CallbackState {
    expected_state: String,
    sender: Mutex<Option<oneshot::Sender<CallbackResult>>>,
}

#[derive(Debug)]
enum CallbackResult {
    Ok(CallbackPayload),
    Err(Error),
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: i64,
}

/// Per-flow configuration. `oauth` is the full `OAuthConfig`
/// section from `bibliotheca-config`; `provider` selects one of
/// the entries in `oauth.providers`.
pub struct BrokerParams<'a> {
    pub oauth: &'a OAuthConfig,
    pub provider: &'a str,
    pub extra_scopes: Vec<String>,
}

/// Entry point. Runs the full flow. `on_ready` fires exactly
/// once after the loopback listener is bound and the authorize
/// URL has been built; operators typically use it to `println!`
/// the URL or `xdg-open` it. The function then blocks on the
/// browser redirect until the provider calls back, the
/// configured timeout elapses, or the caller drops the future.
pub async fn run_flow<F>(params: BrokerParams<'_>, on_ready: F) -> Result<OAuthOutcome>
where
    F: FnOnce(&str) + Send + 'static,
{
    let provider_cfg = params
        .oauth
        .providers
        .get(params.provider)
        .ok_or_else(|| Error::UnknownProvider(params.provider.to_string()))?;

    if provider_cfg.client_id.is_empty() {
        return Err(Error::MissingClientId {
            provider: params.provider.to_string(),
        });
    }

    let client_secret = load_client_secret(provider_cfg)?;
    let scopes = effective_scopes(provider_cfg, &params.extra_scopes);
    let pkce = Pkce::generate();
    let state_nonce = random_state();

    // Bind the loopback listener first so we know our exact
    // callback URL before building the authorize URL.
    let listen_addr = build_listen_addr(params.oauth)?;
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| Error::Bind {
            addr: listen_addr.to_string(),
            source: e,
        })?;
    let bound = listener.local_addr().map_err(|e| Error::Bind {
        addr: listen_addr.to_string(),
        source: e,
    })?;
    let redirect_uri = format!("http://{bound}/callback");
    info!(listen = %bound, redirect = %redirect_uri, provider = params.provider, "oauth broker listening");

    let authorize_url = build_authorize_url(
        provider_cfg,
        &redirect_uri,
        &scopes,
        &state_nonce,
        Some(&pkce),
    )?;
    on_ready(&authorize_url);

    let (tx, rx) = oneshot::channel::<CallbackResult>();
    let cb_state = Arc::new(CallbackState {
        expected_state: state_nonce.clone(),
        sender: Mutex::new(Some(tx)),
    });
    let router = Router::new()
        .route("/callback", get(handle_callback))
        .with_state(cb_state);

    let shutdown_token = tokio::sync::Notify::new();
    let shutdown = Arc::new(shutdown_token);
    let shutdown_wait = shutdown.clone();
    let server = tokio::spawn(async move {
        let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
            shutdown_wait.notified().await;
        });
        if let Err(e) = serve.await {
            warn!(error = %e, "oauth broker listener exited");
        }
    });

    let timeout = Duration::from_secs(params.oauth.callback_timeout_secs);
    let recv = tokio::time::timeout(timeout, rx).await;

    // Regardless of outcome, shut the listener down cleanly.
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    let callback = match recv {
        Ok(Ok(CallbackResult::Ok(payload))) => payload,
        Ok(Ok(CallbackResult::Err(e))) => return Err(e),
        Ok(Err(_)) => return Err(Error::Cancelled),
        Err(_) => {
            return Err(Error::Timeout {
                secs: params.oauth.callback_timeout_secs,
            })
        }
    };

    if callback.state != state_nonce {
        return Err(Error::StateMismatch);
    }

    let token = exchange_code(
        provider_cfg,
        &client_secret,
        &callback.code,
        &redirect_uri,
        &pkce,
    )
    .await?;
    let now = chrono_unix_seconds();
    let expires_at = if token.expires_in > 0 {
        now + token.expires_in
    } else {
        now + 3600
    };
    let outcome = OAuthOutcome {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at,
        client_id: provider_cfg.client_id.clone(),
        client_secret,
        token_url: provider_cfg.token_url.clone(),
        scopes,
        provider: params.provider.to_string(),
    };
    Ok(outcome)
}

async fn handle_callback(
    State(state): State<Arc<CallbackState>>,
    Query(q): Query<CallbackQuery>,
) -> (StatusCode, Html<&'static str>) {
    let result = if let Some(err) = q.error {
        CallbackResult::Err(Error::ProviderError {
            error: err,
            description: q.error_description.unwrap_or_default(),
        })
    } else {
        match (q.code, q.state) {
            (Some(code), Some(rcv_state)) => {
                if rcv_state != state.expected_state {
                    CallbackResult::Err(Error::StateMismatch)
                } else {
                    CallbackResult::Ok(CallbackPayload {
                        code,
                        state: rcv_state,
                    })
                }
            }
            _ => CallbackResult::Err(Error::ProviderError {
                error: "missing_code".into(),
                description: "redirect missing code or state".into(),
            }),
        }
    };
    let sender = state.sender.lock().take();
    if let Some(tx) = sender {
        let _ = tx.send(result);
    }
    (
        StatusCode::OK,
        Html("<html><body>bibliotheca-oauth: you can close this tab.</body></html>"),
    )
}

fn load_client_secret(provider: &OAuthProviderConfig) -> Result<String> {
    let Some(path) = provider.client_secret_file.as_ref() else {
        return Ok(String::new());
    };
    read_trimmed(path).map_err(|source| Error::ReadSecretFile {
        path: path.clone(),
        source,
    })
}

fn read_trimmed(path: &Path) -> std::io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

fn effective_scopes(provider: &OAuthProviderConfig, extra: &[String]) -> Vec<String> {
    let mut scopes = provider.scopes.clone();
    for s in extra {
        if !scopes.iter().any(|existing| existing == s) {
            scopes.push(s.clone());
        }
    }
    scopes
}

fn build_listen_addr(oauth: &OAuthConfig) -> Result<SocketAddr> {
    let ip: IpAddr = oauth
        .callback_host
        .parse()
        .map_err(|e| Error::BuildAuthorizeUrl(format!("callback_host: {e}")))?;
    // Port 0 in the config means "any free port". If both min
    // and max are set and > 0, pick min — a fancier picker would
    // enumerate free ports in the range, but the callers that
    // care can always run the flow with an explicit port.
    let port = if oauth.callback_port_min > 0 {
        oauth.callback_port_min
    } else {
        0
    };
    Ok(SocketAddr::new(ip, port))
}

fn build_authorize_url(
    provider: &OAuthProviderConfig,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    pkce: Option<&Pkce>,
) -> Result<String> {
    let mut url =
        Url::parse(&provider.authorize_url).map_err(|e| Error::BuildAuthorizeUrl(e.to_string()))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", &provider.client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("response_type", "code");
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
        q.append_pair("state", state);
        if provider.pkce {
            if let Some(p) = pkce {
                q.append_pair("code_challenge", &p.challenge);
                q.append_pair("code_challenge_method", "S256");
            }
        }
        for (k, v) in &provider.extra_authorize_params {
            q.append_pair(k, v);
        }
    }
    Ok(url.to_string())
}

async fn exchange_code(
    provider: &OAuthProviderConfig,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    pkce: &Pkce,
) -> Result<TokenResponse> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.to_string()),
        ("redirect_uri".into(), redirect_uri.to_string()),
        ("client_id".into(), provider.client_id.clone()),
    ];
    if !client_secret.is_empty() {
        form.push(("client_secret".into(), client_secret.to_string()));
    }
    if provider.pkce {
        form.push(("code_verifier".into(), pkce.verifier.clone()));
    }
    let resp = http.post(&provider.token_url).form(&form).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::TokenExchange {
            status: status.as_u16(),
            body,
        });
    }
    let token: TokenResponse = resp.json().await?;
    Ok(token)
}

fn random_state() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn chrono_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
