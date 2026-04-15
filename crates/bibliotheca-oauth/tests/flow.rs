//! End-to-end OAuth broker test against an axum-mocked
//! authorization + token server.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use bibliotheca_config::{OAuthConfig, OAuthProviderConfig};
use bibliotheca_oauth::{run_flow, BrokerParams, Error};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::oneshot;

#[derive(Default)]
struct ProviderState {
    last_code_challenge: Mutex<Option<String>>,
    last_verifier: Mutex<Option<String>>,
    code_value: Mutex<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    #[allow(dead_code)]
    response_type: String,
    #[serde(default)]
    scope: String,
    state: String,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
}

async fn authorize(
    State(state): State<Arc<ProviderState>>,
    Query(q): Query<AuthorizeQuery>,
) -> axum::response::Response {
    assert_eq!(q.client_id, "test-client");
    assert_eq!(q.code_challenge_method.as_deref(), Some("S256"));
    *state.last_code_challenge.lock() = q.code_challenge.clone();
    assert!(q.scope.contains("files.content.read"));
    let code = {
        let mut g = state.code_value.lock();
        *g = "auth-code-1".to_string();
        g.clone()
    };
    let redirect = format!("{}?code={}&state={}", q.redirect_uri, code, q.state);
    axum::response::Redirect::to(&redirect).into_response()
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    #[allow(dead_code)]
    redirect_uri: String,
    #[allow(dead_code)]
    client_id: String,
    #[serde(default)]
    code_verifier: Option<String>,
}

async fn token(
    State(state): State<Arc<ProviderState>>,
    Form(form): Form<TokenForm>,
) -> axum::response::Response {
    if form.grant_type != "authorization_code" {
        return (StatusCode::BAD_REQUEST, "bad grant").into_response();
    }
    let expected_code = state.code_value.lock().clone();
    if form.code != expected_code {
        return (StatusCode::BAD_REQUEST, "bad code").into_response();
    }
    *state.last_verifier.lock() = form.code_verifier.clone();
    Json(json!({
        "access_token": "at-new",
        "refresh_token": "rt-new",
        "expires_in": 3600,
    }))
    .into_response()
}

async fn spawn_provider() -> (SocketAddr, Arc<ProviderState>) {
    let state = Arc::new(ProviderState::default());
    let app = Router::new()
        .route("/oauth2/authorize", get(authorize))
        .route("/oauth2/token", post(token))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, state)
}

fn oauth_config_with_provider(addr: SocketAddr, secret_file: Option<PathBuf>) -> OAuthConfig {
    let mut providers = BTreeMap::new();
    providers.insert(
        "test".to_string(),
        OAuthProviderConfig {
            authorize_url: format!("http://{addr}/oauth2/authorize"),
            token_url: format!("http://{addr}/oauth2/token"),
            scopes: vec!["files.content.read".into(), "files.content.write".into()],
            client_id: "test-client".to_string(),
            client_secret_file: secret_file,
            pkce: true,
            extra_authorize_params: BTreeMap::new(),
        },
    );
    OAuthConfig {
        callback_host: "127.0.0.1".to_string(),
        callback_port_min: 0,
        callback_port_max: 0,
        callback_timeout_secs: 10,
        providers,
    }
}

#[tokio::test]
async fn full_flow_exchanges_code_for_tokens() {
    let (addr, provider_state) = spawn_provider().await;
    let cfg = oauth_config_with_provider(addr, None);

    // A oneshot carries the authorize URL from the broker's
    // `on_ready` callback out to the test harness, which then
    // GETs it (following redirects) to play the role of a
    // browser approving the request.
    let (ready_tx, ready_rx) = oneshot::channel::<String>();
    let ready_slot = Arc::new(Mutex::new(Some(ready_tx)));
    let slot_for_cb = ready_slot.clone();

    // Drive the flow concurrently with a "browser" task that
    // waits for the URL, then hits it.
    let broker_fut = run_flow(
        BrokerParams {
            oauth: &cfg,
            provider: "test",
            extra_scopes: vec![],
        },
        move |url| {
            if let Some(tx) = slot_for_cb.lock().take() {
                let _ = tx.send(url.to_string());
            }
        },
    );

    let browser_fut = async move {
        let url = ready_rx.await.expect("authorize url");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let resp = client.get(&url).send().await.expect("authorize GET");
        assert!(resp.status().is_success() || resp.status().is_redirection());
    };

    let (outcome, _) = tokio::join!(broker_fut, browser_fut);
    let outcome = outcome.expect("broker flow");
    assert_eq!(outcome.access_token, "at-new");
    assert_eq!(outcome.refresh_token, "rt-new");
    assert_eq!(outcome.provider, "test");
    assert!(outcome.expires_at > 0);
    assert!(provider_state.last_code_challenge.lock().is_some());
    assert!(provider_state.last_verifier.lock().is_some());
}

#[tokio::test]
async fn unknown_provider_errors() {
    let cfg = OAuthConfig::default();
    let err = run_flow(
        BrokerParams {
            oauth: &cfg,
            provider: "nonexistent",
            extra_scopes: vec![],
        },
        |_| {},
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::UnknownProvider(_)));
}

#[tokio::test]
async fn missing_client_id_errors() {
    let cfg = OAuthConfig::default();
    // The default dropbox profile has an empty client_id.
    let err = run_flow(
        BrokerParams {
            oauth: &cfg,
            provider: "dropbox",
            extra_scopes: vec![],
        },
        |_| {},
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::MissingClientId { .. }));
}

#[tokio::test]
async fn flow_times_out_when_browser_never_returns() {
    // Bring the callback timeout way down so this test finishes
    // quickly even in a loaded CI environment.
    let mut cfg = OAuthConfig {
        callback_timeout_secs: 1,
        ..OAuthConfig::default()
    };
    if let Some(p) = cfg.providers.get_mut("dropbox") {
        p.client_id = "placeholder".into();
        // Point at a bogus authorize + token URL that we'd
        // never reach — the flow times out waiting for the
        // callback that never comes.
        p.authorize_url = "http://127.0.0.1:1/authorize".into();
        p.token_url = "http://127.0.0.1:1/token".into();
    }
    let err = run_flow(
        BrokerParams {
            oauth: &cfg,
            provider: "dropbox",
            extra_scopes: vec![],
        },
        |_| {},
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Timeout { .. }));
}
