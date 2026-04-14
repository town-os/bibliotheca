//! Integration tests for the anisette proxy.
//!
//! We stand up one or more axum "upstream" mocks that serve the
//! same JSON shape as a real operator-controlled anisette server,
//! wire them through `ProxyProvider`, and exercise the proxy's
//! HTTP surface with a `reqwest` client against an ephemeral
//! bound port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use bibliotheca_anisette::{
    serve, AnisetteHeaders, AnisetteProvider, AnisetteServerConfig, MockProvider, ProxyConfig,
    ProxyProvider,
};
use parking_lot::Mutex;
use serde_json::json;
use url::Url;

#[derive(Default)]
struct UpstreamState {
    calls: Mutex<u32>,
    force_error: Mutex<bool>,
}

async fn upstream_get(State(state): State<Arc<UpstreamState>>) -> axum::response::Response {
    let calls = {
        let mut g = state.calls.lock();
        *g += 1;
        *g
    };
    if *state.force_error.lock() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "upstream down").into_response();
    }
    Json(json!({
        "X-Apple-I-MD":          format!("md-{calls}"),
        "X-Apple-I-MD-M":        "md-m",
        "X-Apple-I-MD-RINFO":    "17106176",
        "X-Apple-I-MD-LU":       "md-lu",
        "X-Mme-Device-Id":       "device-id",
        "X-Apple-I-Client-Time": "2026-04-14T12:00:00Z",
        "X-Apple-Locale":        "en_US",
        "X-Apple-I-TimeZone":    "UTC"
    }))
    .into_response()
}

async fn spawn_upstream() -> (SocketAddr, Arc<UpstreamState>) {
    let state = Arc::new(UpstreamState::default());
    let app = Router::new()
        .route("/v3/get_anisette_data", post(upstream_get))
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

async fn spawn_proxy(provider: Arc<dyn AnisetteProvider>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let cfg = AnisetteServerConfig { listen: addr };
    tokio::spawn(async move {
        let _ = serve(provider, cfg).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    addr
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn proxy_forwards_to_single_upstream() {
    let (upstream_addr, upstream) = spawn_upstream().await;
    let proxy: Arc<dyn AnisetteProvider> = Arc::new(
        ProxyProvider::new(ProxyConfig {
            upstreams: vec![Url::parse(&format!("http://{upstream_addr}")).unwrap()],
            cache_ttl_secs: 0,
            request_timeout_secs: 5,
            backoff_secs: 1,
        })
        .unwrap(),
    );
    let proxy_addr = spawn_proxy(proxy).await;

    let resp = client()
        .post(format!("http://{proxy_addr}/v3/get_anisette_data"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let headers: AnisetteHeaders = resp.json().await.unwrap();
    assert_eq!(headers.md, "md-1");
    assert_eq!(*upstream.calls.lock(), 1);
}

#[tokio::test]
async fn proxy_fails_over_across_upstreams() {
    let (down_addr, down) = spawn_upstream().await;
    *down.force_error.lock() = true;
    let (healthy_addr, healthy) = spawn_upstream().await;

    let proxy: Arc<dyn AnisetteProvider> = Arc::new(
        ProxyProvider::new(ProxyConfig {
            upstreams: vec![
                Url::parse(&format!("http://{down_addr}")).unwrap(),
                Url::parse(&format!("http://{healthy_addr}")).unwrap(),
            ],
            cache_ttl_secs: 0,
            request_timeout_secs: 5,
            backoff_secs: 1,
        })
        .unwrap(),
    );
    let proxy_addr = spawn_proxy(proxy).await;

    let resp = client()
        .post(format!("http://{proxy_addr}/v3/get_anisette_data"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // The healthy upstream saw the request once; the down one got
    // hit and marked unhealthy.
    assert_eq!(*healthy.calls.lock(), 1);
    assert!(*down.calls.lock() >= 1);
}

#[tokio::test]
async fn proxy_caches_response_within_ttl() {
    let (upstream_addr, upstream) = spawn_upstream().await;
    let proxy: Arc<dyn AnisetteProvider> = Arc::new(
        ProxyProvider::new(ProxyConfig {
            upstreams: vec![Url::parse(&format!("http://{upstream_addr}")).unwrap()],
            cache_ttl_secs: 60,
            request_timeout_secs: 5,
            backoff_secs: 1,
        })
        .unwrap(),
    );
    let proxy_addr = spawn_proxy(proxy).await;

    for _ in 0..3 {
        let resp = client()
            .post(format!("http://{proxy_addr}/v3/get_anisette_data"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    // Three proxy hits, one upstream hit — cache is holding.
    assert_eq!(*upstream.calls.lock(), 1);
}

#[tokio::test]
async fn proxy_status_exposes_upstream_health() {
    let (upstream_addr, _) = spawn_upstream().await;
    let proxy: Arc<dyn AnisetteProvider> = Arc::new(
        ProxyProvider::new(ProxyConfig {
            upstreams: vec![Url::parse(&format!("http://{upstream_addr}")).unwrap()],
            cache_ttl_secs: 0,
            request_timeout_secs: 5,
            backoff_secs: 1,
        })
        .unwrap(),
    );
    let proxy_addr = spawn_proxy(proxy).await;

    // Prime the counter.
    client()
        .post(format!("http://{proxy_addr}/v3/get_anisette_data"))
        .send()
        .await
        .unwrap();

    let resp = client()
        .get(format!("http://{proxy_addr}/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "proxy");
    let upstreams = body["upstreams"].as_array().unwrap();
    assert_eq!(upstreams.len(), 1);
    assert!(upstreams[0]["ok_count"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn health_endpoint_is_unauthenticated() {
    let mock: Arc<dyn AnisetteProvider> = Arc::new(MockProvider::new());
    let addr = spawn_proxy(mock).await;
    let resp = client()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn mock_provider_is_usable_standalone() {
    let mock = Arc::new(MockProvider::new());
    let dyn_mock: Arc<dyn AnisetteProvider> = mock.clone();
    let addr = spawn_proxy(dyn_mock).await;
    let resp = client()
        .post(format!("http://{addr}/v3/get_anisette_data"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let headers: AnisetteHeaders = resp.json().await.unwrap();
    assert_eq!(headers.md, "mock-md-1");
    assert_eq!(mock.calls(), 1);
}

#[tokio::test]
async fn upstream_all_down_returns_bad_gateway() {
    let (down_addr, down) = spawn_upstream().await;
    *down.force_error.lock() = true;
    let proxy: Arc<dyn AnisetteProvider> = Arc::new(
        ProxyProvider::new(ProxyConfig {
            upstreams: vec![Url::parse(&format!("http://{down_addr}")).unwrap()],
            cache_ttl_secs: 0,
            request_timeout_secs: 5,
            backoff_secs: 60,
        })
        .unwrap(),
    );
    let proxy_addr = spawn_proxy(proxy).await;
    let resp = client()
        .post(format!("http://{proxy_addr}/v3/get_anisette_data"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
}

#[tokio::test]
async fn empty_upstream_list_rejected_at_construction() {
    let err = ProxyProvider::new(ProxyConfig::default()).err().unwrap();
    assert!(matches!(err, bibliotheca_anisette::Error::NoUpstreams));
}

#[tokio::test]
async fn dynamic_add_upstream_enables_fetches() {
    let (upstream_addr, upstream) = spawn_upstream().await;
    let (bootstrap_addr, _) = spawn_upstream().await;
    let proxy = ProxyProvider::new(ProxyConfig {
        upstreams: vec![Url::parse(&format!("http://{bootstrap_addr}")).unwrap()],
        cache_ttl_secs: 0,
        request_timeout_secs: 5,
        backoff_secs: 1,
    })
    .unwrap();
    // Remove the bootstrap upstream and add the real one at runtime.
    proxy
        .remove_upstream(&format!("http://{bootstrap_addr}/"))
        .unwrap();
    proxy
        .add_upstream(&format!("http://{upstream_addr}/"))
        .unwrap();
    assert_eq!(proxy.upstreams().len(), 1);

    let headers = proxy.get().await.unwrap();
    assert_eq!(headers.md, "md-1");
    assert_eq!(*upstream.calls.lock(), 1);
}

#[tokio::test]
async fn add_upstream_is_idempotent_on_duplicate() {
    let (addr, _) = spawn_upstream().await;
    let url = format!("http://{addr}/");
    let proxy = ProxyProvider::new(ProxyConfig {
        upstreams: vec![Url::parse(&url).unwrap()],
        cache_ttl_secs: 0,
        request_timeout_secs: 5,
        backoff_secs: 1,
    })
    .unwrap();
    let err = proxy.add_upstream(&url).unwrap_err();
    assert!(matches!(err, bibliotheca_anisette::Error::AlreadyExists(_)));
    assert_eq!(proxy.upstreams().len(), 1);
}

#[tokio::test]
async fn remove_upstream_missing_returns_not_found() {
    let (addr, _) = spawn_upstream().await;
    let proxy = ProxyProvider::new(ProxyConfig {
        upstreams: vec![Url::parse(&format!("http://{addr}")).unwrap()],
        cache_ttl_secs: 0,
        request_timeout_secs: 5,
        backoff_secs: 1,
    })
    .unwrap();
    let err = proxy.remove_upstream("http://127.0.0.1:1/").unwrap_err();
    assert!(matches!(err, bibliotheca_anisette::Error::NotFound(_)));
}

#[tokio::test]
async fn invalid_upstream_url_rejected() {
    let (addr, _) = spawn_upstream().await;
    let proxy = ProxyProvider::new(ProxyConfig {
        upstreams: vec![Url::parse(&format!("http://{addr}")).unwrap()],
        cache_ttl_secs: 0,
        request_timeout_secs: 5,
        backoff_secs: 1,
    })
    .unwrap();
    let err = proxy.add_upstream("not a url").unwrap_err();
    assert!(matches!(err, bibliotheca_anisette::Error::InvalidUrl(_)));
}

#[tokio::test]
async fn mock_provider_reports_not_supported_for_dynamic_peers() {
    let mock = MockProvider::new();
    let err = mock.add_upstream("http://example.com/").unwrap_err();
    assert!(matches!(err, bibliotheca_anisette::Error::NotSupported(_)));
    let err = mock.remove_upstream("http://example.com/").unwrap_err();
    assert!(matches!(err, bibliotheca_anisette::Error::NotSupported(_)));
    assert!(mock.upstreams().is_empty());
}
