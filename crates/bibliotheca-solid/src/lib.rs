//! Solid (Social Linked Data) interface.
//!
//! Solid layers on top of LDP with WebID auth. We treat one subvolume
//! as one Pod, exposed at `/pods/<subvolume_name>/`. The supported
//! verbs are the LDP subset real Solid apps exercise:
//!
//! * `GET` — read a resource, or, when the target is a container,
//!   return a Turtle directory listing with `ldp:contains` triples.
//! * `HEAD` — metadata lookup.
//! * `PUT` — create or replace a resource.
//! * `POST` — create a new resource inside a container. A `Slug`
//!   header, if present, is honoured; otherwise a random UUID is
//!   generated.
//! * `DELETE` — delete a resource.
//! * `OPTIONS` — advertise the supported verbs + WAC `Accept-Patch`.
//!
//! Authentication is HTTP Basic for now — real WebID-OIDC can layer on
//! once town-os exposes an OIDC provider. An unauthenticated request
//! is allowed only when the subvolume ACL has an explicit `Public`
//! entry (matching the HTTP interface's double opt-in).

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use base64::Engine as _;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    data: DataStore,
    svc: BibliothecaService,
    base_url: String,
}

#[derive(Debug, Clone)]
pub struct SolidConfig {
    pub listen: SocketAddr,
    pub base_url: String,
}

pub async fn start(svc: BibliothecaService, cfg: SolidConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        data: DataStore::new(svc.clone()),
        svc,
        base_url: cfg.base_url.clone(),
    });
    let app = Router::new()
        .route("/pods/:pod", any(pod_root))
        .route("/pods/:pod/", any(pod_root))
        .route("/pods/:pod/*path", any(pod_path))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, base_url = %cfg.base_url, "bibliotheca-solid listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn pod_root(
    state: State<Arc<AppState>>,
    method: Method,
    Path(pod): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    dispatch(state, method, pod, String::new(), headers, body).await
}

async fn pod_path(
    state: State<Arc<AppState>>,
    method: Method,
    Path((pod, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    dispatch(state, method, pod, path, headers, body).await
}

async fn dispatch(
    State(state): State<Arc<AppState>>,
    method: Method,
    pod: String,
    mut path: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let is_container = path.is_empty() || path.ends_with('/');
    if is_container && path.ends_with('/') {
        path.pop();
    }

    let user = authenticate(&state, &headers);

    match method {
        Method::OPTIONS => options(),
        Method::GET => get_impl(&state, &pod, &path, is_container, user),
        Method::HEAD => head_impl(&state, &pod, &path, user),
        Method::PUT => put_impl(&state, &pod, &path, is_container, user, body),
        Method::POST => post_impl(&state, &pod, &path, user, &headers, body),
        Method::DELETE => delete_impl(&state, &pod, &path, user),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn options() -> Response {
    let accept_patch = HeaderName::from_static("accept-patch");
    let link = HeaderName::from_static("link");
    (
        StatusCode::NO_CONTENT,
        [
            (header::ALLOW, "OPTIONS, HEAD, GET, PUT, POST, DELETE"),
            (accept_patch, "application/sparql-update"),
            (link, "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\""),
        ],
    )
        .into_response()
}

fn get_impl(
    state: &AppState,
    pod: &str,
    path: &str,
    is_container: bool,
    user: Option<User>,
) -> Response {
    if is_container {
        match state
            .data
            .list(pod, path, user.as_ref().map(|u| u.id), true)
        {
            Ok(entries) => {
                let mut body = String::new();
                body.push_str("@prefix ldp: <http://www.w3.org/ns/ldp#> .\n");
                let self_iri = container_iri(&state.base_url, pod, path);
                body.push_str(&format!("<{self_iri}> a ldp:Container"));
                if entries.is_empty() {
                    body.push_str(" .\n");
                } else {
                    body.push_str(" ;\n    ldp:contains\n");
                    for (i, entry) in entries.iter().enumerate() {
                        let last = i == entries.len() - 1;
                        let child = child_iri(&state.base_url, pod, path, &entry.key);
                        body.push_str(&format!(
                            "        <{child}>{}\n",
                            if last { " ." } else { "," }
                        ));
                    }
                }
                let mut h = HeaderMap::new();
                h.insert(header::CONTENT_TYPE, "text/turtle".parse().unwrap());
                h.insert(
                    HeaderName::from_static("link"),
                    "<http://www.w3.org/ns/ldp#Container>; rel=\"type\""
                        .parse()
                        .unwrap(),
                );
                (StatusCode::OK, h, body).into_response()
            }
            Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
            Err(CoreError::PermissionDenied) => deny(user.is_none()),
            Err(e) => server_error(e),
        }
    } else {
        match state.data.get(pod, path, user.as_ref().map(|u| u.id), true) {
            Ok(bytes) => {
                let mut h = HeaderMap::new();
                h.insert(
                    header::CONTENT_TYPE,
                    "application/octet-stream".parse().unwrap(),
                );
                h.insert(
                    HeaderName::from_static("link"),
                    "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\""
                        .parse()
                        .unwrap(),
                );
                (StatusCode::OK, h, bytes).into_response()
            }
            Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
            Err(CoreError::PermissionDenied) => deny(user.is_none()),
            Err(e) => server_error(e),
        }
    }
}

fn head_impl(state: &AppState, pod: &str, path: &str, user: Option<User>) -> Response {
    match state
        .data
        .head(pod, path, user.as_ref().map(|u| u.id), true)
    {
        Ok(meta) => (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, meta.size.to_string()),
                (
                    header::CONTENT_TYPE,
                    if meta.is_dir {
                        "text/turtle".into()
                    } else {
                        "application/octet-stream".into()
                    },
                ),
            ],
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(e) => server_error(e),
    }
}

fn put_impl(
    state: &AppState,
    pod: &str,
    path: &str,
    is_container: bool,
    user: Option<User>,
    body: Bytes,
) -> Response {
    if is_container {
        match state
            .data
            .mkdir(pod, path, user.as_ref().map(|u| u.id), true)
        {
            Ok(_) => StatusCode::CREATED.into_response(),
            Err(CoreError::AlreadyExists(_)) => StatusCode::NO_CONTENT.into_response(),
            Err(CoreError::PermissionDenied) => deny(user.is_none()),
            Err(e) => server_error(e),
        }
    } else {
        match state
            .data
            .put(pod, path, user.as_ref().map(|u| u.id), true, body.as_ref())
        {
            Ok(_) => StatusCode::CREATED.into_response(),
            Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
            Err(CoreError::PermissionDenied) => deny(user.is_none()),
            Err(CoreError::InvalidArgument(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Err(e) => server_error(e),
        }
    }
}

fn post_impl(
    state: &AppState,
    pod: &str,
    path: &str,
    user: Option<User>,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let slug = headers
        .get("slug")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{:x}", rand_u64()));
    let key = if path.is_empty() {
        slug.clone()
    } else {
        format!("{}/{}", path.trim_end_matches('/'), slug)
    };
    match state
        .data
        .put(pod, &key, user.as_ref().map(|u| u.id), true, body.as_ref())
    {
        Ok(_) => (
            StatusCode::CREATED,
            [(
                header::LOCATION,
                child_iri(&state.base_url, pod, path, &slug),
            )],
        )
            .into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(e) => server_error(e),
    }
}

fn delete_impl(state: &AppState, pod: &str, path: &str, user: Option<User>) -> Response {
    match state
        .data
        .delete(pod, path, user.as_ref().map(|u| u.id), true)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => deny(user.is_none()),
        Err(e) => server_error(e),
    }
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let creds = auth.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(creds.trim())
        .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    state.svc.verify_user_password(user, pass).ok().flatten()
}

fn deny(anonymous: bool) -> Response {
    if anonymous {
        (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"bibliotheca-solid\"",
            )],
        )
            .into_response()
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "solid interface error");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn container_iri(base: &str, pod: &str, path: &str) -> String {
    if path.is_empty() {
        format!("{}/pods/{pod}/", base.trim_end_matches('/'))
    } else {
        format!("{}/pods/{pod}/{path}/", base.trim_end_matches('/'))
    }
}

fn child_iri(base: &str, pod: &str, path: &str, child: &str) -> String {
    if path.is_empty() {
        format!("{}/pods/{pod}/{child}", base.trim_end_matches('/'))
    } else {
        format!(
            "{}/pods/{pod}/{}/{child}",
            base.trim_end_matches('/'),
            path.trim_end_matches('/'),
        )
    }
}

fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
