//! Nextcloud-compatible WebDAV + OCS interface.
//!
//! Exposes `/remote.php/dav/files/<user>/...` and the OCS share API so
//! that the official Nextcloud desktop and mobile clients can sync
//! against a bibliotheca user's home subvolume. The first path segment
//! after the user root is the target subvolume name; the rest becomes
//! an object key. For example:
//!
//!   PUT /remote.php/dav/files/alice/photos/IMG_0001.jpg
//!     -> subvolume "photos", key "IMG_0001.jpg"
//!
//! Authentication is HTTP Basic (the Nextcloud desktop client uses
//! app-password basic tokens). The OCS share API is stubbed to the
//! minimum response Nextcloud clients tolerate while still exercising
//! its routing.

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
use bibliotheca_core::data::{DataStore, ObjectMeta};
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    data: DataStore,
    svc: BibliothecaService,
}

#[derive(Debug, Clone)]
pub struct NextcloudConfig {
    pub listen: SocketAddr,
}

pub async fn start(svc: BibliothecaService, cfg: NextcloudConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        data: DataStore::new(svc.clone()),
        svc,
    });
    let app = Router::new()
        .route("/remote.php/dav/files/:user", any(dav_root))
        .route("/remote.php/dav/files/:user/", any(dav_root))
        .route("/remote.php/dav/files/:user/*path", any(dav_path))
        .route(
            "/ocs/v2.php/apps/files_sharing/api/v1/shares",
            any(shares_op),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-nextcloud listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn dav_root(
    state: State<Arc<AppState>>,
    method: Method,
    Path(user): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    dispatch(state, method, user, String::new(), headers, body).await
}

async fn dav_path(
    state: State<Arc<AppState>>,
    method: Method,
    Path((user, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    dispatch(state, method, user, path, headers, body).await
}

async fn dispatch(
    State(state): State<Arc<AppState>>,
    method: Method,
    path_user: String,
    full_path: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authed = match authenticate(&state, &headers) {
        Some(u) => u,
        None => return unauthorized(),
    };
    if authed.name != path_user {
        return forbidden();
    }
    let (sv_name, rel) = match split_path(&full_path) {
        Ok(v) => v,
        Err(r) => return r,
    };

    match method.as_str() {
        "GET" => dav_get(&state, &sv_name, &rel, &authed),
        "HEAD" => dav_head(&state, &sv_name, &rel, &authed),
        "PUT" => dav_put(&state, &sv_name, &rel, &authed, body),
        "DELETE" => dav_delete(&state, &sv_name, &rel, &authed),
        "MKCOL" => dav_mkcol(&state, &sv_name, &rel, &authed),
        "PROPFIND" => dav_propfind(&state, &path_user, &sv_name, &rel, &authed, &headers),
        "OPTIONS" => options(),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn dav_get(state: &AppState, sv: &str, rel: &str, user: &User) -> Response {
    if rel.is_empty() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    match state.data.get(sv, rel, Some(user.id), false) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

fn dav_head(state: &AppState, sv: &str, rel: &str, user: &User) -> Response {
    match state.data.head(sv, rel, Some(user.id), false) {
        Ok(meta) => (
            StatusCode::OK,
            [(header::CONTENT_LENGTH, meta.size.to_string())],
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

fn dav_put(state: &AppState, sv: &str, rel: &str, user: &User, body: Bytes) -> Response {
    match state.data.put(sv, rel, Some(user.id), false, body.as_ref()) {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::CONFLICT.into_response(),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(CoreError::InvalidArgument(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(e) => server_error(e),
    }
}

fn dav_delete(state: &AppState, sv: &str, rel: &str, user: &User) -> Response {
    match state.data.delete(sv, rel, Some(user.id), false) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

fn dav_mkcol(state: &AppState, sv: &str, rel: &str, user: &User) -> Response {
    if rel.is_empty() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    match state.data.mkdir(sv, rel, Some(user.id), false) {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(CoreError::AlreadyExists(_)) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        Err(CoreError::PermissionDenied) => forbidden(),
        Err(e) => server_error(e),
    }
}

fn dav_propfind(
    state: &AppState,
    path_user: &str,
    sv: &str,
    rel: &str,
    user: &User,
    headers: &HeaderMap,
) -> Response {
    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("1");
    let mut entries = Vec::new();
    // The target itself.
    match state.data.head(sv, rel, Some(user.id), false) {
        Ok(meta) => entries.push((rel.to_string(), meta)),
        Err(CoreError::NotFound(_)) => return StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => return forbidden(),
        Err(e) => return server_error(e),
    }
    if depth != "0" {
        if let Ok(children) = state.data.list(sv, rel, Some(user.id), false) {
            for child in children {
                entries.push((child.key.clone(), child));
            }
        }
    }

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">"#,
    );
    for (key, meta) in entries {
        let href = if key.is_empty() {
            format!("/remote.php/dav/files/{path_user}/{sv}/")
        } else {
            format!("/remote.php/dav/files/{path_user}/{sv}/{key}")
        };
        let href = if meta.is_dir && !href.ends_with('/') {
            format!("{href}/")
        } else {
            href
        };
        let resourcetype = if meta.is_dir {
            "<d:collection/>".to_string()
        } else {
            String::new()
        };
        xml.push_str(&format!(
            "<d:response><d:href>{}</d:href><d:propstat><d:prop>\
            <d:resourcetype>{}</d:resourcetype>\
            <d:getcontentlength>{}</d:getcontentlength>\
            <d:getlastmodified>{}</d:getlastmodified>\
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
            xml_escape(&href),
            resourcetype,
            meta.size,
            xml_escape(&meta.modified.unix_timestamp().to_string()),
        ));
    }
    xml.push_str("</d:multistatus>");
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        "application/xml; charset=utf-8".parse().unwrap(),
    );
    (StatusCode::from_u16(207).unwrap(), h, xml).into_response()
}

fn options() -> Response {
    let dav = HeaderName::from_static("dav");
    (
        StatusCode::OK,
        [
            (
                header::ALLOW,
                "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL",
            ),
            (dav, "1, 2"),
        ],
    )
        .into_response()
}

async fn shares_op() -> Response {
    let body = r#"<?xml version="1.0"?>
<ocs>
 <meta>
  <status>ok</status>
  <statuscode>200</statuscode>
  <message>OK</message>
 </meta>
 <data/>
</ocs>"#;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        body,
    )
        .into_response()
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

fn split_path(full: &str) -> Result<(String, String), Response> {
    if full.is_empty() {
        return Err(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    let (sv, rest) = full.split_once('/').unwrap_or((full, ""));
    Ok((sv.to_string(), rest.trim_end_matches('/').to_string()))
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"Nextcloud\"")],
    )
        .into_response()
}

fn forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "nextcloud interface error");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[allow(dead_code)]
fn _force_used(_: ObjectMeta) {}
