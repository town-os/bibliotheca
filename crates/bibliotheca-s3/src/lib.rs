//! S3-compatible interface.
//!
//! Buckets correspond 1:1 to subvolumes. The bucket owner is the
//! subvolume owner. PUTs create subvolumes owned by the authenticated
//! user; GET/HEAD/DELETE on a key stream bytes through the
//! `bibliotheca-core::data::DataStore` helper, which enforces path
//! traversal and ACL checks.
//!
//! Authentication accepts either HTTP Basic — convenient for test
//! clients — or the AWS-style `Authorization: AWS4-HMAC-SHA256
//! Credential=<access-key>/...` header. Only the access key is pulled
//! off the sigv4 header; the matching secret must be supplied alongside
//! via `X-Amz-Bibliotheca-Secret`, which is the same shape town-os uses
//! for its other HMAC credentials. The control plane will mint proper
//! per-user access-key/secret pairs once that module lands — until
//! then, the access key is the user name and the secret is the user
//! password, which matches what the CLI already understands.

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use bibliotheca_core::acl::Acl;
use bibliotheca_core::data::DataStore;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use serde::Deserialize;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    data: DataStore,
    svc: BibliothecaService,
    #[allow(dead_code)]
    region: String,
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub listen: SocketAddr,
    pub region: String,
}

pub async fn start(svc: BibliothecaService, cfg: S3Config) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        data: DataStore::new(svc.clone()),
        svc,
        region: cfg.region.clone(),
    });
    let app = Router::new()
        .route("/", get(list_buckets))
        .route(
            "/:bucket",
            get(bucket_get)
                .put(bucket_put)
                .delete(bucket_delete)
                .head(bucket_head),
        )
        .route(
            "/:bucket/*key",
            get(object_get)
                .put(object_put)
                .delete(object_delete)
                .head(object_head),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, region = %cfg.region, "bibliotheca-s3 listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct BucketQuery {
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default, rename = "list-type")]
    _list_type: Option<String>,
}

async fn list_buckets(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let subvolumes = state.data.owned_subvolumes(user.id).unwrap_or_default();
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Owner><ID>"#,
    );
    xml.push_str(&xml_escape(&user.name));
    xml.push_str("</ID><DisplayName>");
    xml.push_str(&xml_escape(&user.display_name));
    xml.push_str("</DisplayName></Owner><Buckets>");
    for sv in subvolumes {
        xml.push_str("<Bucket><Name>");
        xml.push_str(&xml_escape(&sv.name));
        xml.push_str("</Name><CreationDate>");
        xml.push_str(&format_http_date(sv.created_at));
        xml.push_str("</CreationDate></Bucket>");
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    xml_response(StatusCode::OK, xml)
}

async fn bucket_get(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<BucketQuery>,
    headers: HeaderMap,
) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let prefix = q.prefix.unwrap_or_default();
    let entries = match state
        .data
        .list_recursive(&bucket, &prefix, Some(user.id), false)
    {
        Ok(e) => e,
        Err(CoreError::NotFound(_)) => return not_found("NoSuchBucket"),
        Err(CoreError::PermissionDenied) => return access_denied(),
        Err(e) => return server_error(e),
    };
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>"#,
    );
    xml.push_str(&xml_escape(&bucket));
    xml.push_str("</Name><Prefix>");
    xml.push_str(&xml_escape(&prefix));
    xml.push_str("</Prefix><KeyCount>");
    xml.push_str(&entries.len().to_string());
    xml.push_str("</KeyCount><IsTruncated>false</IsTruncated>");
    for e in &entries {
        xml.push_str("<Contents><Key>");
        xml.push_str(&xml_escape(&e.key));
        xml.push_str("</Key><Size>");
        xml.push_str(&e.size.to_string());
        xml.push_str("</Size><LastModified>");
        xml.push_str(&format_http_date(e.modified));
        xml.push_str("</LastModified></Contents>");
    }
    xml.push_str("</ListBucketResult>");
    xml_response(StatusCode::OK, xml)
}

async fn bucket_head(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let _user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.svc.get_subvolume(&bucket) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => server_error(e),
    }
}

async fn bucket_put(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state
        .svc
        .create_subvolume(&bucket, user.id, 0, Some(Acl::owner_only(user.id)))
        .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(CoreError::AlreadyExists(_)) => xml_response(
            StatusCode::CONFLICT,
            r#"<?xml version="1.0"?><Error><Code>BucketAlreadyOwnedByYou</Code></Error>"#.into(),
        ),
        Err(e) => server_error(e),
    }
}

async fn bucket_delete(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let sv = match state.svc.get_subvolume(&bucket) {
        Ok(sv) => sv,
        Err(CoreError::NotFound(_)) => return not_found("NoSuchBucket"),
        Err(e) => return server_error(e),
    };
    if sv.owner != user.id {
        return access_denied();
    }
    match state.svc.delete_subvolume(sv.id, true).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => server_error(e),
    }
}

async fn object_get(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.data.get(&bucket, &key, Some(user.id), false) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_LENGTH, &bytes.len().to_string()),
            ],
            bytes,
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => not_found("NoSuchKey"),
        Err(CoreError::PermissionDenied) => access_denied(),
        Err(e) => server_error(e),
    }
}

async fn object_head(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.data.head(&bucket, &key, Some(user.id), false) {
        Ok(meta) => (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, meta.size.to_string()),
                (header::LAST_MODIFIED, format_http_date(meta.modified)),
            ],
        )
            .into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(CoreError::PermissionDenied) => access_denied(),
        Err(e) => server_error(e),
    }
}

async fn object_put(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state
        .data
        .put(&bucket, &key, Some(user.id), false, body.as_ref())
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(CoreError::NotFound(_)) => not_found("NoSuchBucket"),
        Err(CoreError::PermissionDenied) => access_denied(),
        Err(CoreError::InvalidArgument(msg)) => xml_response(
            StatusCode::BAD_REQUEST,
            format!(
                r#"<?xml version="1.0"?><Error><Code>InvalidRequest</Code><Message>{}</Message></Error>"#,
                xml_escape(&msg)
            ),
        ),
        Err(e) => server_error(e),
    }
}

async fn object_delete(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let user = match require_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.data.delete(&bucket, &key, Some(user.id), false) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(CoreError::NotFound(_)) => StatusCode::NO_CONTENT.into_response(),
        Err(CoreError::PermissionDenied) => access_denied(),
        Err(e) => server_error(e),
    }
}

fn require_auth(state: &AppState, headers: &HeaderMap) -> std::result::Result<User, Response> {
    if let Some(user) = basic_auth(state, headers) {
        return Ok(user);
    }
    if let Some(user) = sigv4_auth(state, headers) {
        return Ok(user);
    }
    Err(unauthorized())
}

fn basic_auth(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let creds = auth.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(creds.trim())
        .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    state.svc.verify_user_password(user, pass).ok().flatten()
}

fn sigv4_auth(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = auth.strip_prefix("AWS4-HMAC-SHA256 ")?;
    // Pull the access key out of the `Credential=<key>/...,` segment.
    let cred_part = rest.split(',').find_map(|p| {
        let p = p.trim();
        p.strip_prefix("Credential=")
    })?;
    let access_key = cred_part.split('/').next()?;
    let secret = headers
        .get("x-amz-bibliotheca-secret")
        .and_then(|v| v.to_str().ok())?;
    state
        .svc
        .verify_user_password(access_key, secret)
        .ok()
        .flatten()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"bibliotheca-s3\"")],
        xml_body(r#"<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>"#),
    )
        .into_response()
}

fn access_denied() -> Response {
    xml_response(
        StatusCode::FORBIDDEN,
        r#"<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>"#.into(),
    )
}

fn not_found(code: &str) -> Response {
    xml_response(
        StatusCode::NOT_FOUND,
        format!(r#"<?xml version="1.0"?><Error><Code>{code}</Code></Error>"#),
    )
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "s3 interface error");
    xml_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"<?xml version="1.0"?><Error><Code>InternalError</Code></Error>"#.into(),
    )
}

fn xml_response(code: StatusCode, body: String) -> Response {
    (code, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

fn xml_body(s: &str) -> String {
    s.to_string()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn format_http_date(ts: time::OffsetDateTime) -> String {
    // RFC 1123-ish fixed-width. `time` can't format without a
    // well-known feature turned on in the workspace; ISO 8601 is good
    // enough for the cloud clients that currently point at us.
    ts.format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}
