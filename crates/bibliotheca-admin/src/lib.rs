//! HTML admin panel.
//!
//! Serves a minimal HTML admin UI for indexed browsing of subvolume
//! contents plus read-only views of users, groups, and subvolumes.
//! Admin access **bypasses** subvolume ACLs by design — the operator
//! needs to inspect state they don't necessarily own — so the crate is
//! gated by membership in a configurable admin group.
//!
//! ## Bootstrap
//!
//! Before the admin panel is usable the operator must provision at
//! least one admin out of band:
//!
//! ```text
//! bibliothecactl user  create alice --password hunter2
//! bibliothecactl group create admins
//! bibliothecactl group add   admins <alice-id>
//! ```
//!
//! If the admin group doesn't exist the `require_admin` layer rejects
//! every authenticated request with 403 — locked out by default is the
//! correct failure mode.
//!
//! ## Wire path
//!
//! File reads for the directory browser and download endpoint use
//! [`bibliotheca_core::data::resolve_key`] for traversal safety and
//! then talk to the filesystem directly via `std::fs`. The
//! [`bibliotheca_core::data::DataStore`] helper is intentionally not
//! used here: its entire surface takes `Option<UserId>` and enforces
//! the subvolume ACL, which is the exact behaviour the admin panel
//! needs to override. Keeping the bypass local to this crate prevents
//! every other transport from being able to reach it.

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use bibliotheca_core::acl::{Permission, Principal};
use bibliotheca_core::data::resolve_key;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::{GroupId, User, UserId};
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::subvolume::Subvolume;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    svc: BibliothecaService,
    admin_group: String,
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub listen: SocketAddr,
    pub admin_group: String,
}

pub async fn start(svc: BibliothecaService, cfg: AdminConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        svc,
        admin_group: cfg.admin_group.clone(),
    });

    let admin = Router::new()
        .route("/admin", get(dashboard))
        .route("/admin/subvolumes", get(subvolumes_index))
        .route("/admin/subvolumes/:name", get(subvolume_detail))
        .route("/admin/subvolumes/:name/tree", get(subvolume_tree_root))
        .route("/admin/subvolumes/:name/tree/*path", get(subvolume_tree))
        .route(
            "/admin/subvolumes/:name/download/*key",
            get(subvolume_download),
        )
        .route("/admin/users", get(users_index))
        .route("/admin/users/:name", get(user_detail))
        .route("/admin/groups", get(groups_index))
        .route("/admin/groups/:name", get(group_detail))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(admin)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, admin_group = %cfg.admin_group, "bibliotheca-admin listening");
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- auth middleware ----------

async fn require_admin(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(user) = basic_auth(&state, req.headers()) else {
        return unauthorized();
    };
    let group = match state.svc.get_group(&state.admin_group) {
        Ok(g) => g,
        Err(CoreError::NotFound(_)) => return forbidden("admin group not configured"),
        Err(e) => return server_error(e),
    };
    let groups = match state.svc.store().groups_for_user(user.id) {
        Ok(g) => g,
        Err(e) => return server_error(e),
    };
    if !groups.contains(&group.id) {
        return forbidden("not a member of the admin group");
    }
    req.extensions_mut().insert(user);
    next.run(req).await
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

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"bibliotheca-admin\"",
        )],
        Html(error_page("unauthorized", "authentication required")),
    )
        .into_response()
}

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, Html(error_page("forbidden", msg))).into_response()
}

fn server_error(e: CoreError) -> Response {
    warn!(error = %e, "admin interface error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(error_page("server error", &e.to_string())),
    )
        .into_response()
}

fn not_found(what: &str) -> Response {
    (StatusCode::NOT_FOUND, Html(error_page("not found", what))).into_response()
}

fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(error_page("bad request", msg)),
    )
        .into_response()
}

fn map_core(e: CoreError) -> Response {
    match e {
        CoreError::NotFound(what) => not_found(&what),
        CoreError::InvalidArgument(msg) => bad_request(&msg),
        CoreError::PermissionDenied => forbidden("permission denied"),
        other => server_error(other),
    }
}

// ---------- handlers ----------

async fn dashboard(State(state): State<Arc<AppState>>) -> Response {
    let users = match state.svc.list_users(0, 0) {
        Ok(u) => u,
        Err(e) => return map_core(e),
    };
    let groups = match state.svc.list_groups(0, 0) {
        Ok(g) => g,
        Err(e) => return map_core(e),
    };
    let subs = match state.svc.list_subvolumes(None, 0, 0) {
        Ok(s) => s,
        Err(e) => return map_core(e),
    };
    let body = format!(
        "<table><tr><th>entity</th><th>count</th></tr>\
         <tr><td><a href=\"/admin/users\">users</a></td><td>{}</td></tr>\
         <tr><td><a href=\"/admin/groups\">groups</a></td><td>{}</td></tr>\
         <tr><td><a href=\"/admin/subvolumes\">subvolumes</a></td><td>{}</td></tr>\
         </table>",
        users.len(),
        groups.len(),
        subs.len(),
    );
    page("dashboard", body)
}

async fn subvolumes_index(State(state): State<Arc<AppState>>) -> Response {
    let subs = match state.svc.list_subvolumes(None, 0, 0) {
        Ok(s) => s,
        Err(e) => return map_core(e),
    };
    let mut rows = String::new();
    for sv in &subs {
        let owner_name = state
            .svc
            .store()
            .get_user_by_id(sv.owner)
            .map(|u| u.name)
            .unwrap_or_else(|_| sv.owner.to_string());
        rows.push_str(&format!(
            "<tr><td><a href=\"/admin/subvolumes/{name}\">{name_esc}</a></td>\
             <td>{owner}</td><td>{quota}</td><td>{acl_count}</td>\
             <td><a href=\"/admin/subvolumes/{name}/tree\">browse</a></td></tr>",
            name = esc(&sv.name),
            name_esc = esc(&sv.name),
            owner = esc(&owner_name),
            quota = sv.quota_bytes,
            acl_count = sv.acl.entries.len(),
        ));
    }
    let body = format!(
        "<table><tr><th>name</th><th>owner</th><th>quota</th><th>acl entries</th><th></th></tr>{rows}</table>",
    );
    page("subvolumes", body)
}

async fn subvolume_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    let sv = match state.svc.get_subvolume(&name) {
        Ok(s) => s,
        Err(e) => return map_core(e),
    };
    let mut acl_rows = String::new();
    for entry in &sv.acl.entries {
        let principal_label = principal_label(&state, &entry.principal);
        let mut perms: Vec<&'static str> = entry
            .permissions
            .iter()
            .map(|p| permission_label(*p))
            .collect();
        perms.sort();
        acl_rows.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td></tr>",
            esc(&principal_label),
            esc(&perms.join(", ")),
        ));
    }
    let owner_name = state
        .svc
        .store()
        .get_user_by_id(sv.owner)
        .map(|u| u.name)
        .unwrap_or_else(|_| sv.owner.to_string());
    let body = format!(
        "<table>\
         <tr><th>id</th><td><code>{id}</code></td></tr>\
         <tr><th>name</th><td>{name}</td></tr>\
         <tr><th>owner</th><td>{owner}</td></tr>\
         <tr><th>quota</th><td>{quota} bytes</td></tr>\
         <tr><th>mount path</th><td><code>{mount}</code></td></tr>\
         </table>\
         <p><a href=\"/admin/subvolumes/{browse_name}/tree\">browse contents →</a></p>\
         <h2>acl</h2>\
         <table><tr><th>principal</th><th>permissions</th></tr>{acl_rows}</table>",
        id = esc(&sv.id.to_string()),
        name = esc(&sv.name),
        owner = esc(&owner_name),
        quota = sv.quota_bytes,
        mount = esc(&sv.mount_path.display().to_string()),
        browse_name = esc(&sv.name),
    );
    page(&format!("subvolume: {}", sv.name), body)
}

async fn subvolume_tree_root(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    render_tree(&state, &name, "").await
}

async fn subvolume_tree(
    State(state): State<Arc<AppState>>,
    Path((name, path)): Path<(String, String)>,
) -> Response {
    render_tree(&state, &name, &path).await
}

async fn render_tree(state: &AppState, name: &str, path: &str) -> Response {
    let sv = match state.svc.get_subvolume(name) {
        Ok(s) => s,
        Err(e) => return map_core(e),
    };
    let trimmed = path.trim_matches('/');
    let abs = match resolve_key(&sv.mount_path, trimmed) {
        Ok(p) => p,
        Err(e) => return map_core(e),
    };
    if !abs.exists() {
        return not_found(&format!("{}/{}", sv.name, trimmed));
    }
    if abs.is_file() {
        let body = format!(
            "<p><a href=\"/admin/subvolumes/{n}/download/{p}\">download {p}</a></p>",
            n = esc(&sv.name),
            p = esc(trimmed),
        );
        return page(&format!("{}:{}", sv.name, trimmed), body);
    }

    let entries = match list_dir(&abs) {
        Ok(e) => e,
        Err(e) => {
            return server_error(CoreError::Backend(format!("read_dir: {e}")));
        }
    };

    let breadcrumb = breadcrumb_html(&sv, trimmed);
    let mut rows = String::new();
    for entry in &entries {
        let child_key = if trimmed.is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", trimmed, entry.name)
        };
        let link = if entry.is_dir {
            format!(
                "<a href=\"/admin/subvolumes/{n}/tree/{k}\">{label}/</a>",
                n = esc(&sv.name),
                k = esc(&child_key),
                label = esc(&entry.name),
            )
        } else {
            format!(
                "<a href=\"/admin/subvolumes/{n}/download/{k}\">{label}</a>",
                n = esc(&sv.name),
                k = esc(&child_key),
                label = esc(&entry.name),
            )
        };
        let kind = if entry.is_dir { "dir" } else { "file" };
        rows.push_str(&format!(
            "<tr><td>{link}</td><td>{kind}</td><td>{size}</td></tr>",
            size = entry.size,
        ));
    }
    let body = format!(
        "<p class=\"breadcrumb\">{breadcrumb}</p>\
         <table><tr><th>name</th><th>kind</th><th>size</th></tr>{rows}</table>",
    );
    page(
        &format!(
            "{}/{}",
            sv.name,
            if trimmed.is_empty() { "" } else { trimmed }
        ),
        body,
    )
}

async fn subvolume_download(
    State(state): State<Arc<AppState>>,
    Path((name, key)): Path<(String, String)>,
) -> Response {
    let sv = match state.svc.get_subvolume(&name) {
        Ok(s) => s,
        Err(e) => return map_core(e),
    };
    let abs = match resolve_key(&sv.mount_path, &key) {
        Ok(p) => p,
        Err(e) => return map_core(e),
    };
    if !abs.exists() {
        return not_found(&format!("{}/{}", sv.name, key));
    }
    if abs.is_dir() {
        return bad_request("cannot download a directory");
    }
    let bytes = match std::fs::read(&abs) {
        Ok(b) => b,
        Err(e) => return server_error(CoreError::Backend(format!("read: {e}"))),
    };
    let filename = abs
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download")
        .to_string();
    let disposition = format!("attachment; filename=\"{}\"", esc(&filename));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    headers.insert(
        HeaderName::from_static("content-disposition"),
        disposition.parse().unwrap(),
    );
    (StatusCode::OK, headers, Bytes::from(bytes)).into_response()
}

async fn users_index(State(state): State<Arc<AppState>>) -> Response {
    let users = match state.svc.list_users(0, 0) {
        Ok(u) => u,
        Err(e) => return map_core(e),
    };
    let mut rows = String::new();
    for u in &users {
        rows.push_str(&format!(
            "<tr><td><a href=\"/admin/users/{n}\">{ne}</a></td>\
             <td>{d}</td><td>{dis}</td></tr>",
            n = esc(&u.name),
            ne = esc(&u.name),
            d = esc(&u.display_name),
            dis = if u.disabled { "yes" } else { "no" },
        ));
    }
    let body =
        format!("<table><tr><th>name</th><th>display</th><th>disabled</th></tr>{rows}</table>");
    page("users", body)
}

async fn user_detail(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let user = match state.svc.get_user(&name) {
        Ok(u) => u,
        Err(e) => return map_core(e),
    };
    let groups: Vec<String> = state
        .svc
        .store()
        .group_ids_for_user(user.id)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|gid| state.svc.store().get_group_by_id(gid).ok().map(|g| g.name))
        .collect();
    let group_links: String = groups
        .iter()
        .map(|g| {
            format!(
                "<a href=\"/admin/groups/{n}\">{ne}</a>",
                n = esc(g),
                ne = esc(g)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let body = format!(
        "<table>\
         <tr><th>id</th><td><code>{id}</code></td></tr>\
         <tr><th>name</th><td>{name}</td></tr>\
         <tr><th>display</th><td>{display}</td></tr>\
         <tr><th>disabled</th><td>{dis}</td></tr>\
         <tr><th>groups</th><td>{gl}</td></tr>\
         </table>",
        id = esc(&user.id.to_string()),
        name = esc(&user.name),
        display = esc(&user.display_name),
        dis = if user.disabled { "yes" } else { "no" },
        gl = if group_links.is_empty() {
            "<em>none</em>".into()
        } else {
            group_links
        },
    );
    page(&format!("user: {}", user.name), body)
}

async fn groups_index(State(state): State<Arc<AppState>>) -> Response {
    let groups = match state.svc.list_groups(0, 0) {
        Ok(g) => g,
        Err(e) => return map_core(e),
    };
    let mut rows = String::new();
    for g in &groups {
        let members = state
            .svc
            .list_group_members(g.id)
            .map(|v| v.len())
            .unwrap_or(0);
        rows.push_str(&format!(
            "<tr><td><a href=\"/admin/groups/{n}\">{ne}</a></td>\
             <td>{desc}</td><td>{m}</td></tr>",
            n = esc(&g.name),
            ne = esc(&g.name),
            desc = esc(&g.description),
            m = members,
        ));
    }
    let body =
        format!("<table><tr><th>name</th><th>description</th><th>members</th></tr>{rows}</table>");
    page("groups", body)
}

async fn group_detail(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let group = match state.svc.get_group(&name) {
        Ok(g) => g,
        Err(e) => return map_core(e),
    };
    let members = match state.svc.list_group_members(group.id) {
        Ok(m) => m,
        Err(e) => return map_core(e),
    };
    let mut rows = String::new();
    for m in &members {
        rows.push_str(&format!(
            "<tr><td><a href=\"/admin/users/{n}\">{ne}</a></td><td>{d}</td></tr>",
            n = esc(&m.name),
            ne = esc(&m.name),
            d = esc(&m.display_name),
        ));
    }
    let body = format!(
        "<table>\
         <tr><th>id</th><td><code>{id}</code></td></tr>\
         <tr><th>name</th><td>{name}</td></tr>\
         <tr><th>description</th><td>{desc}</td></tr>\
         </table>\
         <h2>members</h2>\
         <table><tr><th>name</th><th>display</th></tr>{rows}</table>",
        id = esc(&group.id.to_string()),
        name = esc(&group.name),
        desc = esc(&group.description),
    );
    page(&format!("group: {}", group.name), body)
}

// ---------- rendering helpers ----------

fn page(title: &str, body: String) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>{t} — bibliotheca admin</title>\
         <style>\
         body{{font:14px/1.4 -apple-system,sans-serif;margin:2rem;max-width:960px;color:#111}}\
         h1{{margin-top:0}} nav{{margin-bottom:1rem;padding-bottom:0.5rem;border-bottom:2px solid #333}}\
         nav a{{margin-right:1rem}} table{{border-collapse:collapse;width:100%}}\
         th,td{{padding:4px 8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}\
         a{{color:#06c;text-decoration:none}} a:hover{{text-decoration:underline}}\
         code{{background:#f4f4f4;padding:0 4px;border-radius:3px}}\
         .breadcrumb{{color:#666}}\
         </style></head><body>\
         <nav><strong>bibliotheca admin</strong>\
         <a href=\"/admin\">dashboard</a>\
         <a href=\"/admin/subvolumes\">subvolumes</a>\
         <a href=\"/admin/users\">users</a>\
         <a href=\"/admin/groups\">groups</a></nav>\
         <h1>{t}</h1>{body}</body></html>",
        t = esc(title),
    );
    Html(html).into_response()
}

fn error_page(title: &str, msg: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>{t} — bibliotheca admin</title></head>\
         <body style=\"font:14px sans-serif;margin:2rem\">\
         <h1>{t}</h1><p>{m}</p></body></html>",
        t = esc(title),
        m = esc(msg),
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn permission_label(p: Permission) -> &'static str {
    match p {
        Permission::Read => "read",
        Permission::Write => "write",
        Permission::List => "list",
        Permission::Delete => "delete",
        Permission::Admin => "admin",
    }
}

fn principal_label(state: &AppState, principal: &Principal) -> String {
    match principal {
        Principal::User(uid) => state
            .svc
            .store()
            .get_user_by_id(*uid)
            .map(|u| format!("user: {}", u.name))
            .unwrap_or_else(|_| format!("user: {uid}")),
        Principal::Group(gid) => lookup_group_name(state, *gid)
            .map(|n| format!("group: {n}"))
            .unwrap_or_else(|| format!("group: {gid}")),
        Principal::Public => "public".into(),
    }
}

fn lookup_group_name(state: &AppState, id: GroupId) -> Option<String> {
    state.svc.store().get_group_by_id(id).ok().map(|g| g.name)
}

// ---------- filesystem walk ----------

struct DirEntry {
    name: String,
    is_dir: bool,
    size: u64,
}

fn list_dir(abs: &FsPath) -> std::io::Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(abs)? {
        let entry = entry?;
        let md = entry.metadata()?;
        out.push(DirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir: md.is_dir(),
            size: md.len(),
        });
    }
    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

fn breadcrumb_html(sv: &Subvolume, path: &str) -> String {
    let mut out = format!(
        "<a href=\"/admin/subvolumes/{n}/tree\">{ne}</a>",
        n = esc(&sv.name),
        ne = esc(&sv.name),
    );
    if path.is_empty() {
        return out;
    }
    let mut cum = String::new();
    for seg in path.split('/') {
        if seg.is_empty() {
            continue;
        }
        if !cum.is_empty() {
            cum.push('/');
        }
        cum.push_str(seg);
        out.push_str(" / ");
        out.push_str(&format!(
            "<a href=\"/admin/subvolumes/{n}/tree/{c}\">{s}</a>",
            n = esc(&sv.name),
            c = esc(&cum),
            s = esc(seg),
        ));
    }
    out
}

// Silence unused-import warnings on UserId in the current surface —
// kept imported because `require_admin` stashes `User` (which carries
// a `UserId`) into the request extension for future handlers that
// want to display "logged in as" banners.
#[allow(dead_code)]
fn _keep_user_id_import(_: UserId) {}
