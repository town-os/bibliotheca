//! Authenticated HTTP interface.
//!
//! HTTP is **disabled by default**. Operators must explicitly enable
//! this interface via the control plane (`Interfaces.Enable`). Anonymous
//! requests are only ever served when the requested subvolume's ACL has
//! an explicit `Public` entry. Even then, the interface as a whole has
//! to be enabled before any anonymous traffic is honoured — defense in
//! depth against accidental exposure.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use bibliotheca_core::acl::Permission;
use bibliotheca_core::error::Error as CoreError;
use bibliotheca_core::identity::User;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::subvolume::SubvolumeId;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    svc: BibliothecaService,
    public_allowed: bool,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub listen: SocketAddr,
    /// Honour ACL entries with `Principal::Public`. Requires the
    /// interface to be enabled in the first place.
    pub allow_public: bool,
}

pub async fn start(svc: BibliothecaService, cfg: HttpConfig) -> anyhow::Result<()> {
    let state = AppState {
        svc,
        public_allowed: cfg.allow_public,
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/subvolumes/:sv/objects/*key", get(get_object))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    info!(addr = %cfg.listen, "bibliotheca-http listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((sv_name, _key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let sv = match state.svc.get_subvolume(&sv_name) {
        Ok(sv) => sv,
        Err(CoreError::NotFound(_)) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            warn!(error = %e, "subvolume lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let user = authenticate(&state, &headers);
    let allowed = state
        .svc
        .check_permission(
            SubvolumeId(sv.id.0),
            user.as_ref().map(|u| u.id),
            Permission::Read,
            state.public_allowed,
        )
        .unwrap_or(false);

    if !allowed {
        if user.is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"bibliotheca\"")],
            )
                .into_response();
        }
        return StatusCode::FORBIDDEN.into_response();
    }

    // Streaming the actual object body is the next implementation step;
    // it lives behind ACL evaluation so the auth path is correct first.
    StatusCode::NO_CONTENT.into_response()
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let creds = auth.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(creds)
        .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    state.svc.verify_user_password(user, pass).ok().flatten()
}
