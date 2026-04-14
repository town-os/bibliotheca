//! bibliotheca-anisette: a thin HTTP proxy in front of operator-
//! controlled anisette servers.
//!
//! # Why a proxy
//!
//! `bibliotheca-sync-icloud`'s login flow needs Apple's device
//! attestation headers (`X-Apple-I-MD`, `X-Apple-I-MD-M`, and
//! friends) on every request it makes to `idmsa.apple.com`. Those
//! headers are computed by Apple's `CoreADI` library, which only
//! runs against Apple-signed binaries. The actual producer must
//! therefore live somewhere the operator owns and runs that code.
//! The producer is out of scope for this crate.
//!
//! bibliotheca-anisette is always a client-side proxy that
//! forwards to upstream anisette servers the operator controls
//! (typically a peer bibliotheca node reachable over a VPN and
//! resolved via private DNS). The upstream is always your
//! infrastructure; this crate never forwards to community or
//! third-party providers. Zero Python, no Apple binaries on disk,
//! no shared state between trust domains.
//!
//! What the proxy adds on top of a single upstream:
//!
//! - Round-robin failover across multiple upstreams so a reboot
//!   or VPN flap on any one producer doesn't stall sync.
//! - Per-upstream health tracking with exponential backoff so a
//!   down upstream stops getting hit until it recovers.
//! - Short TTL caching (Apple's OTPs are valid for roughly 30 s)
//!   so a burst of sync cycles doesn't hammer producers.
//! - Local endpoint on 127.0.0.1 (or whatever you bind) that every
//!   `sync-icloud` mount in the same daemon can point at without
//!   extra auth, since it sits inside the loopback + filesystem
//!   trust boundary.
//!
//! `sync-icloud` points at the proxy's local socket and never has
//! to know the upstream exists.
//!
//! # Wire shape
//!
//! The endpoint is `POST /v3/get_anisette_data`. The response is
//! a JSON object containing the `X-Apple-*` and `X-Mme-*` headers
//! as top-level fields, which `sync-icloud::auth::anisette` already
//! knows how to consume.
//!
//! A `GET /health` endpoint is always unauthenticated and always
//! returns `200 ok` once the server is bound. The point is a
//! liveness probe, not an upstream reachability probe; the upstream
//! check is exposed through `AnisetteProvider::status` and the
//! `AnisetteAdmin` gRPC surface in `bibliothecad`.

#![allow(clippy::result_large_err)]

pub mod error;
pub mod provider;
pub mod proxy;
pub mod server;

pub use error::{Error, Result};
pub use provider::{
    AnisetteHeaders, AnisetteProvider, MockProvider, ProviderStatus, UpstreamHealth,
};
pub use proxy::{ProxyConfig, ProxyProvider};
pub use server::{serve, AnisetteServerConfig};
