//! In-process edge server — the pure-Rust reverse proxy that replaces the
//! external nginx the panel drives today.
//!
//! Layered like the rest of the codebase, but self-contained:
//!   - [`config`] — the immutable typed route table ([`config::RuntimeConfig`]).
//!   - [`build`] — project the persisted `Site`/`AccessList`/… model into it
//!     (the `confgen` text generation, replaced).
//!   - [`validate`] — the in-process `nginx -t`.
//!   - [`store`] — the `ArcSwap` (the in-process `nginx -s reload`).
//!   - [`reload`] — build → validate → publish, called from `infra::website`.
//!   - [`listener`]/[`tls`]/[`router`]/[`proxy`]/[`static_files`]/[`security`]/
//!     [`acme`]/[`lifecycle`] — the request data plane (M1–M5).
//!
//! This is the sole web-server implementation: it always drives :80/:443 and
//! builds its route table from the persisted manifests via [`reload`].
//!
//! Dead code is no longer blanket-allowed (the data plane is fully wired); the
//! few intentionally-reserved items carry a local `#[allow(dead_code)]` with a
//! rationale.

mod acme;
mod build;
mod config;
mod conn_limit;
mod htpasswd;
mod lifecycle;
mod limit;
mod limit_body;
mod listener;
pub mod model;
mod ports;
mod proxy;
mod reload;
mod response;
mod router;
mod security;
mod static_files;
mod status;
mod store;
mod throttle_body;
mod timeout_body;
mod tls;
mod validate;

#[cfg(test)]
mod tests;

// Public surface used by the panel's `infra::website` control plane + `platform`.
pub use build::{ConsoleParams, ReloadInput};
pub use config::CONSOLE_LOOPBACK_PORT;
pub use htpasswd::{apr1_with_salt, htpasswd_hash};
pub use ports::{set_listen_ports, ListenPorts};
pub use reload::reload;
pub use status::port_conflict;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;

type ResolverFut = Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send>>;
type Resolver = Arc<dyn Fn(String, i64) -> ResolverFut + Send + Sync>;
static RESOLVER: OnceLock<Resolver> = OnceLock::new();

/// Register how the edge resolves a `proxy_container` site's upstream to a live
/// `host:port`. The panel injects this so the edge stays decoupled from the
/// container backend (bollard or dn7) — the edge's one outward dependency, made
/// explicit instead of a direct call into `infra`.
pub fn set_upstream_resolver<F, Fut>(f: F)
where
    F: Fn(String, i64) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<String>> + Send + 'static,
{
    let _ = RESOLVER.set(Arc::new(move |name, port| Box::pin(f(name, port))));
}

/// Resolve a container upstream via the injected resolver (or error if the panel
/// never registered one).
pub(crate) async fn resolve_container_upstream(name: &str, port: i64) -> anyhow::Result<String> {
    match RESOLVER.get() {
        Some(f) => f(name.to_string(), port).await,
        None => Err(anyhow::anyhow!("edge: no upstream resolver registered")),
    }
}

/// Register an in-flight ACME HTTP-01 challenge so the edge's :80 listener can
/// answer `/.well-known/acme-challenge/<token>` from memory during issuance.
/// Thin wrapper so `infra::website` can drive ACME without reaching into the
/// private `acme` module.
pub fn acme_insert(token: &str, key_authorization: &str) {
    acme::insert(token, key_authorization);
}

/// Drop an ACME HTTP-01 challenge once issuance finishes.
pub fn acme_remove(token: &str) {
    acme::remove(token);
}

/// Start the edge data plane. Spawned from the panel role at startup and from
/// the website setup flow. Safe to call repeatedly: while the listeners are
/// up (or an attempt is in flight) a second call is a no-op, but once a previous
/// attempt has RETURNED — e.g. it parked on a port conflict — a later call
/// re-attempts the bind. That re-attempt is exactly what force-start uses after
/// killing the port's occupant.
pub fn spawn() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Once;
    static RUNNING: AtomicBool = AtomicBool::new(false);
    static PROVIDER: Once = Once::new();

    // Install the ring crypto provider as the rustls process default ONCE. The
    // TLS *listener* pins ring explicitly (`builder_with_provider`), but the
    // proxy's HTTPS upstream client (hyper-rustls / tokio-rustls
    // `ClientConfig::builder`) resolves the *process-default* provider and
    // panics if none is installed. Idempotent — a prior install (e.g. reqwest).
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    // Don't launch a second serve attempt while one is live/in-flight.
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }

    // Bound the rate-limit/auto-ban state by sweeping idle entries (idempotent).
    limit::start_sweeper();

    tokio::spawn(async {
        if let Err(e) = listener::run().await {
            tracing::error!("edge: listener exited: {e:#}");
        }
        // `run` returned: a port conflict (status already set) or a serve-loop
        // error. Clear the guard so a force-start can re-attempt the bind.
        RUNNING.store(false, Ordering::SeqCst);
    });
}
