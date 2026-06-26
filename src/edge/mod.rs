//! In-process edge server — the pure-Rust reverse proxy that replaces the
//! external nginx the panel drives today.
//!
//! Layered like the rest of the codebase, but self-contained:
//!   - [`config`] — the immutable typed route table ([`config::RuntimeConfig`]).
//!   - [`build`] — project the persisted `Site`/`AccessList`/… model into it
//!     (the `confgen` text generation, replaced).
//!   - [`validate`] — the in-process `nginx -t`.
//!   - [`store`] — the `ArcSwap` (the in-process `nginx -s reload`).
//!   - [`reload`] — build → validate → publish, called from `infra::nginx`.
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
mod lifecycle;
mod listener;
mod proxy;
mod reload;
mod response;
mod router;
mod security;
mod static_files;
mod status;
mod store;
mod timeout_body;
mod tls;
mod validate;

#[cfg(test)]
mod tests;

// Public surface used by `infra::website` (the control plane) and `platform`.
pub(crate) use build::{ConsoleParams, ReloadInput};
pub(crate) use config::CONSOLE_LOOPBACK_PORT;
pub(crate) use reload::reload;
pub(crate) use status::port_conflict;

/// Register an in-flight ACME HTTP-01 challenge so the edge's :80 listener can
/// answer `/.well-known/acme-challenge/<token>` from memory during issuance.
/// Thin wrapper so `infra::nginx` can drive ACME without reaching into the
/// private `acme` module.
pub(crate) fn acme_insert(token: &str, key_authorization: &str) {
    acme::insert(token, key_authorization);
}

/// Drop an ACME HTTP-01 challenge once issuance finishes.
pub(crate) fn acme_remove(token: &str) {
    acme::remove(token);
}

/// Start the edge data plane. Spawned from the panel role at startup and from
/// the nginx setup flow. Safe to call repeatedly: while the listeners are
/// up (or an attempt is in flight) a second call is a no-op, but once a previous
/// attempt has RETURNED — e.g. it parked on a port conflict — a later call
/// re-attempts the bind. That re-attempt is exactly what force-start uses after
/// killing the port's occupant.
pub(crate) fn spawn() {
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

    tokio::spawn(async {
        if let Err(e) = listener::run().await {
            tracing::error!("edge: listener exited: {e:#}");
        }
        // `run` returned: a port conflict (status already set) or a serve-loop
        // error. Clear the guard so a force-start can re-attempt the bind.
        RUNNING.store(false, Ordering::SeqCst);
    });
}
