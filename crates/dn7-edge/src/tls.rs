//! [M1] TLS termination: the rustls `ServerConfig` + SNI certificate resolver.
//!
//! The resolver reads the *current* published config on every handshake (not a
//! captured snapshot), so a cert added/renewed by a reload is presented
//! immediately without re-binding the listener. The `ServerConfig` is built with
//! the ring provider explicitly to keep the musl-static build C-toolchain-free
//! (never aws-lc-rs). ALPN advertises `h2` + `http/1.1`; the hyper-util auto
//! server selects the right protocol per the negotiated value, and a route's
//! `http2` preference is honoured by the auto server downgrading to h1 when the
//! client doesn't pick h2.

use std::sync::Arc;

/// Resolves the server certificate for a TLS handshake by SNI, against the
/// currently-published [`super::config::RuntimeConfig`]'s cert store. Stateless
/// (a unit struct): all the material lives in the store it reads on each call.
#[derive(Debug)]
pub(crate) struct SniResolver;

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // `current()` is a lock-free `ArcSwap` load; cert lookup is exact →
        // wildcard → default (see `CertStore::resolve`). `None` means the
        // handshake has no cert to offer and rustls aborts it.
        super::store::current()
            .certs
            .resolve(client_hello.server_name())
    }
}

/// Build the shared rustls server config: ring provider, safe default protocol
/// versions, no client auth, the SNI resolver, and `h2`/`http1.1` ALPN.
pub(crate) fn server_config() -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(SniResolver));
    // ALPN: advertise h2 + http/1.1 (hyper-util auto server selects per ALPN).
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
