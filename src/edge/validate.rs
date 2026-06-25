//! In-process config validation — the replacement for `nginx -t`.
//!
//! `build::build_runtime` already rejects the structural problems `nginx -t`
//! catches at *parse* time (duplicate `server_name`, a port/host claimed twice)
//! by erroring on collision while it indexes routes. This module does the
//! *semantic* gate `nginx -t` performs after parsing: an `ssl` server must have
//! a usable certificate, a `redirect` default must have a target, and every
//! location prefix must be well-formed. A failure here aborts the reload before
//! the [`super::store::publish`] swap, so the live config is untouched.

use super::config::{DefaultRoute, RouteKind, RuntimeConfig};

/// Validate a freshly-built [`RuntimeConfig`]. Returns an `nginx -t`-style error
/// string on the first problem, or `Ok(())` when the table is safe to publish.
pub(crate) fn validate(cfg: &RuntimeConfig) -> Result<(), String> {
    // Every TLS-serving host must have a certificate to present, else the
    // handshake would fail for that SNI (the `listen 443 ssl` with no cert that
    // `nginx -t` rejects). `build` degrades cert-less sites to plain HTTP, so by
    // here `ssl == true` should always resolve — assert it to fail closed.
    for (host, route) in &cfg.hosts {
        if route.ssl && cfg.certs.resolve(Some(host)).is_none() {
            return Err(format!(
                "site \"{}\": listen 443 ssl is set but no certificate resolves for {host}",
                route.id
            ));
        }
        for loc in &route.locations {
            if !loc.path.starts_with('/') {
                return Err(format!(
                    "site \"{}\": location \"{}\" must start with '/'",
                    route.id, loc.path
                ));
            }
        }
        if let RouteKind::Static(s) = &route.kind {
            if !s.root.is_absolute() {
                return Err(format!(
                    "site \"{}\": static root must be an absolute path",
                    route.id
                ));
            }
        }
    }

    if let DefaultRoute::Redirect(url) = &cfg.default_site {
        if url.trim().is_empty() {
            return Err("default site is set to redirect but has no target URL".into());
        }
    }

    Ok(())
}
