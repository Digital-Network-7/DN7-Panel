//! In-process config validation — the replacement for `nginx -t`.
//!
//! `build::build_runtime` already rejects the structural problems `nginx -t`
//! catches at *parse* time (duplicate `server_name`, a port/host claimed twice)
//! by erroring on collision while it indexes routes. This module does the
//! *semantic* gate `nginx -t` performs after parsing: an `ssl` server must have
//! a usable certificate, a `redirect` default must have a target, and every
//! location prefix must be well-formed. A failure here aborts the reload before
//! the [`super::store::publish`] swap, so the live config is untouched.

use super::config::{DefaultRoute, RouteKind, RuntimeConfig, ServerRoute};

/// Validate a freshly-built [`RuntimeConfig`]. Returns an `nginx -t`-style error
/// string on the first problem, or `Ok(())` when the table is safe to publish.
pub(crate) fn validate(cfg: &RuntimeConfig) -> Result<(), String> {
    // Exact-host routes: resolve the cert against the host itself.
    for (host, route) in &cfg.hosts {
        check_route(cfg, route, host)?;
    }
    // Wildcard routes get the same checks — they were previously skipped. The
    // stored suffix is `.example.com`, so a synthesized matching host resolves
    // the wildcard cert the same way a real request would.
    for (suffix, route) in &cfg.wildcards {
        check_route(cfg, route, &format!("wildcard-check{suffix}"))?;
    }

    if let DefaultRoute::Redirect(url) = &cfg.default_site {
        if url.trim().is_empty() {
            return Err("default site is set to redirect but has no target URL".into());
        }
    }

    Ok(())
}

/// The per-route semantic checks (`nginx -t`-equivalent): a TLS-serving route
/// must have a cert that resolves (`cert_host` is the host to test resolution
/// for), every location prefix must start with `/`, and a static root must be
/// absolute.
fn check_route(cfg: &RuntimeConfig, route: &ServerRoute, cert_host: &str) -> Result<(), String> {
    if route.ssl && cfg.certs.resolve(Some(cert_host)).is_none() {
        return Err(format!(
            "site \"{}\": listen 443 ssl is set but no certificate resolves for {cert_host}",
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
    Ok(())
}
