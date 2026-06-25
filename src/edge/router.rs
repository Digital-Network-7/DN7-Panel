//! [M1] Per-request routing — the heart of request handling. Mirrors the nginx
//! server/location pipeline, in order:
//!
//!   1. Resolve the request host: the `Host` header (lowercased, port stripped),
//!      falling back to the HTTP/2 `:authority` (`req.uri().host()`) and finally
//!      the TLS SNI, so an h2 request that omits `Host` still routes.
//!   2. ACME first: a `/.well-known/acme-challenge/<token>` request is answered
//!      from the in-flight challenge map *before* any redirect/auth, because the
//!      validating CA speaks plain HTTP and follows no redirects.
//!   3. Pick the route: `cfg.route_for(host)`; a miss serves `cfg.default_site`.
//!   4. Real client IP: `security::real_ip` (honours a trusted front proxy's XFF).
//!   5. Force-SSL: a plain request to an `force_ssl` route → 301 to its https URL.
//!   6. Attack block: a tripped `block_attacks` query → 403.
//!   7. Access control: `security::check_access` may short-circuit (401/403).
//!   8. Dispatch: the longest matching custom-location prefix wins, else the
//!      route's main handler (Proxy / Static / Maintenance(503)).
//!   9. Decorate: `security::decorate` attaches HSTS (TLS) + allowlisted headers.

use hyper::body::Incoming;

use super::config::{DefaultRoute, RouteKind, ServerRoute};
use super::listener::ConnCtx;
use super::response::{self, Resp};
use super::{acme, proxy, security, static_files};

/// The `/.well-known/acme-challenge/` path prefix HTTP-01 validation hits.
const ACME_PREFIX: &str = "/.well-known/acme-challenge/";

/// Handle one request end-to-end. `cfg` is the snapshot the connection loaded.
pub(crate) async fn handle(
    req: hyper::Request<Incoming>,
    ctx: &ConnCtx,
    cfg: super::listener::SharedConfig,
) -> Resp {
    // Extract everything we need from the request *before* the body-owning `req`
    // is moved into a downstream handler. `path`/`query` are owned copies so they
    // outlive `req`; the header map is borrowed only for the security checks,
    // which all run before dispatch.
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    // Normalized path for ROUTING decisions only (ACME + location matching):
    // collapse duplicate slashes so `//api/x` matches an `/api` location, as
    // nginx does with `merge_slashes on` (its default). The *original* `path` is
    // still what we forward upstream / use in redirects, so encoding is preserved.
    let match_path = collapse_slashes(&path);

    // 1. Resolve the host. Prefer the `Host` header; fall back to the h2
    //    `:authority` (surfaced via `uri().host()`) and then the offered SNI.
    let host = {
        let header_host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok());
        let mut h = host_key(header_host);
        if h.is_empty() {
            if let Some(authority) = req.uri().host() {
                h = host_key(Some(authority));
            }
        }
        if h.is_empty() {
            if let Some(sni) = ctx.sni.as_deref() {
                h = host_key(Some(sni));
            }
        }
        h
    };

    // 2. ACME HTTP-01 — bypasses redirect/auth/route entirely. A token we don't
    //    hold falls through to normal routing (so a stray probe 404s as usual).
    if let Some(token) = match_path.strip_prefix(ACME_PREFIX) {
        if !token.is_empty() {
            if let Some(resp) = acme::serve(token) {
                return resp;
            }
        }
    }

    // 3. Route selection: managed host, else the default-site behaviour.
    let route = match cfg.route_for(&host) {
        Some(r) => r.clone(),
        None => return default_response(&cfg.default_site, &host, &path, &query),
    };

    // 4. The real client IP, recovered through any trusted front proxy.
    let client_ip = security::real_ip(ctx, req.headers(), route.trust_proxy.as_ref());

    // 5. Force-SSL: redirect plain HTTP to the canonical https URL (path+query).
    if route.force_ssl && !ctx.tls {
        return https_redirect(&host, &path, &query);
    }

    // 6. Exploit-pattern query blocking.
    if route.block_attacks && security::blocked_by_attacks(&query) {
        return finish(response::status(http::StatusCode::FORBIDDEN), &route, ctx.tls);
    }

    // 7. Access control (HTTP Basic + IP allow/deny). A `Some` short-circuits.
    if let Some(mut resp) = security::check_access(route.access.as_deref(), req.headers(), client_ip)
    {
        security::decorate(&mut resp, &route, ctx.tls);
        return resp;
    }

    // 8. Dispatch. A custom location whose prefix matches the request path takes
    //    precedence over the site's main handler; locations are pre-sorted
    //    longest-prefix-first by the builder, so the first match is the most
    //    specific one.
    let resp = if let Some(loc) = route
        .locations
        .iter()
        .find(|l| location_matches(&l.path, &match_path))
    {
        proxy::handle(req, &loc.target, ctx, client_ip, &cfg.tuning).await
    } else {
        match &route.kind {
            RouteKind::Proxy(target) => {
                proxy::handle(req, target, ctx, client_ip, &cfg.tuning).await
            }
            RouteKind::Static(root) => static_files::handle(&req, root, &cfg.tuning).await,
            // The maintenance stub: upstream unresolvable at build time.
            RouteKind::Maintenance => {
                response::text(http::StatusCode::SERVICE_UNAVAILABLE, "503 Service Unavailable")
            }
        }
    };

    // 9. Attach HSTS (TLS only) + the route's allowlisted extra headers.
    finish(resp, &route, ctx.tls)
}

/// Collapse runs of `/` into a single `/` (nginx `merge_slashes`). Borrows when
/// there's nothing to collapse so the common path pays nothing.
pub(crate) fn collapse_slashes(path: &str) -> std::borrow::Cow<'_, str> {
    if !path.contains("//") {
        return std::borrow::Cow::Borrowed(path);
    }
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for c in path.chars() {
        if c == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(c);
    }
    std::borrow::Cow::Owned(out)
}

/// Whether a custom-location `prefix` matches `path` with nginx prefix-match
/// semantics: a literal prefix where a non-`/`-terminated prefix only matches at
/// a path-segment boundary (so `/api` matches `/api` and `/api/x` but not
/// `/apixyz`). A bare `/` matches everything.
pub(crate) fn location_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    // Exact match, or the next char is a separator (segment boundary). A prefix
    // already ending in `/` is a clean boundary by construction.
    prefix.ends_with('/')
        || path.len() == prefix.len()
        || path.as_bytes().get(prefix.len()) == Some(&b'/')
}

/// Apply `security::decorate` to a built response and return it. Centralised so
/// every response leaving the router (including short-circuit 403s) is decorated.
fn finish(mut resp: Resp, route: &ServerRoute, tls: bool) -> Resp {
    security::decorate(&mut resp, route, tls);
    resp
}

/// Build the 301 to the https form of the same request (`host` + path + query).
fn https_redirect(host: &str, path: &str, query: &str) -> Resp {
    let target = if query.is_empty() {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}{path}?{query}")
    };
    response::redirect(&target)
}

/// Serve the configured default-site behaviour for an unmatched host.
fn default_response(default: &DefaultRoute, host: &str, path: &str, query: &str) -> Resp {
    match default {
        DefaultRoute::NotFound => response::text(http::StatusCode::NOT_FOUND, "404 Not Found"),
        DefaultRoute::Welcome => response::html(
            http::StatusCode::OK,
            "<!doctype html><html><head><meta charset=\"utf-8\">\
             <title>Welcome</title></head><body>\
             <h1>Welcome</h1><p>This server is managed by DN7 Panel.</p>\
             </body></html>",
        ),
        // nginx `444`: close the connection with no response. We can only return
        // a response from a service, so emit a bare 444 status (best effort) and
        // let the connection close after it.
        DefaultRoute::Drop => match http::StatusCode::from_u16(444) {
            Ok(code) => response::status(code),
            Err(_) => response::status(http::StatusCode::BAD_REQUEST),
        },
        // 301 the whole vhost to the operator's fixed URL verbatim; the original
        // request path/query are intentionally dropped (the configured target is
        // the canonical destination).
        DefaultRoute::Redirect(url) => {
            let _ = (host, path, query);
            response::redirect(url)
        }
    }
}

/// Normalise a `Host` header value to a bare lowercased hostname (strip any
/// `:port`). Provided here because both routing and cert lookup need it.
pub(crate) fn host_key(host_header: Option<&str>) -> String {
    host_header
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}
