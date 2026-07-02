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
//!      Then the per-IP "高级功能" gates on that IP: inline IP-ACL (allow/deny →
//!      403), rate limit + auto-ban (429/403).
//!   5. Force-SSL: a plain request to an `force_ssl` route → 301 to its https URL.
//!   6. Attack block: a tripped `block_attacks` query → 403.
//!   7. Access control: `security::check_access` may short-circuit (401/403).
//!      Then anti-hotlinking (foreign `Referer` → 403) and the per-IP concurrency
//!      admission (over `conn_per_ip` in-flight → 503), whose RAII slot is held
//!      until the response body drains.
//!   8. Dispatch: the longest matching custom-location prefix wins, else the
//!      route's main handler (Proxy / Static / Maintenance(503)).
//!   9. Decorate: `security::decorate` attaches HSTS (TLS) + allowlisted headers.

use hyper::body::Incoming;

use super::config::{DefaultRoute, RouteKind, ServerRoute};
use super::listener::ConnCtx;
use super::response::{self, Resp};
use super::{acme, conn_limit, limit, proxy, security, static_files, throttle_body};

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

    // 4.3 Per-site inline IP ACL (the "高级功能" IP-ACL knob). A pure IP gate
    //     distinct from the shared access list (checked at step 7): allow-mode
    //     admits only listed nets, deny-mode blocks listed nets. A disallowed IP
    //     is 403'd before any other work. Loopback (the console / same-host) is
    //     exempt so the box stays manageable regardless of the operator's list.
    if let Some(acl) = route.ip_acl.as_ref() {
        if !client_ip.is_loopback() && !acl.permits(client_ip) {
            return finish(
                response::status(http::StatusCode::FORBIDDEN),
                &route,
                ctx.tls,
            );
        }
    }

    // 4.5 Per-IP rate limit + auto-ban (the "高级功能" knobs). Loopback (the
    //     console / same-host) is exempt; a banned IP is dropped before any
    //     other work (even the force-SSL redirect).
    if let Some(rl) = route.rate_limit.as_ref() {
        if !client_ip.is_loopback() {
            match limit::check(&route.id, client_ip, rl) {
                limit::Verdict::Allow => {}
                limit::Verdict::Banned => {
                    return finish(
                        response::status(http::StatusCode::FORBIDDEN),
                        &route,
                        ctx.tls,
                    );
                }
                limit::Verdict::RateLimited => {
                    let mut resp = response::text(
                        http::StatusCode::TOO_MANY_REQUESTS,
                        "429 Too Many Requests",
                    );
                    resp.headers_mut().insert(
                        http::header::RETRY_AFTER,
                        http::HeaderValue::from_static("1"),
                    );
                    return finish(resp, &route, ctx.tls);
                }
            }
        }
    }

    // 5. Force-SSL: redirect plain HTTP to the canonical https URL (path+query).
    if route.force_ssl && !ctx.tls {
        return https_redirect(&host, &path, &query);
    }

    // 6. Exploit-pattern query blocking.
    if route.block_attacks && security::blocked_by_attacks(&query) {
        return finish(
            response::status(http::StatusCode::FORBIDDEN),
            &route,
            ctx.tls,
        );
    }

    // 7. Access control (HTTP Basic + IP allow/deny). A `Some` short-circuits.
    if let Some(mut resp) =
        security::check_access(route.access.as_deref(), req.headers(), client_ip)
    {
        security::decorate(&mut resp, &route, ctx.tls);
        return resp;
    }

    // 7.5 Anti-hotlinking (the "高级功能" hotlink knob): an absent/same-origin/
    //     allowlisted Referer passes; a foreign referer is 403'd. See
    //     `config::Hotlink::permits` for the exact policy.
    if let Some(hotlink) = route.hotlink.as_ref() {
        let referer = req
            .headers()
            .get(http::header::REFERER)
            .and_then(|v| v.to_str().ok());
        if !hotlink.permits(referer, &host) {
            return finish(
                response::status(http::StatusCode::FORBIDDEN),
                &route,
                ctx.tls,
            );
        }
    }

    // 7.7 Per-IP concurrency limit (the "高级功能" connection-limit knob): admit
    //     at most `conn_per_ip` in-flight requests per client IP. The RAII guard
    //     is threaded into the response body below, so the slot stays held until
    //     the body drains (a slow reader keeps occupying its slot). Loopback is
    //     exempt; 0 = unlimited.
    let conn_guard = if route.conn_per_ip > 0 && !client_ip.is_loopback() {
        match conn_limit::acquire(&route.id, client_ip, route.conn_per_ip) {
            Some(guard) => Some(guard),
            None => {
                let mut resp = response::text(
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    "503 Service Unavailable",
                );
                resp.headers_mut().insert(
                    http::header::RETRY_AFTER,
                    http::HeaderValue::from_static("1"),
                );
                return finish(resp, &route, ctx.tls);
            }
        }
    } else {
        None
    };

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
            RouteKind::Maintenance => response::text(
                http::StatusCode::SERVICE_UNAVAILABLE,
                "503 Service Unavailable",
            ),
        }
    };

    // 8.5 Download throttle (the "高级功能" bandwidth knob): pace the response
    //     body to the configured bytes/sec. Loopback (console / same-host) is
    //     exempt; a 0 rate (or no config) leaves the body untouched.
    let resp = match route.rate_limit.as_ref().map(|r| r.bytes_per_sec) {
        Some(rate) if rate > 0 && !client_ip.is_loopback() => {
            let (parts, body) = resp.into_parts();
            http::Response::from_parts(parts, throttle_body::throttle(body, rate))
        }
        _ => resp,
    };

    // 8.7 Hold the per-IP concurrency slot until the response body drains: wrap
    //     the body so `conn_guard`'s `Drop` (which releases the slot) fires at
    //     request completion, not merely when this handler returns.
    let resp = match conn_guard {
        Some(guard) => {
            let (parts, body) = resp.into_parts();
            http::Response::from_parts(parts, conn_limit::guard_body(body, guard))
        }
        None => resp,
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
///
/// A bracketed IPv6 literal (`[::1]` / `[::1]:443`) keeps its brackets — that is
/// how the address is spelled in a `Host` header and how the route/cert tables
/// index it — so we strip only a trailing `:port` after the `]`, never the
/// colons *inside* the literal. A bare hostname or IPv4 splits on its single
/// `:port` as before; an unbracketed multi-colon value is left intact (it can
/// only be a malformed host, and there is no safe port to strip).
pub(crate) fn host_key(host_header: Option<&str>) -> String {
    let h = host_header.unwrap_or("").trim();
    let host = if let Some(rest) = h.strip_prefix('[') {
        // `[v6]` or `[v6]:port` — keep everything up to and including the `]`.
        match rest.find(']') {
            Some(end) => &h[..end + 2], // `[` + `rest[..end]` + `]`
            None => h,                  // malformed (no closing bracket): leave as-is
        }
    } else if h.matches(':').count() == 1 {
        // A single colon: a `host:port` (or `v4:port`) — strip the port.
        h.split(':').next().unwrap_or("")
    } else {
        // No colon (bare host), or many colons (an unbracketed v6 literal):
        // nothing safe to strip.
        h
    };
    host.to_ascii_lowercase()
}
