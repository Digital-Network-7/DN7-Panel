//! HTTP middleware (≈ Laravel `app/Http/Middleware`): the safe-entry gate and
//! the defensive security-header layer. The entry-gate also binds the
//! per-request audit context (client IP + redacted headers).

use super::*;

mod gate;
pub(crate) use gate::*;

/// Attach defensive security headers to every response. A Content-Security-
/// Policy locks `default-src`/`connect-src`/`img-src` to same-origin, which
/// blocks an injected script from exfiltrating the session token to an external
/// origin. `script-src 'self'` (no `'unsafe-inline'`) — the UI ships zero inline
/// scripts/handlers (the pre-paint logic is `/ui/js/prepaint.js` and controls
/// are wired via `addEventListener` in `boot.js`). `style-src` keeps
/// `'unsafe-inline'` for the bundled inline styles. HSTS is sent only over
/// HTTPS (browsers ignore it over HTTP, and sending it could strand an
/// HTTP-only deployment).
pub(crate) async fn security_headers(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let https = state
        .settings
        .lock()
        .map(|s| SecurityPolicy::new(&s).https())
        .unwrap_or(false);
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    const CSP: &str = "default-src 'self'; script-src 'self'; \
        style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
        object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";
    let mut set = |name: header::HeaderName, val: &str| {
        if let Ok(v) = header::HeaderValue::from_str(val) {
            h.insert(name, v);
        }
    };
    set(header::CONTENT_SECURITY_POLICY, CSP);
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(header::REFERRER_POLICY, "same-origin");
    if https {
        set(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        );
    }
    resp
}
