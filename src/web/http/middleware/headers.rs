//! Defensive security-header response layer (CSP / nosniff / frame-deny /
//! referrer / HSTS-over-https).
use super::super::*;

/// Policy locks `default-src`/`connect-src`/`img-src` to same-origin, which
/// blocks an injected script from exfiltrating the session token to an external
/// origin. `script-src 'self'` (no `'unsafe-inline'`) — the UI ships zero inline
/// scripts/handlers (the pre-paint logic is `/ui/js/prepaint.js` and controls
/// are wired via `addEventListener` in `boot.js`). `style-src` keeps
/// `'unsafe-inline'` for the bundled inline styles. HSTS is sent only over
/// HTTPS (browsers ignore it over HTTP, and sending it could strand an
/// HTTP-only deployment).
pub(crate) async fn security_headers(req: Request, next: Next) -> Response {
    // The console binds loopback behind the edge, which terminates TLS and sets
    // X-Forwarded-Proto. Send HSTS only when the *external* hop is HTTPS (over
    // plain HTTP a browser ignores it, and sending it could strand an HTTP-only
    // deployment).
    let https = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https");
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
