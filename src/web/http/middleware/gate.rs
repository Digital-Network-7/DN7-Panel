//! Init-token gate + request-audit header/response redaction + IP allow-list (split from web/server.rs).
use super::super::*;
use crate::web::http::controllers::index_page;

/// Front-door gate: the IP allow-list always applies; then, while the panel is
/// UNINITIALIZED, only requests bearing the init token (`?init_token=` on first
/// hit → a `dn7_init` cookie) are served the first-run wizard — everything else
/// gets a bare 404. Once initialized the gate is transparent (normal auth
/// protects every endpoint). The name `entry_gate` is kept for the route wiring.
pub(crate) async fn entry_gate(State(state): State<Shared>, req: Request, next: Next) -> Response {
    // Capture the client IP + sanitized request headers for the audit log, and
    // bind them as a per-request context so any audit record made while handling
    // this request can attach them (no per-handler plumbing).
    let client_ip = audit_client_ip(&state, &req);
    let headers_str = sanitize_headers(req.headers());
    let ctx = audit::RequestCtx {
        ip: client_ip,
        headers: headers_str,
    };
    audit::scope(ctx, entry_gate_inner(state, req, next)).await
}

/// The effective source IP stored on audit records. This must use the same
/// proxy-aware policy as login / rate limiting; otherwise requests through a
/// same-host reverse proxy are logged as 127.0.0.1 while login is logged as the
/// real client.
pub(crate) fn audit_client_ip(state: &Shared, req: &Request) -> String {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let Some(peer) = peer else {
        return String::new();
    };
    let s = state.settings.lock().unwrap_or_else(|poison| {
        tracing::warn!(
            "settings lock poisoned; recovering to keep audit client IP policy enforced"
        );
        poison.into_inner()
    });
    client_ip(peer, req.headers(), &SecurityPolicy::new(&s)).to_string()
}

/// The actual gate logic (allow list + safe-entry path), run inside the audit
/// request-context scope established by `entry_gate`.
pub(crate) async fn entry_gate_inner(state: Shared, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    // Resolve all security decisions under one brief settings lock via the
    // policy view (allow-list verdict + init-token gate state).
    let (allow_active, ip_ok, initialized, init_token) = {
        // A poisoned lock means a thread panicked while holding it. The settings
        // it guards are only ever *read* here (a snapshot for security
        // decisions) and aren't left half-written by a panic, so recovering the
        // guard and proceeding with the real settings is both correct and
        // strictly safer than the old behaviour — which fell back to "no
        // allow-list, entry gate disabled" (fail-open), silently dropping every
        // security control exactly when something had already gone wrong.
        let s = state.settings.lock().unwrap_or_else(|poison| {
            tracing::warn!(
                "settings lock poisoned; recovering to keep the allow-list + entry gate enforced"
            );
            poison.into_inner()
        });
        let pol = SecurityPolicy::new(&s);
        let eff = peer.map(|p| client_ip(p, req.headers(), &pol));
        (
            pol.allow_list_active(),
            eff.map(|ip| pol.ip_allowed(ip)),
            pol.initialized(),
            pol.init_token(),
        )
    };
    // Authorized-IP allow list (when configured). Loopback is always allowed.
    if allow_active {
        let ok = ip_ok.unwrap_or_else(|| {
            // An allow-list is active but we can't determine the source IP
            // (shouldn't happen — the router is mounted with ConnectInfo).
            // Fail closed: allowing would silently disable the allow-list.
            tracing::warn!("allow-list active but peer IP unavailable; denying request");
            false
        });
        if !ok {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }
    }
    // Init-token gate: while the panel is UNINITIALIZED the console serves only
    // the token-gated wizard. Once initialized there's no gate (normal auth
    // protects every endpoint). This replaces the old secret safe-entry path.
    if initialized {
        return next.run(req).await;
    }
    let token = match init_token {
        Some(t) => t,
        // Uninitialized with no token must be impossible — load_or_init always
        // seeds (or self-heals) one. Treat a missing token as an anomaly and fail
        // CLOSED rather than expose the wizard to anyone (a configured install is
        // migrated to `initialized` before it ever reaches here).
        None => return (StatusCode::NOT_FOUND, "Not Found").into_response(),
    };
    let headers = req.headers();
    // The wizard SPA + /api/init both ride the `dn7_init` cookie set on the first
    // tokened hit. Constant-time compares — it's the bootstrap secret.
    if cookie_value(headers, "dn7_init")
        .map(|c| ct_eq(c.as_bytes(), token.as_bytes()))
        .unwrap_or(false)
    {
        return next.run(req).await;
    }
    // First arrival with `?init_token=<token>`: serve the SPA (wizard) and set the
    // cookie so its subsequent /ui + /api/init requests pass.
    let q_token = req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("init_token="))
            .map(str::to_string)
    });
    if q_token
        .map(|q| ct_eq(q.as_bytes(), token.as_bytes()))
        .unwrap_or(false)
    {
        // `Secure` when the external hop is HTTPS (the edge sets X-Forwarded-Proto;
        // the console is loopback-only) so the token never rides a cleartext
        // request once TLS is on. Init is normally http, so this is usually empty.
        let secure = if headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            == Some("https")
        {
            "; Secure"
        } else {
            ""
        };
        let mut resp = index_page().await.into_response();
        if let Ok(v) =
            format!("dn7_init={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400{secure}")
                .parse()
        {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
        return resp;
    }
    // No valid token → 404 (don't reveal the console exists to a blind scan).
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

/// Constant-time byte-slice equality (length-aware). The length of the init
/// token is fixed/known, so only the *content* comparison needs to avoid an
/// early-exit timing signal on the bootstrap secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Read a named cookie value from the request headers.
pub(crate) fn cookie_value(headers: &header::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let pfx = format!("{name}=");
    raw.split(';')
        .map(|p| p.trim())
        .find_map(|p| p.strip_prefix(&pfx).map(|v| v.to_string()))
}

/// Serialize request headers to a "Name: value" block for the audit log,
/// redacting anything that could carry a credential (Authorization, Cookie,
/// and any header whose name hints at a token/secret/password/session/key).
pub(crate) fn sanitize_headers(h: &header::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in h.iter() {
        let n = name.as_str();
        let nl = n.to_ascii_lowercase();
        let secret = nl == "authorization"
            || nl == "cookie"
            || nl == "proxy-authorization"
            || nl.contains("token")
            || nl.contains("secret")
            || nl.contains("password")
            || nl.contains("session")
            || nl.contains("api-key")
            || nl.contains("apikey")
            || nl.contains("credential")
            || nl.contains("bearer");
        let v = if secret {
            "[redacted]".to_string()
        } else {
            value
                .to_str()
                .unwrap_or("[binary]")
                .chars()
                .take(256)
                .collect()
        };
        out.push_str(n);
        out.push_str(": ");
        out.push_str(&v);
        out.push('\n');
    }
    out
}

/// Redact secret-looking fields from a response value (recursively) before it
/// goes into the audit log, then serialize + truncate it.
pub(crate) fn redact_response(v: &Value) -> String {
    let mut v = v.clone();
    redact_json(&mut v);
    let s = serde_json::to_string(&v).unwrap_or_default();
    s.chars().take(4000).collect()
}

pub(crate) fn redact_json(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                let kl = k.to_ascii_lowercase();
                if kl.contains("password")
                    || kl.contains("passwd")
                    || kl.contains("pw_")
                    || kl == "pw"
                    || kl.contains("token")
                    || kl.contains("secret")
                    || kl.contains("salt")
                    || kl.contains("private")
                    || kl.contains("hash")
                    || kl.contains("verifier")
                    || kl.contains("otp")
                    || kl.contains("cred")
                    || kl.contains("seed")
                    || kl.contains("mnemonic")
                    || kl.ends_with("key")
                {
                    *val = Value::String("[redacted]".into());
                } else {
                    redact_json(val);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redact_covers_credential_shaped_fields() {
        let mut v = json!({
            "username": "alice",
            "pw_hash": "deadbeef",
            "totp_secret": "ABC",
            "verifier": "v",
            "otp_code": "123456",
            "recovery_seed": "x y z",
            "credential": "c",
            "nested": { "session_token": "t", "public": "ok" },
            "list": [ { "api_key": "k" } ]
        });
        redact_json(&mut v);
        assert_eq!(v["username"], json!("alice"));
        assert_eq!(v["nested"]["public"], json!("ok"));
        for ptr in [
            "/pw_hash",
            "/totp_secret",
            "/verifier",
            "/otp_code",
            "/recovery_seed",
            "/credential",
            "/nested/session_token",
            "/list/0/api_key",
        ] {
            assert_eq!(
                v.pointer(ptr),
                Some(&json!("[redacted]")),
                "field {ptr} should be redacted"
            );
        }
    }

    #[test]
    fn audit_client_ip_uses_forwarded_headers_from_loopback_proxy() {
        use axum::http::Request as HttpRequest;

        let cfg = crate::platform::config::PanelConfig::from_env();
        let settings = serde_json::from_value(serde_json::json!({
            "port": 1080,
            "trusted_proxies": [],
        }))
        .unwrap();
        let state = std::sync::Arc::new(WebState {
            auth: crate::infra::auth::AuthState::new(),
            settings: std::sync::Mutex::new(settings),
            collector: Mutex::new(crate::infra::metrics::Collector::new()),
            cfg,
        });
        let mut req = HttpRequest::builder()
            .uri("/api/website")
            .header("x-real-ip", "113.233.101.139")
            .header("x-forwarded-for", "113.233.101.139")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:50123".parse::<SocketAddr>().unwrap(),
        ));

        assert_eq!(audit_client_ip(&state, &req), "113.233.101.139");
    }
}
