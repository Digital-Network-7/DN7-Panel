//! Safe-entry gate + request-audit header/response redaction + IP allow-list (split from web/server.rs).
use super::super::*;
use crate::web::http::controllers::index_page;

/// (a) carry a valid session token, (b) carry the matching `dn7_entry` cookie,
/// or (c) hit the entry path itself are served; everything else gets a bare
/// 404. Visiting the entry path returns the login page and sets the cookie, so
/// the SPA's subsequent `/api` + `/ui` requests pass. Defends against scanners
/// that don't know the secret path (obscurity layer, not a TLS replacement).
pub(crate) async fn entry_gate(State(state): State<Shared>, req: Request, next: Next) -> Response {
    // Capture the client IP + sanitized request headers for the audit log, and
    // bind them as a per-request context so any audit record made while handling
    // this request can attach them (no per-handler plumbing).
    let client_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_default();
    let headers_str = sanitize_headers(req.headers());
    let ctx = audit::RequestCtx {
        ip: client_ip,
        headers: headers_str,
    };
    audit::scope(ctx, entry_gate_inner(state, req, next)).await
}

/// The actual gate logic (allow list + safe-entry path), run inside the audit
/// request-context scope established by `entry_gate`.
pub(crate) async fn entry_gate_inner(state: Shared, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    // Resolve all security decisions under one brief settings lock via the
    // policy view (allow-list verdict, entry token/path, cookie Secure attr).
    let (allow_active, ip_ok, entry_token, entry_path, secure) = match state.settings.lock() {
        Ok(s) => {
            let pol = SecurityPolicy::new(&s);
            let eff = peer.map(|p| client_ip(p, req.headers(), &pol));
            (
                pol.allow_list_active(),
                eff.map(|ip| pol.ip_allowed(ip)),
                pol.entry_token(),
                pol.entry_path(),
                pol.cookie_secure_attr(),
            )
        }
        // Poisoned lock: behave as the permissive default (no allow-list, gate
        // disabled) rather than locking everyone out.
        Err(_) => (false, None, None, "/".to_string(), ""),
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
    // Safe-entry gate. Disabled (token None) → serve everything.
    let token = match entry_token {
        Some(t) => t,
        None => return next.run(req).await,
    };
    let headers = req.headers();
    let authed = bearer(headers)
        .map(|t| state.auth.valid(&t))
        .unwrap_or(false);
    let cookie_ok = cookie_value(headers, "dn7_entry").as_deref() == Some(token.as_str());
    if authed || cookie_ok {
        return next.run(req).await;
    }
    if req.uri().path() == entry_path {
        let mut resp = index_page().await.into_response();
        // Add `Secure` when serving over HTTPS so the entry token never rides a
        // plaintext request if the user later hits the same host over HTTP.
        if let Ok(v) =
            format!("dn7_entry={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000{secure}")
                .parse()
        {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
        return resp;
    }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
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
}
