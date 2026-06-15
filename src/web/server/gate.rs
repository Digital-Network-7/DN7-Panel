//! Safe-entry gate + request-audit header/response redaction + IP allow-list (split from web/server.rs).
use super::*;

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
    // Authorized-IP allow list (when configured). Loopback is always allowed to
    // avoid a self-lockout from the local CLI / curl.
    let allow = state
        .settings
        .lock()
        .map(|s| s.allow_ips.clone())
        .unwrap_or_default();
    if !allow.is_empty() {
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        let ok = match peer {
            Some(ip) => ip_in_allowlist(&allow, ip),
            // Fail closed: an allow-list is configured but we can't determine
            // the source IP (shouldn't happen — the router is mounted with
            // ConnectInfo). Denying is the safe choice; allowing would silently
            // disable the allow-list.
            None => {
                tracing::warn!("allow-list active but peer IP unavailable; denying request");
                false
            }
        };
        if !ok {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }
    }
    let entry = state
        .settings
        .lock()
        .map(|s| s.entry_path.clone())
        .unwrap_or_else(|_| "/".to_string());
    if entry == "/" || entry.is_empty() {
        return next.run(req).await;
    }
    let token = entry.trim_start_matches('/').to_string();
    let headers = req.headers();
    let authed = bearer(headers)
        .map(|t| state.auth.valid(&t))
        .unwrap_or(false);
    let cookie_ok = cookie_value(headers, "dn7_entry").as_deref() == Some(token.as_str());
    if authed || cookie_ok {
        return next.run(req).await;
    }
    if req.uri().path() == entry {
        let mut resp = index_page().await.into_response();
        if let Ok(v) =
            format!("dn7_entry={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000").parse()
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
            || nl.contains("apikey");
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

/// Whether `ip` is permitted by the authorized-IP allow list. Loopback is
/// always allowed (avoids locking the local operator out). Entries are exact
/// IPs or CIDR blocks (validated on save).
pub(crate) fn ip_in_allowlist(allow: &[String], ip: std::net::IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    for entry in allow {
        if let Some((a, p)) = entry.split_once('/') {
            if let (Ok(net), Ok(prefix)) = (a.parse::<std::net::IpAddr>(), p.parse::<u8>()) {
                if cidr_contains(net, prefix, ip) {
                    return true;
                }
            }
        } else if let Ok(a) = entry.parse::<std::net::IpAddr>() {
            if a == ip {
                return true;
            }
        }
    }
    false
}

/// Whether `ip` falls within the `net`/`prefix` CIDR block (v4 or v6).
pub(crate) fn cidr_contains(net: std::net::IpAddr, prefix: u8, ip: std::net::IpAddr) -> bool {
    match (net, ip) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}
