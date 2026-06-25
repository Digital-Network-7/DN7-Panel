//! [M4] Request-time access control + response security headers.
//!
//! This is the in-process replacement for the nginx `set_real_ip_from`/`real_ip`
//! recovery, the `BLOCK_EXPLOITS` query-string guard, the `allow`/`deny` +
//! `auth_basic` access lists, and the `add_header`/HSTS response decoration that
//! the panel used to render into generated config. The router calls these in the
//! same order nginx evaluates them (real-IP → attack block → access → decorate).

use std::net::IpAddr;

use base64::Engine as _;
use http::header::{HeaderName, HeaderValue};
use http::{header, HeaderMap, StatusCode};

use super::config::{AccessControl, ServerRoute, TrustProxy};
use super::listener::ConnCtx;
use super::response::{self, Resp};

/// Resolve the real client IP, honouring a trusted front proxy's `X-Forwarded-For`.
///
/// Without a [`TrustProxy`] config — or when the immediate peer is NOT a trusted
/// source — we return the peer IP unchanged. This is the load-bearing safety
/// property: an untrusted client can forge an arbitrary XFF chain, so we must
/// never let XFF override the peer unless the hop that delivered the request is
/// one we explicitly trust to set it (mirrors `set_real_ip_from`).
pub(crate) fn real_ip(ctx: &ConnCtx, headers: &HeaderMap, trust: Option<&TrustProxy>) -> IpAddr {
    // Canonicalize the resolved address: an IPv4-mapped IPv6 form
    // (`::ffff:1.2.3.4`) is collapsed to plain `1.2.3.4` so it can't sidestep an
    // IPv4 `allow`/`deny` rule (or the trusted-proxy check) by wearing a v6 mask.
    real_ip_inner(ctx, headers, trust).to_canonical()
}

fn real_ip_inner(ctx: &ConnCtx, headers: &HeaderMap, trust: Option<&TrustProxy>) -> IpAddr {
    // Canonicalize the peer too, so a v4-mapped peer is matched against trusted
    // sources as its v4 form.
    let peer = ctx.peer.ip().to_canonical();
    let Some(tp) = trust else {
        return peer;
    };
    // Only consult XFF if the immediate peer is itself a trusted proxy.
    if !tp.trusts(peer) {
        return peer;
    }

    // Collect every parseable XFF entry, in header order (leftmost = original
    // client, rightmost = nearest proxy). A single client can send multiple
    // `X-Forwarded-For` headers; nginx flattens them, so we concatenate.
    let mut chain: Vec<IpAddr> = Vec::new();
    for hv in headers.get_all("x-forwarded-for").iter() {
        let Ok(s) = hv.to_str() else { continue };
        for part in s.split(',') {
            if let Some(ip) = parse_xff_entry(part) {
                chain.push(ip);
            }
        }
    }
    if chain.is_empty() {
        return peer;
    }

    if tp.recursive {
        // `real_ip_recursive on`: walk right-to-left skipping trusted hops and
        // return the first untrusted address — that is the real client. If every
        // hop is trusted, fall back to the leftmost (original) entry.
        for ip in chain.iter().rev() {
            if !tp.trusts(*ip) {
                return *ip;
            }
        }
        chain[0]
    } else {
        // `real_ip_recursive off`: trust exactly one hop — the rightmost entry,
        // i.e. the address the trusted proxy reported as its own client.
        *chain.last().unwrap()
    }
}

/// Parse one `X-Forwarded-For` list entry into an [`IpAddr`].
///
/// Entries may carry surrounding whitespace, and an IPv6 address may arrive
/// bracketed and/or port-suffixed (`[2001:db8::1]:443`). We strip those so a
/// well-formed proxy chain still parses.
fn parse_xff_entry(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // Canonicalize so a v4-mapped v6 entry is compared as its v4 form (parity
    // with the peer + ACL canonicalization).
    // Fast path: a bare address.
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    // `[v6]` or `[v6]:port`.
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            if let Ok(ip) = rest[..end].parse::<IpAddr>() {
                return Some(ip.to_canonical());
            }
        }
    }
    // `v4:port` (IPv6 without brackets is ambiguous with its own colons, so we
    // only strip a port when there is exactly one colon).
    if s.matches(':').count() == 1 {
        if let Some((host, _port)) = s.rsplit_once(':') {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(ip.to_canonical());
            }
        }
    }
    None
}

/// Whether the query string trips an exploit-blocking rule.
///
/// These reproduce the five intents of the classic nginx `BLOCK_EXPLOITS`
/// ruleset using plain (lowercased) substring tests — there is no regex crate in
/// the edge build, and substring matching is strictly more permissive than the
/// original anchored regexes, so we never miss the obvious attack while staying
/// conservative about what we reject. Query-string only; we never block on a
/// legitimately encoded body.
pub(crate) fn blocked_by_attacks(query: &str) -> bool {
    let q = query.to_ascii_lowercase();

    // (1) Reflected/script injection: a `<…script…>` tag in either raw or
    // percent-encoded form. Require an opener, the word `script`, and a closer
    // so an innocent `?description=javascript` doesn't trip it.
    let has_open = q.contains('<') || q.contains("%3c");
    let has_close = q.contains('>') || q.contains("%3e");
    if has_open && has_close && q.contains("script") {
        return true;
    }

    // (2) PHP `$GLOBALS[...]` override attempts.
    if q.contains("globals=") || q.contains("globals[") || q.contains("globals%") {
        return true;
    }

    // (3) PHP `$_REQUEST[...]` override attempts.
    if q.contains("_request=") || q.contains("_request[") || q.contains("_request%") {
        return true;
    }

    // (4) `/proc/self/environ` LFI/RCE probe.
    if q.contains("proc/self/environ") {
        return true;
    }

    // (5) `base64_encode(` / `base64_decode(` PHP-injection probes.
    if q.contains("base64_encode(") || q.contains("base64_decode(") {
        return true;
    }

    false
}

/// Enforce access control. `Some(resp)` short-circuits the request with the
/// appropriate 401/403; `None` means the request is permitted.
///
/// Two independent factors are evaluated and then combined per `satisfy`:
///   * IP factor — the `allow`/`deny` rules, first-match-wins (nginx order). A
///     request that matches no rule is allowed (nginx default), and an empty
///     rule set is unconditionally allowed.
///   * Auth factor — HTTP Basic credentials checked against the access list's
///     htpasswd hashes.
pub(crate) fn check_access(
    access: Option<&AccessControl>,
    headers: &HeaderMap,
    client_ip: IpAddr,
) -> Option<Resp> {
    // No access list configured → fully public.
    let access = access?;

    // nginx `satisfy` combines only the access methods that are actually
    // configured: an *absent* method is not a passing factor. So a `deny all`
    // with no auth users must reject under `satisfy any` (the IP method is the
    // only one configured and it failed) — treating absent auth as "pass" would
    // wrongly open it. An access list with neither factor is simply public.
    let has_acl = access.has_acl();
    let has_auth = access.has_auth();
    if !has_acl && !has_auth {
        return None;
    }

    let ip_pass = has_acl && ip_allowed(access, client_ip);
    let auth_pass = has_auth && auth_allowed(access, headers);

    let granted = if access.satisfy_all {
        // Every configured method must pass.
        (!has_acl || ip_pass) && (!has_auth || auth_pass)
    } else {
        // Any configured method passing is enough.
        ip_pass || auth_pass
    };
    if granted {
        return None;
    }

    // Denied — prefer a 401 challenge (so a browser can prompt for credentials)
    // only when supplying a password could actually satisfy the policy.
    if access.satisfy_all {
        // Both required. A wrong IP can't be fixed by a password → 403; otherwise
        // the missing/incorrect credential is the blocker → 401.
        if has_acl && !ip_pass {
            Some(response::status(StatusCode::FORBIDDEN))
        } else {
            Some(response::auth_challenge(&access.realm))
        }
    } else {
        // Either would suffice and neither did. Offer the credential prompt when
        // auth is even an option; otherwise it's a pure IP rejection → 403.
        if has_auth {
            Some(response::auth_challenge(&access.realm))
        } else {
            Some(response::status(StatusCode::FORBIDDEN))
        }
    }
}

/// Evaluate the allow/deny rules against `client_ip` (first match wins).
/// No matching rule → allow (nginx default); empty rule set → allow.
fn ip_allowed(access: &AccessControl, client_ip: IpAddr) -> bool {
    if !access.has_acl() {
        return true;
    }
    for rule in &access.rules {
        if rule.net.matches(client_ip) {
            return rule.allow;
        }
    }
    // Reached the end with no match — default allow (nginx semantics).
    true
}

/// Verify HTTP Basic credentials against the access list's htpasswd hashes.
fn auth_allowed(access: &AccessControl, headers: &HeaderMap) -> bool {
    let Some((user, pass)) = parse_basic_auth(headers) else {
        return false;
    };
    // Match the username, then verify the password against its stored hash.
    // Usernames are unique in an access list; first match is sufficient.
    access
        .users
        .iter()
        .find(|(u, _)| *u == user)
        .map(|(_, hash)| crate::infra::nginx::verify_htpasswd_hash(hash, &pass))
        .unwrap_or(false)
}

/// Extract `(username, password)` from an `Authorization: Basic <b64>` header.
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    // The scheme token is case-insensitive per RFC 7617; the credentials follow.
    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let b64 = parts.next()?.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    // Split on the FIRST colon only: passwords may legitimately contain colons.
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Attach security/extra response headers (HSTS on TLS, allowlisted add_headers).
///
/// HSTS is only emitted over TLS — advertising it on a plain-HTTP response is
/// meaningless and (per the spec) must be ignored by clients anyway. We never
/// clobber a header a handler already set: the proxied upstream or static
/// handler is authoritative for anything it chose to emit.
pub(crate) fn decorate(resp: &mut Resp, route: &ServerRoute, tls: bool) {
    let headers = resp.headers_mut();

    if tls {
        if let Some(hsts) = &route.hsts {
            if !headers.contains_key(header::STRICT_TRANSPORT_SECURITY) {
                if let Ok(v) = HeaderValue::from_str(&hsts.header_value()) {
                    headers.insert(header::STRICT_TRANSPORT_SECURITY, v);
                }
            }
        }
    }

    // Allowlisted `add_header` directives parsed from the site's extra config.
    // Skip any name/value that can't form a valid header, and don't duplicate a
    // header already present on the response.
    for (name, value) in &route.extra_headers {
        let Ok(hname) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        if headers.contains_key(&hname) {
            continue;
        }
        let Ok(hvalue) = HeaderValue::from_str(value) else {
            continue;
        };
        headers.insert(hname, hvalue);
    }
}
