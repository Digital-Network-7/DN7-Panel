//! Security-boundary configuration as an explicit policy object.
//!
//! The console's security posture is spread across a handful of `WebSettings`
//! fields (initialized, init_token, allow_ips, trusted_proxies). Rather than have
//! the init gate, headers and session layer each read and interpret those raw
//! fields, `SecurityPolicy` is a read-only view that exposes the
//! *normalized decisions* they actually need — so the policy lives in one place
//! and stays testable.
use super::*;
use std::net::IpAddr;

/// A read-only view over the security-relevant parts of [`WebSettings`].
pub(crate) struct SecurityPolicy<'a> {
    s: &'a WebSettings,
}

impl<'a> SecurityPolicy<'a> {
    pub(crate) fn new(s: &'a WebSettings) -> Self {
        Self { s }
    }

    /// Whether first-run setup is complete. Before it is, the console serves the
    /// token-gated init wizard; after it, normal auth applies.
    pub(crate) fn initialized(&self) -> bool {
        self.s.initialized
    }

    /// Whether an authorized-IP allow list is configured. When it is, a request
    /// whose source IP can't be determined must fail closed.
    pub(crate) fn allow_list_active(&self) -> bool {
        !self.s.allow_ips.is_empty()
    }

    /// Whether `ip` is permitted. An empty allow list permits any address;
    /// loopback is always allowed (avoids locking the local operator out).
    pub(crate) fn ip_allowed(&self, ip: IpAddr) -> bool {
        if self.s.allow_ips.is_empty() {
            return true;
        }
        ip_in_allowlist(&self.s.allow_ips, ip)
    }

    /// Whether `peer` is a trusted front-proxy whose forwarded headers we honor.
    ///
    /// A **loopback** peer is always trusted: the recommended deployment binds
    /// the panel to localhost behind a same-host reverse proxy (nginx / SSH
    /// tunnel), so a request from 127.0.0.1 is that proxy (or another same-host
    /// process, which is already privileged on the box). Without this, every
    /// proxied request is attributed to 127.0.0.1 — losing the real client IP
    /// in the audit log and silently bypassing the IP allow list (loopback is
    /// always allowed). Non-loopback peers must be opted into explicitly so a
    /// direct remote client can't spoof `X-Forwarded-For`.
    pub(crate) fn trusts_proxy(&self, peer: IpAddr) -> bool {
        peer.is_loopback()
            || (!self.s.trusted_proxies.is_empty() && ip_in_cidrs(&self.s.trusted_proxies, peer))
    }
}

/// Resolve the effective client IP for rate-limiting / allow-list / audit.
/// When the direct TCP `peer` is trusted (a loopback same-host proxy, or a
/// configured front-proxy CIDR), take the rightmost `X-Forwarded-For` entry
/// (the address that proxy observed), falling back to `X-Real-IP`; otherwise
/// use `peer` itself. Forwarded headers are never read from an untrusted peer
/// (they're client-spoofable), so this can't be used to bypass the allow-list.
pub(crate) fn client_ip(
    peer: IpAddr,
    headers: &header::HeaderMap,
    policy: &SecurityPolicy,
) -> IpAddr {
    if policy.trusts_proxy(peer) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = xff
                .split(',')
                .map(str::trim)
                .rfind(|s| !s.is_empty())
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                return ip;
            }
        }
        // No usable X-Forwarded-For — fall back to X-Real-IP (set by nginx to
        // the immediate client `$remote_addr`).
        if let Some(real) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            return real;
        }
    }
    peer
}

/// Whether `ip` is permitted by the authorized-IP allow list. Loopback is
/// always allowed (avoids locking the local operator out). Entries are exact
/// IPs or CIDR blocks (validated on save).
pub(crate) fn ip_in_allowlist(allow: &[String], ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    ip_in_cidrs(allow, ip)
}

/// Whether `ip` matches any exact IP or CIDR block in `list`. No loopback
/// special-case (callers that want it, like the allow-list, add it themselves).
pub(crate) fn ip_in_cidrs(list: &[String], ip: IpAddr) -> bool {
    for entry in list {
        if let Some((a, p)) = entry.split_once('/') {
            if let (Ok(net), Ok(prefix)) = (a.parse::<IpAddr>(), p.parse::<u8>()) {
                if cidr_contains(net, prefix, ip) {
                    return true;
                }
            }
        } else if let Ok(a) = entry.parse::<IpAddr>() {
            if a == ip {
                return true;
            }
        }
    }
    false
}

/// Whether `ip` falls within the `net`/`prefix` CIDR block (v4 or v6).
pub(crate) fn cidr_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(settings: &WebSettings) -> SecurityPolicy<'_> {
        SecurityPolicy::new(settings)
    }

    fn settings_with(allow: &[&str]) -> WebSettings {
        serde_json::from_value(serde_json::json!({
            "port": 1080,
            "allow_ips": allow,
        }))
        .unwrap()
    }

    #[test]
    fn empty_allow_list_permits_any() {
        let s = settings_with(&[]);
        let p = pol(&s);
        assert!(!p.allow_list_active());
        assert!(p.ip_allowed("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn allow_list_matches_exact_and_cidr_and_loopback() {
        let s = settings_with(&["10.0.0.0/8", "203.0.113.5"]);
        let p = pol(&s);
        assert!(p.allow_list_active());
        assert!(p.ip_allowed("10.1.2.3".parse().unwrap())); // CIDR
        assert!(p.ip_allowed("203.0.113.5".parse().unwrap())); // exact
        assert!(p.ip_allowed("127.0.0.1".parse().unwrap())); // loopback always
        assert!(!p.ip_allowed("198.51.100.7".parse().unwrap())); // outside
    }

    #[test]
    fn initialized_state_reads_through() {
        let from = |v: serde_json::Value| -> WebSettings { serde_json::from_value(v).unwrap() };
        assert!(!pol(&from(serde_json::json!({ "port": 1080 }))).initialized());
        assert!(pol(&from(
            serde_json::json!({ "port": 1080, "initialized": true })
        ))
        .initialized());
    }

    #[test]
    fn client_ip_only_trusts_xff_from_configured_proxy() {
        use std::net::IpAddr;
        let mut s = settings_with(&[]);
        s.trusted_proxies = vec!["10.0.0.1".to_string()];
        let p = pol(&s);
        let mut h = header::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        let trusted: IpAddr = "10.0.0.1".parse().unwrap();
        let untrusted: IpAddr = "198.51.100.7".parse().unwrap();
        // From the trusted proxy: take the rightmost XFF entry.
        assert_eq!(
            client_ip(trusted, &h, &p),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        // From an untrusted peer: ignore XFF entirely (no spoofing).
        assert_eq!(client_ip(untrusted, &h, &p), untrusted);
    }

    #[test]
    fn no_trusted_proxies_never_reads_xff() {
        use std::net::IpAddr;
        let s = settings_with(&[]); // trusted_proxies empty
        let p = pol(&s);
        let mut h = header::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(client_ip(peer, &h, &p), peer);
    }

    #[test]
    fn loopback_proxy_is_trusted_and_resolves_real_client() {
        use std::net::IpAddr;
        let s = settings_with(&[]); // no explicit trusted proxies
        let p = pol(&s);
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        // A same-host (loopback) reverse proxy is trusted automatically, so the
        // real client IP is taken from the forwarded headers instead of 127.0.0.1.
        let mut xff = header::HeaderMap::new();
        xff.insert("x-forwarded-for", "175.161.169.65".parse().unwrap());
        assert_eq!(
            client_ip(lo, &xff, &p),
            "175.161.169.65".parse::<IpAddr>().unwrap()
        );
        // X-Real-IP is used when no X-Forwarded-For is present.
        let mut real = header::HeaderMap::new();
        real.insert("x-real-ip", "175.161.169.65".parse().unwrap());
        assert_eq!(
            client_ip(lo, &real, &p),
            "175.161.169.65".parse::<IpAddr>().unwrap()
        );
        // No forwarded headers (direct loopback, e.g. SSH tunnel) → stays loopback.
        assert_eq!(client_ip(lo, &header::HeaderMap::new(), &p), lo);
    }
}
