//! Security-boundary configuration as an explicit policy object.
//!
//! The console's security posture is spread across a handful of `WebSettings`
//! fields (https, entry_path, allow_ips, session_timeout). Rather than have the
//! entry gate, cookie/HSTS headers and session layer each read and interpret
//! those raw fields, `SecurityPolicy` is a read-only view that exposes the
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

    /// Whether the console is served over HTTPS (drives Secure cookie + HSTS).
    pub(crate) fn https(&self) -> bool {
        self.s.https
    }

    /// The `; Secure` cookie-attribute suffix to append (empty over plain HTTP),
    /// so an entry token never rides a cleartext request once TLS is on.
    pub(crate) fn cookie_secure_attr(&self) -> &'static str {
        if self.s.https {
            "; Secure"
        } else {
            ""
        }
    }

    /// The configured safe-entry path (raw), used to match the request URI.
    pub(crate) fn entry_path(&self) -> String {
        self.s.entry_path.clone()
    }

    /// The safe-entry cookie token, or `None` when the gate is disabled
    /// (entry path is "/" or empty).
    pub(crate) fn entry_token(&self) -> Option<String> {
        let e = self.s.entry_path.trim();
        if e == "/" || e.is_empty() {
            None
        } else {
            Some(e.trim_start_matches('/').to_string())
        }
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
}

/// Whether `ip` is permitted by the authorized-IP allow list. Loopback is
/// always allowed (avoids locking the local operator out). Entries are exact
/// IPs or CIDR blocks (validated on save).
pub(crate) fn ip_in_allowlist(allow: &[String], ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    for entry in allow {
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

    fn settings_with(allow: &[&str], https: bool, entry: &str) -> WebSettings {
        serde_json::from_value(serde_json::json!({
            "port": 1080,
            "allow_ips": allow,
            "https": https,
            "entry_path": entry,
        }))
        .unwrap()
    }

    #[test]
    fn empty_allow_list_permits_any() {
        let s = settings_with(&[], false, "/");
        let p = pol(&s);
        assert!(!p.allow_list_active());
        assert!(p.ip_allowed("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn allow_list_matches_exact_and_cidr_and_loopback() {
        let s = settings_with(&["10.0.0.0/8", "203.0.113.5"], false, "/");
        let p = pol(&s);
        assert!(p.allow_list_active());
        assert!(p.ip_allowed("10.1.2.3".parse().unwrap())); // CIDR
        assert!(p.ip_allowed("203.0.113.5".parse().unwrap())); // exact
        assert!(p.ip_allowed("127.0.0.1".parse().unwrap())); // loopback always
        assert!(!p.ip_allowed("198.51.100.7".parse().unwrap())); // outside
    }

    #[test]
    fn cookie_secure_follows_https() {
        assert_eq!(
            pol(&settings_with(&[], true, "/")).cookie_secure_attr(),
            "; Secure"
        );
        assert_eq!(
            pol(&settings_with(&[], false, "/")).cookie_secure_attr(),
            ""
        );
    }

    #[test]
    fn entry_token_none_when_disabled() {
        assert_eq!(pol(&settings_with(&[], false, "/")).entry_token(), None);
        assert_eq!(pol(&settings_with(&[], false, "")).entry_token(), None);
        assert_eq!(
            pol(&settings_with(&[], false, "/s3cr3t")).entry_token(),
            Some("s3cr3t".to_string())
        );
    }
}
