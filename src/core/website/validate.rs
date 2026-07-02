//! Pure input validators for the Nginx domain. No I/O, no parent types — just
//! string/number checks that gate user input before it reaches a config file
//! or a shell-free command. Kept together so the rules are easy to audit.

/// Normalize a requested cert key type to a supported value. Empty / unknown →
/// "" (the default, ECDSA P-256); the only non-default is "ecdsa-p384". Callers
/// persist the result and map it to an rcgen algorithm at generation time.
pub(crate) fn norm_key_type(s: &str) -> String {
    match s.trim() {
        "ecdsa-p384" => "ecdsa-p384".to_string(),
        "ecdsa-p256" => "ecdsa-p256".to_string(),
        _ => String::new(),
    }
}

/// A cert name: a single filesystem-safe token (letters/digits/_-.), 1..=64.
pub(crate) fn valid_cert_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Validate an access-list display name (1..=64, no control chars / quotes).
pub(crate) fn valid_access_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.chars().count() <= 64
        && !s.chars().any(|c| c.is_control() || c == '"' || c == '\\')
}

/// Validate a basic-auth username (no ':' — the htpasswd field separator).
pub(crate) fn valid_auth_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@'))
}

/// Validate a client address for allow/deny. Accepts ONLY the exact token
/// `all`, a bare IPv4/IPv6 literal, or an IPv4/IPv6 CIDR — mirroring the edge's
/// runtime `parse_acl_net` (`build.rs`) so any value that passes here is one the
/// edge can actually match, and everything else (`999.999.999.999`, a malformed
/// prefix, `deny ` with a stray space, …) is rejected at SAVE time.
pub(crate) fn valid_client_address(s: &str) -> bool {
    use std::net::IpAddr;
    let s = s.trim();
    if s == "all" {
        return true;
    }
    if s.contains('/') {
        return valid_cidr(s);
    }
    s.parse::<IpAddr>().is_ok()
}

/// Whether `s` is a valid `addr/prefix` CIDR, matching `ipnet`'s acceptance:
/// the address parses as IPv4/IPv6 and the prefix length is in range for the
/// family (0..=32 for v4, 0..=128 for v6). Host bits are not required to be zero
/// (the edge stores the pair as-is), but exactly one `/` and a numeric prefix
/// are required.
fn valid_cidr(s: &str) -> bool {
    use std::net::IpAddr;
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    if prefix.contains('/') {
        return false; // more than one '/'
    }
    let Ok(len) = prefix.parse::<u8>() else {
        return false;
    };
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => len <= 32,
        Ok(IpAddr::V6(_)) => len <= 128,
        Err(_) => false,
    }
}

/// A server_name: one or more space-free hostnames (letters/digits/.-/* and _).
/// Wildcards (`*.example.com`) and `_` (catch-all) are allowed.
pub(crate) fn valid_server_name(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    s.split_whitespace().all(|h| {
        !h.is_empty()
            && h.len() <= 253
            && h.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | '_'))
    })
}

/// The first hostname of a server_name (used for cert CN / acme domain).
pub(crate) fn primary_host(server_name: &str) -> String {
    server_name
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// A proxy target host[:port] or container name — no scheme, no path, no shell
/// metacharacters. We build the final `http://host:port` ourselves. Brackets are
/// allowed so the canonical IPv6 authority form (`[2001:db8::2]:8443`) passes and
/// reaches the edge builder, which is written to preserve it.
pub(crate) fn valid_host_token(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 255
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
}

/// A container name (docker's own charset).
pub(crate) fn valid_container_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A static webroot subdirectory name (single path segment, no separators).
pub(crate) fn valid_root_segment(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && s != "."
        && s != ".."
}

pub(crate) fn valid_port(p: i64) -> bool {
    (1..=65535).contains(&p)
}

/// Normalize an upstream scheme to "http" or "https" (default http).
pub(crate) fn norm_scheme(s: Option<&str>) -> String {
    match s.map(str::trim) {
        Some("https") => "https".to_string(),
        _ => "http".to_string(),
    }
}

/// A location prefix: starts with '/', no spaces or shell metacharacters, and
/// stays within a sane length. We embed it literally into a `location` block.
pub(crate) fn valid_location_path(s: &str) -> bool {
    let s = s.trim();
    s.starts_with('/')
        && s.len() <= 200
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~' | ':' | '@')
        })
}

/// Validate a redirect target URL (http/https, no quotes/whitespace/newlines).
pub(crate) fn valid_redirect_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2048
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\\')
}

/// Validate a size value like "1m", "512k", "0" (bytes default). Bounded.
pub(crate) fn valid_size_value(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty() && s.len() <= 12 && {
        let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
        !num.is_empty()
            && num.chars().all(|c| c.is_ascii_digit())
            && matches!(unit, "" | "k" | "K" | "m" | "M" | "g" | "G")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Most validators are also exercised from the infra website tests; these keep
    // domain-local coverage with the rule, and cover the two that had none
    // (`valid_size_value`, `norm_scheme`).

    #[test]
    fn size_value_accepts_bounded_units_only() {
        assert!(valid_size_value("0"));
        assert!(valid_size_value("1m"));
        assert!(valid_size_value("512k"));
        assert!(valid_size_value("2G"));
        assert!(valid_size_value(" 100M ")); // trimmed
                                             // No digits, bad unit, empty, oversized, or injection attempts.
        assert!(!valid_size_value(""));
        assert!(!valid_size_value("m"));
        assert!(!valid_size_value("50x"));
        assert!(!valid_size_value("1mb")); // multi-char unit
        assert!(!valid_size_value("1.5m")); // no decimals
        assert!(!valid_size_value("10 m")); // inner space
        assert!(!valid_size_value("999999999999m")); // > 12 chars
        assert!(!valid_size_value("1m;rm")); // metacharacters
    }

    #[test]
    fn norm_scheme_only_https_or_http() {
        assert_eq!(norm_scheme(Some("https")), "https");
        assert_eq!(norm_scheme(Some(" https ")), "https"); // trimmed
        assert_eq!(norm_scheme(Some("http")), "http");
        assert_eq!(norm_scheme(Some("HTTPS")), "http"); // case-sensitive → default
        assert_eq!(norm_scheme(Some("ftp")), "http");
        assert_eq!(norm_scheme(None), "http");
    }

    #[test]
    fn location_path_must_be_rooted_and_clean() {
        assert!(valid_location_path("/"));
        assert!(valid_location_path("/api/v1"));
        assert!(!valid_location_path("api")); // not rooted
        assert!(!valid_location_path("/a b")); // space
        assert!(!valid_location_path("/a;b")); // metacharacter
    }

    #[test]
    fn redirect_url_http_only_no_whitespace() {
        assert!(valid_redirect_url("https://example.com/x"));
        assert!(valid_redirect_url("http://a.test"));
        assert!(!valid_redirect_url("ftp://x"));
        assert!(!valid_redirect_url("https://a b.com"));
        assert!(!valid_redirect_url("javascript:alert(1)"));
    }

    #[test]
    fn client_address_accepts_all_ip_and_cidr_only() {
        // The exact keyword, bare IPs, and well-formed CIDRs are accepted.
        assert!(valid_client_address("all"));
        assert!(valid_client_address(" all ")); // trimmed
        assert!(valid_client_address("1.2.3.4"));
        assert!(valid_client_address("10.0.0.0/8"));
        assert!(valid_client_address("192.168.0.0/16"));
        assert!(valid_client_address("::1"));
        assert!(valid_client_address("2001:db8::/32"));
        assert!(valid_client_address("0.0.0.0/0"));

        // Rejected: not a real IP, malformed / out-of-range CIDR, wrong keyword,
        // stray whitespace inside, or a smuggled directive.
        assert!(!valid_client_address(""));
        assert!(!valid_client_address("ALL")); // must be the exact lower-case token
        assert!(!valid_client_address("999.999.999.999"));
        assert!(!valid_client_address("1.2.3.4/33")); // v4 prefix > 32
        assert!(!valid_client_address("2001:db8::/129")); // v6 prefix > 128
        assert!(!valid_client_address("10.0.0.0/")); // empty prefix
        assert!(!valid_client_address("10.0.0.0/x")); // non-numeric prefix
        assert!(!valid_client_address("10.0.0.0/8/8")); // more than one '/'
        assert!(valid_client_address("1.2.3.4 ")); // trailing space trims to a valid IP
        assert!(!valid_client_address("1.2.3. 4")); // inner space breaks parse
        assert!(!valid_client_address("deny 1.2.3.4")); // directive smuggled in
        assert!(!valid_client_address("nope"));
    }
}
