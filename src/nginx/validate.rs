//! Pure input validators for the Nginx module. No I/O, no parent types — just
//! string/number checks that gate user input before it reaches a config file
//! or a shell-free command. Kept together so the rules are easy to audit.

/// A cert name: a single filesystem-safe token (letters/digits/_-.), 1..=64.
pub(super) fn valid_cert_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Validate an access-list display name (1..=64, no control chars / quotes).
pub(super) fn valid_access_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.chars().count() <= 64
        && !s.chars().any(|c| c.is_control() || c == '"' || c == '\\')
}

/// Validate a basic-auth username (no ':' — the htpasswd field separator).
pub(super) fn valid_auth_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@'))
}

/// Validate a client address for allow/deny: "all", or an IPv4/IPv6/CIDR token.
pub(super) fn valid_client_address(s: &str) -> bool {
    let s = s.trim();
    if s.eq_ignore_ascii_case("all") {
        return true;
    }
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
}

/// A server_name: one or more space-free hostnames (letters/digits/.-/* and _).
/// Wildcards (`*.example.com`) and `_` (catch-all) are allowed.
pub(super) fn valid_server_name(s: &str) -> bool {
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
pub(super) fn primary_host(server_name: &str) -> String {
    server_name
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// A proxy target host[:port] or container name — no scheme, no path, no shell
/// metacharacters. We build the final `http://host:port` ourselves.
pub(super) fn valid_host_token(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 255
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// A container name (docker's own charset).
pub(super) fn valid_container_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A static webroot subdirectory name (single path segment, no separators).
pub(super) fn valid_root_segment(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && s != "."
        && s != ".."
}

pub(super) fn valid_port(p: i64) -> bool {
    (1..=65535).contains(&p)
}

/// Normalize an upstream scheme to "http" or "https" (default http).
pub(super) fn norm_scheme(s: Option<&str>) -> String {
    match s.map(str::trim) {
        Some("https") => "https".to_string(),
        _ => "http".to_string(),
    }
}

/// A location prefix: starts with '/', no spaces or shell metacharacters, and
/// stays within a sane length. We embed it literally into a `location` block.
pub(super) fn valid_location_path(s: &str) -> bool {
    let s = s.trim();
    s.starts_with('/')
        && s.len() <= 200
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~' | ':' | '@')
        })
}

/// Validate a redirect target URL (http/https, no quotes/whitespace/newlines).
pub(super) fn valid_redirect_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2048
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\\')
}

/// Validate a size value like "1m", "512k", "0" (bytes default). Bounded.
pub(super) fn valid_size_value(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty() && s.len() <= 12 && {
        let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
        !num.is_empty()
            && num.chars().all(|c| c.is_ascii_digit())
            && matches!(unit, "" | "k" | "K" | "m" | "M" | "g" | "G")
    }
}
