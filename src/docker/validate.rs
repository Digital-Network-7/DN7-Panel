//! Input validators for container creation (split from docker.rs).
use super::*;

// ---------------------------------------------------------------------------
// Detached create container
// ---------------------------------------------------------------------------

/// Whitelisted restart policies.
pub(crate) fn restart_allowed(p: &str) -> bool {
    matches!(p, "no" | "unless-stopped" | "always")
}

/// Trim an optional string and drop it when empty.
pub(crate) fn opt_trim(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Whitelisted network drivers offered in the create-network dialog.
pub(crate) fn net_driver_allowed(d: &str) -> bool {
    matches!(
        d,
        "bridge" | "macvlan" | "ipvlan" | "overlay" | "host" | "none"
    )
}

/// Validate an IPv4 dotted-quad address (no port, no CIDR suffix).
pub(crate) fn valid_ipv4(s: &str) -> Result<()> {
    let ok = s.parse::<std::net::Ipv4Addr>().is_ok();
    if !ok {
        return Err(anyhow!("ERR_CODE:docker.bad_ipv4"));
    }
    Ok(())
}

/// Validate an IPv4 CIDR block like `172.20.0.0/16`.
pub(crate) fn valid_cidr(s: &str) -> Result<()> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_cidr"))?;
    if addr.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(anyhow!("ERR_CODE:docker.bad_cidr"));
    }
    match prefix.parse::<u8>() {
        Ok(p) if p <= 32 => Ok(()),
        _ => Err(anyhow!("ERR_CODE:docker.bad_cidr")),
    }
}

/// Validate a MAC address: six colon-separated hex octets, e.g. `02:42:ac:11:00:02`.
pub(crate) fn valid_mac(s: &str) -> Result<()> {
    let parts: Vec<&str> = s.split(':').collect();
    let ok = parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()));
    if !ok {
        return Err(anyhow!("ERR_CODE:docker.bad_mac"));
    }
    Ok(())
}

/// Validate a hostname / domainname label set per RFC 1123 (letters, digits,
/// hyphen, dots between labels; max 253 chars).
pub(crate) fn valid_hostname(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 253 {
        return Err(anyhow!("ERR_CODE:docker.bad_hostname"));
    }
    let ok = s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !ok {
        return Err(anyhow!("ERR_CODE:docker.bad_hostname"));
    }
    Ok(())
}

/// Validate a container name: docker allows [a-zA-Z0-9][a-zA-Z0-9_.-]+.
pub(crate) fn validate_name(s: &str) -> Result<()> {
    if s.len() > 128 {
        return Err(anyhow!("ERR_CODE:docker.name_too_long"));
    }
    let ok = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !ok || s.starts_with('-') {
        return Err(anyhow!("ERR_CODE:docker.bad_name"));
    }
    Ok(())
}

/// Validate a host filesystem path (no shell metacharacters; must be absolute).
pub(crate) fn validate_path(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 1024 || !s.starts_with('/') {
        return Err(anyhow!("ERR_CODE:docker.path_not_absolute"));
    }
    // Disallow characters that could break out of a single argv entry or look
    // like injection; container/host paths in practice don't need them.
    let bad = s.chars().any(|c| {
        matches!(
            c,
            ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '"' | '\'' | '\\' | '<' | '>' | '*'
        )
    });
    if bad {
        return Err(anyhow!("ERR_CODE:docker.path_bad_chars"));
    }
    Ok(())
}

/// Validate an env var entry "KEY=VALUE". KEY must be a valid identifier; VALUE
/// is taken verbatim (it's a separate argv entry, so no shell interpretation),
/// but we still reject newlines.
pub(crate) fn validate_env(s: &str) -> Result<()> {
    if s.len() > 4096 {
        return Err(anyhow!("ERR_CODE:docker.env_too_long"));
    }
    let (k, _v) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("ERR_CODE:docker.env_format"))?;
    if k.is_empty() {
        return Err(anyhow!("ERR_CODE:docker.env_name_empty"));
    }
    let key_ok = k
        .chars()
        .enumerate()
        .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
    if !key_ok {
        return Err(anyhow!("ERR_CODE:docker.env_name_rules"));
    }
    if s.contains('\n') || s.contains('\r') {
        return Err(anyhow!("ERR_CODE:docker.env_bad_chars"));
    }
    Ok(())
}
