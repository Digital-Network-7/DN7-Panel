//! Input validators for container creation (split from docker.rs).
use super::*;

// ---------------------------------------------------------------------------
// Detached create container
// ---------------------------------------------------------------------------

/// Trim an optional string and drop it when empty.
pub(crate) fn opt_trim(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Validate an IPv4 dotted-quad address (no port, no CIDR suffix).
pub(crate) fn valid_ipv4(s: &str) -> Result<()> {
    let ok = s.parse::<std::net::Ipv4Addr>().is_ok();
    if !ok {
        return Err(docker_err(DockerError::BadIpv4));
    }
    Ok(())
}

/// Validate an IPv4 CIDR block like `172.20.0.0/16`.
pub(crate) fn valid_cidr(s: &str) -> Result<()> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| docker_err(DockerError::BadCidr))?;
    if addr.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(docker_err(DockerError::BadCidr));
    }
    match prefix.parse::<u8>() {
        Ok(p) if p <= 32 => Ok(()),
        _ => Err(docker_err(DockerError::BadCidr)),
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
        return Err(docker_err(DockerError::BadMac));
    }
    Ok(())
}

/// Validate a hostname / domainname label set per RFC 1123 (letters, digits,
/// hyphen, dots between labels; max 253 chars).
pub(crate) fn valid_hostname(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 253 {
        return Err(docker_err(DockerError::BadHostname));
    }
    let ok = s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !ok {
        return Err(docker_err(DockerError::BadHostname));
    }
    Ok(())
}

/// Validate a container name: docker allows [a-zA-Z0-9][a-zA-Z0-9_.-]+.
pub(crate) fn validate_name(s: &str) -> Result<()> {
    if s.len() > 128 {
        return Err(docker_err(DockerError::NameTooLong));
    }
    let ok = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !ok || s.starts_with('-') {
        return Err(docker_err(DockerError::BadName));
    }
    Ok(())
}

/// Validate a host filesystem path (no shell metacharacters; must be absolute).
pub(crate) fn validate_path(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 1024 || !s.starts_with('/') {
        return Err(docker_err(DockerError::PathNotAbsolute));
    }
    // Disallow characters that could break out of a single argv entry or look
    // like injection; container/host paths in practice don't need them. `:` , `,`
    // and whitespace are also rejected: a path is fed into the daemon bind string
    // `src:dst[:opts]`, so a `:`/`,` in either field would smuggle extra mount
    // options (rw, propagation rshared, SELinux relabel z/Z) the UI never offered.
    let bad = s.chars().any(|c| {
        matches!(
            c,
            ';' | '|'
                | '&'
                | '$'
                | '`'
                | '\n'
                | '\r'
                | '"'
                | '\''
                | '\\'
                | '<'
                | '>'
                | '*'
                | ':'
                | ','
                | ' '
                | '\t'
        )
    });
    if bad {
        return Err(docker_err(DockerError::PathBadChars));
    }
    // Reject any `..` component so a container-destination or bind path can't
    // traverse out of the container rootfs / an allowed bind subtree. The
    // absolute-path prefix above doesn't stop `/data/../../etc`.
    if std::path::Path::new(s)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(docker_err(DockerError::PathBadChars));
    }
    Ok(())
}

/// Validate an absolute host path used as a bind-mount SOURCE — for a container
/// volume OR a host-path-backed `local`/bind named volume. Both end up as a real
/// bind mount the daemon resolves, so this is the single host-compromise gate:
/// bad-char check, the lexical deny-list (docker socket, `/`, `/etc`, `/root`,
/// kernel pseudo-fs, …), and a symlink re-check (canonicalize → deny-list) so a
/// host symlink under an allowed path can't mount a denied target. Factored out
/// of `spec_binds` so the container-create and volume-create paths share ONE
/// gate and can't drift — a named volume hides its host path from `spec_binds`,
/// so the deny-list MUST also run at volume-create time.
pub(crate) fn validate_bind_source(host: &str) -> Result<()> {
    validate_path(host)?;
    if crate::core::docker::host_bind_denied(host) {
        return Err(docker_err(DockerError::BindHostPathDenied));
    }
    if let Ok(canon) = std::fs::canonicalize(host) {
        if crate::core::docker::host_bind_denied(&canon.to_string_lossy()) {
            return Err(docker_err(DockerError::BindHostPathDenied));
        }
    }
    Ok(())
}

/// Validate an env var entry "KEY=VALUE". KEY must be a valid identifier; VALUE
/// is taken verbatim (it's a separate argv entry, so no shell interpretation),
/// but we still reject newlines.
pub(crate) fn validate_env(s: &str) -> Result<()> {
    if s.len() > 4096 {
        return Err(docker_err(DockerError::EnvTooLong));
    }
    let (k, _v) = s
        .split_once('=')
        .ok_or_else(|| docker_err(DockerError::EnvFormat))?;
    if k.is_empty() {
        return Err(docker_err(DockerError::EnvNameEmpty));
    }
    let key_ok = k
        .chars()
        .enumerate()
        .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
    if !key_ok {
        return Err(docker_err(DockerError::EnvNameRules));
    }
    if s.contains('\n') || s.contains('\r') {
        return Err(docker_err(DockerError::EnvBadChars));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_source_rejects_host_compromise_paths() {
        // The deny-list (lexical, incl. `//`/`/.` normalization) applies to the
        // bind/volume SOURCE — these must be rejected on BOTH container-create and
        // volume-create paths via this one gate.
        for p in [
            "/",
            "/etc",
            "/etc/shadow",
            "/root/.ssh",
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/proc/1/mem",
            "//etc/./shadow",
        ] {
            assert!(validate_bind_source(p).is_err(), "{p} must be denied");
        }
        // Bad chars / non-absolute are rejected before the deny-list.
        assert!(validate_bind_source("/srv:data").is_err());
        assert!(validate_bind_source("relative/path").is_err());
        // A benign, non-existent absolute path passes (canonicalize skipped on ENOENT).
        assert!(validate_bind_source("/srv/dn7-nonexistent-bindsrc-test").is_ok());
    }

    #[test]
    fn path_rejects_parent_dir_traversal() {
        // `..` in either a container destination or a host source could escape
        // the rootfs / an allowed bind subtree — reject every form.
        for p in ["/../etc/x", "/data/../../etc", "/a/b/../../../etc"] {
            assert!(validate_path(p).is_err(), "{p} must be rejected");
        }
        // Plain absolute paths still pass.
        assert!(validate_path("/data/foo").is_ok());
        assert!(validate_path("/var/lib/x").is_ok());
        // The existing bad-char / non-absolute checks still hold.
        assert!(validate_path("/srv:data").is_err());
        assert!(validate_path("relative/path").is_err());
    }
}
