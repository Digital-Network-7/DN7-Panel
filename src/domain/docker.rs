//! Docker domain rules: the policy whitelists for container/network creation.
//! Pure (no I/O, no transport). The format validators that surface stable
//! `ERR_CODE:` messages stay in `docker::validate` (transport-coupled) until the
//! capability adopts a typed command model.

/// Whitelisted container restart policies.
pub(crate) fn restart_allowed(p: &str) -> bool {
    matches!(p, "no" | "unless-stopped" | "always")
}

/// Whitelisted network drivers offered in the create-network dialog.
pub(crate) fn net_driver_allowed(d: &str) -> bool {
    matches!(
        d,
        "bridge" | "macvlan" | "ipvlan" | "overlay" | "host" | "none"
    )
}

/// Host-path bind-mount deny-list. A bind mount of any of these onto a
/// container is a direct host-compromise primitive (the docker socket grants
/// host-root; `/etc`/`/root` hold credentials; the kernel pseudo-filesystems
/// expose the host). We reject the path itself **and any descendant** of the
/// sensitive trees so a `/etc/shadow` or `/root/.ssh` mount can't slip through.
/// Pure (no I/O) so it's unit-testable and lives with the other create policies.
pub(crate) fn host_bind_denied(path: &str) -> bool {
    // Normalize a trailing slash; keep root as "/".
    let p = path.trim_end_matches('/');
    let p = if p.is_empty() { "/" } else { p };
    // The docker socket = instant host-root escape (not under a denied tree).
    if matches!(p, "/var/run/docker.sock" | "/run/docker.sock") {
        return true;
    }
    if p == "/" {
        return true;
    }
    const TREES: &[&str] = &["/etc", "/root", "/boot", "/proc", "/sys", "/dev"];
    TREES
        .iter()
        .any(|t| p == *t || p.starts_with(&format!("{t}/")))
}

/// Whether a container network mode shares another namespace's network stack in
/// a way that bypasses container isolation. `host` shares the host's network
/// namespace (can bind host ports / sniff host traffic); `container:<id>` joins
/// another container's. Both are gated to the super-admin; `bridge`/`none`/a
/// named user network are isolated and allowed for any admin.
pub(crate) fn network_mode_privileged(mode: &str) -> bool {
    mode == "host" || mode.starts_with("container:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelists() {
        assert!(restart_allowed("always"));
        assert!(!restart_allowed("on-failure"));
        assert!(net_driver_allowed("bridge"));
        assert!(!net_driver_allowed("weave"));
    }

    #[test]
    fn bind_deny_list() {
        // Docker socket and root are always denied.
        assert!(host_bind_denied("/var/run/docker.sock"));
        assert!(host_bind_denied("/run/docker.sock"));
        assert!(host_bind_denied("/"));
        // Sensitive trees and their descendants.
        assert!(host_bind_denied("/etc"));
        assert!(host_bind_denied("/etc/shadow"));
        assert!(host_bind_denied("/root/.ssh"));
        assert!(host_bind_denied("/proc/sys"));
        assert!(host_bind_denied("/sys/"));
        assert!(host_bind_denied("/dev/sda"));
        // Ordinary data paths are allowed.
        assert!(!host_bind_denied("/opt/data"));
        assert!(!host_bind_denied("/home/app/files"));
        assert!(!host_bind_denied("/var/lib/myapp"));
        assert!(!host_bind_denied("/etcd")); // not under /etc
    }

    #[test]
    fn host_network_is_privileged() {
        assert!(network_mode_privileged("host"));
        assert!(network_mode_privileged("container:abc"));
        assert!(!network_mode_privileged("bridge"));
        assert!(!network_mode_privileged("none"));
        assert!(!network_mode_privileged("my-net"));
    }
}
