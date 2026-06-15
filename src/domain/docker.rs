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
}
