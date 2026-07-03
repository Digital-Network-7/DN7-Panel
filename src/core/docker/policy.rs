//! Docker domain rules: the policy whitelists for container/network creation.
//! Pure (no I/O, no transport). The format validators that surface stable
//! `ERR_CODE:` messages stay in `docker::validate` (transport-coupled) until the
//! capability adopts a typed command model.

/// A Docker capability error — a typed, exhaustive replacement for the scattered
/// `anyhow!("ERR_CODE:docker.*")` string literals. Each variant owns its stable
/// `docker.*` semantic code (aligned with the frontend `err.<code>` map) in one
/// place. Domain owns only the semantic code; the `ERR_CODE:` transport marker
/// the `op_err_body` boundary parses is added in infra (per §2/§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DockerError {
    BackupBadConfig,
    BackupMissing,
    BadBackup,
    BadCidr,
    BadCpuFormat,
    BadHostname,
    BadIpv4,
    BadMac,
    BadMemFormat,
    BadMirror,
    BadName,
    BadNetDriver,
    BadProto,
    BadRef,
    BadRegistry,
    BadRestartPolicy,
    BadTag,
    BindHostPathDenied,
    CmdNoNewline,
    CmdTooManyArgs,
    CmdUnclosedQuote,
    CpuOutOfRange,
    CpuSharesRange,
    EnvBadChars,
    EnvFormat,
    EnvNameEmpty,
    EnvNameRules,
    EnvTooLong,
    HostNetworkRequiresSuper,
    ImportNoImage,
    MemOverHost,
    MemTooSmall,
    MissingImageName,
    MissingName,
    MissingNetworkName,
    MissingRef,
    MissingVolumeName,
    NameTooLong,
    NetPredefinedIp,
    NetRangeNeedsSubnet,
    NetworkInUse,
    NetworkPredefined,
    NoStats,
    PathBadChars,
    PathNotAbsolute,
    PortRange,
    PrivilegedRequiresSuper,
    PullIncomplete,
    TagEmpty,
    TooManyDns,
    TooManyEnvs,
    TooManyMounts,
    TooManyNetworks,
    TooManyPorts,
    TooManyTags,
    VolumeInUse,
    VolumeManaged,
}

impl DockerError {
    /// The stable, `docker.`-namespaced semantic code (no transport prefix).
    pub(crate) fn code(self) -> &'static str {
        use DockerError::*;
        match self {
            BackupBadConfig => "docker.backup_bad_config",
            BackupMissing => "docker.backup_missing",
            BadBackup => "docker.bad_backup",
            BadCidr => "docker.bad_cidr",
            BadCpuFormat => "docker.bad_cpu_format",
            BadHostname => "docker.bad_hostname",
            BadIpv4 => "docker.bad_ipv4",
            BadMac => "docker.bad_mac",
            BadMemFormat => "docker.bad_mem_format",
            BadMirror => "docker.bad_mirror",
            BadName => "docker.bad_name",
            BadNetDriver => "docker.bad_net_driver",
            BadProto => "docker.bad_proto",
            BadRef => "docker.bad_ref",
            BadRegistry => "docker.bad_registry",
            BadRestartPolicy => "docker.bad_restart_policy",
            BadTag => "docker.bad_tag",
            BindHostPathDenied => "docker.bind_host_path_denied",
            CmdNoNewline => "docker.cmd_no_newline",
            CmdTooManyArgs => "docker.cmd_too_many_args",
            CmdUnclosedQuote => "docker.cmd_unclosed_quote",
            CpuOutOfRange => "docker.cpu_out_of_range",
            CpuSharesRange => "docker.cpu_shares_range",
            EnvBadChars => "docker.env_bad_chars",
            EnvFormat => "docker.env_format",
            EnvNameEmpty => "docker.env_name_empty",
            EnvNameRules => "docker.env_name_rules",
            EnvTooLong => "docker.env_too_long",
            HostNetworkRequiresSuper => "docker.host_network_requires_super",
            ImportNoImage => "docker.import_no_image",
            MemOverHost => "docker.mem_over_host",
            MemTooSmall => "docker.mem_too_small",
            MissingImageName => "docker.missing_image_name",
            MissingName => "docker.missing_name",
            MissingNetworkName => "docker.missing_network_name",
            MissingRef => "docker.missing_ref",
            MissingVolumeName => "docker.missing_volume_name",
            NameTooLong => "docker.name_too_long",
            NetPredefinedIp => "docker.net_predefined_ip",
            NetRangeNeedsSubnet => "docker.net_range_needs_subnet",
            NetworkInUse => "docker.network_in_use",
            NetworkPredefined => "docker.network_predefined",
            NoStats => "docker.no_stats",
            PathBadChars => "docker.path_bad_chars",
            PathNotAbsolute => "docker.path_not_absolute",
            PortRange => "docker.port_range",
            PrivilegedRequiresSuper => "docker.privileged_requires_super",
            PullIncomplete => "docker.pull_incomplete",
            TagEmpty => "docker.tag_empty",
            TooManyDns => "docker.too_many_dns",
            TooManyEnvs => "docker.too_many_envs",
            TooManyMounts => "docker.too_many_mounts",
            TooManyNetworks => "docker.too_many_networks",
            TooManyPorts => "docker.too_many_ports",
            TooManyTags => "docker.too_many_tags",
            VolumeInUse => "docker.volume_in_use",
            VolumeManaged => "docker.volume_managed",
        }
    }
}

impl std::fmt::Display for DockerError {
    /// Renders the semantic code only; the infra boundary adds the `ERR_CODE:`
    /// marker when building the wire error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DockerError {}

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
    // Normalize FIRST: the daemon resolves `//`, `/./`, `/..` before mounting,
    // so a raw prefix match is trivially bypassed (e.g. `//var/run/docker.sock`,
    // `/srv/../etc/shadow`). Collapse to the canonical path the daemon will use.
    let p = crate::core::path::normalize_lexical(path);
    let p = p.as_str();
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

/// A host-escape capability a container-create request asked for. Both forms
/// grant effective host access, so both are reserved to the super-admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreateEscalation {
    /// `privileged: true` — full host device + capability access.
    Privileged,
    /// `--network host` / `container:<id>` — shares a host/peer network stack.
    HostNetwork,
}

/// The pure create-authorization rule: given whether the request asked for
/// privileged mode and the set of requested network modes, return the
/// host-escape capability it needs (if any). A request that needs an escalation
/// is allowed only for the super-admin — the *decision* (who may do it) belongs
/// to the app layer; this is just the rule (what counts as an escalation).
/// `privileged` is checked first so the message names the strongest signal.
pub(crate) fn create_escalation<'a>(
    privileged: bool,
    network_modes: impl Iterator<Item = &'a str>,
) -> Option<CreateEscalation> {
    if privileged {
        return Some(CreateEscalation::Privileged);
    }
    if network_modes.map(str::trim).any(network_mode_privileged) {
        return Some(CreateEscalation::HostNetwork);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_error_codes_namespaced_and_wire_stable() {
        // Representative codes match the exact frontend `err.*` strings, incl.
        // the two host-escape codes the create guardrail (A2) returns.
        assert_eq!(DockerError::BadName.code(), "docker.bad_name");
        assert_eq!(
            DockerError::PrivilegedRequiresSuper.code(),
            "docker.privileged_requires_super"
        );
        assert_eq!(
            DockerError::HostNetworkRequiresSuper.code(),
            "docker.host_network_requires_super"
        );
        // Display is the semantic code only (no transport prefix in domain).
        assert_eq!(DockerError::PortRange.to_string(), "docker.port_range");
        // Spot-check namespacing/charset on a spread of variants.
        for e in [
            DockerError::BackupBadConfig,
            DockerError::BadIpv4,
            DockerError::EnvNameRules,
            DockerError::TooManyPorts,
            DockerError::VolumeManaged,
        ] {
            let c = e.code();
            assert!(c.starts_with("docker."), "{c} not namespaced");
            assert!(
                c[7..]
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
                "{c} not snake_case"
            );
        }
    }

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
    fn bind_deny_resists_non_normalized_bypass() {
        // The daemon resolves these to a sensitive target before mounting; the
        // guard must too (regression: raw prefix-match let them through).
        assert!(host_bind_denied("//var/run/docker.sock"));
        assert!(host_bind_denied("/var/run/../run/docker.sock"));
        assert!(host_bind_denied("/./etc/shadow"));
        assert!(host_bind_denied("//etc/shadow"));
        assert!(host_bind_denied("/srv/../etc/shadow"));
        assert!(host_bind_denied("/opt/../../root/.ssh"));
        assert!(host_bind_denied("/etc/")); // trailing slash
        assert!(host_bind_denied("/etc/./ssh"));
        // Still allows legit paths after normalization.
        assert!(!host_bind_denied("/opt/../opt/data"));
        assert!(!host_bind_denied("/srv/./www"));
    }

    #[test]
    fn host_network_is_privileged() {
        assert!(network_mode_privileged("host"));
        assert!(network_mode_privileged("container:abc"));
        assert!(!network_mode_privileged("bridge"));
        assert!(!network_mode_privileged("none"));
        assert!(!network_mode_privileged("my-net"));
    }

    #[test]
    fn create_escalation_rule() {
        // No escalation: not privileged, only isolated networks.
        assert_eq!(
            create_escalation(false, ["bridge", "my-net"].into_iter()),
            None
        );
        // Privileged wins (named first).
        assert_eq!(
            create_escalation(true, ["bridge"].into_iter()),
            Some(CreateEscalation::Privileged)
        );
        // Host/container network namespace triggers HostNetwork.
        assert_eq!(
            create_escalation(false, ["host"].into_iter()),
            Some(CreateEscalation::HostNetwork)
        );
        assert_eq!(
            create_escalation(false, ["bridge", "container:abc"].into_iter()),
            Some(CreateEscalation::HostNetwork)
        );
        // Whitespace is trimmed before the check.
        assert_eq!(
            create_escalation(false, [" host "].into_iter()),
            Some(CreateEscalation::HostNetwork)
        );
    }
}
