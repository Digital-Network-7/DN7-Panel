//! Translate an image's config (Entrypoint/Cmd/Env/WorkingDir/User) into an OCI
//! runtime `config.json` for the bundle, so a pulled image is directly runnable.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::image::manifest::ImageConfig;

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The runc/Docker default set of kernel paths masked from a container.
const MASKED_PATHS: &[&str] = &[
    "/proc/asound",
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

/// The runc/Docker default set of read-only kernel paths.
const READONLY_PATHS: &[&str] = &[
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

/// Dangerous syscalls blocked by the generated default seccomp profile (default
/// action: allow). A curated subset of what Docker blocks — the syscalls a normal
/// container never needs, several of which (mount/pivot_root/…) are also gated by
/// the dropped capabilities, so this is defense-in-depth. Names absent on an arch
/// are silently skipped.
const BLOCKED_SYSCALLS: &[&str] = &[
    // kernel modules / kexec / reboot
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    // swap + mount / namespace escapes
    "swapon",
    "swapoff",
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "move_mount",
    "open_tree",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    // fd-based path escapes
    "open_by_handle_at",
    "name_to_handle_at",
    // cross-process tracing / memory peeking
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    // perf + bpf
    "perf_event_open",
    "bpf",
    // clock / time tampering
    "settimeofday",
    "clock_settime",
    "adjtimex",
    "clock_adjtime",
    // accounting / quotas / keyring / legacy sysctl
    "acct",
    "quotactl",
    "nfsservctl",
    "add_key",
    "request_key",
    "keyctl",
    "_sysctl",
    // raw I/O ports
    "ioperm",
    "iopl",
    // NUMA memory policy
    "mbind",
    "set_mempolicy",
    "migrate_pages",
    "move_pages",
    "get_mempolicy",
    // misc privileged
    "fanotify_init",
    "lookup_dcookie",
];

/// Docker's default capability allowlist (notably *without* `CAP_SYS_ADMIN`,
/// `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, …). A root container gets exactly these.
const DEFAULT_CAPS: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

/// Options for assembling a bundle's `config.json` from an image config.
pub struct CreateOpts<'a> {
    /// Container hostname (uts namespace).
    pub hostname: &'a str,
    /// If non-empty, replaces the image's Entrypoint+Cmd entirely.
    pub cmd_override: &'a [String],
    /// `bridge` | `none` | `host` (annotation `dn7.net`).
    pub net_mode: &'a str,
    /// Published-port string (`[hostip:]hp:cp[/proto]` joined by `,`).
    pub ports: &'a str,
    /// Bind / named-volume mounts.
    pub volumes: &'a [crate::image::volume::VolumeMount],
    /// Extra `KEY=VALUE` env entries — a matching KEY overrides the image's.
    pub env_extra: &'a [String],
    /// `linux.resources.memory.limit` (bytes).
    pub mem_limit: Option<i64>,
    /// `linux.resources.cpu.{quota,period}` (µs) — the `--cpus` translation.
    pub cpu_quota: Option<(i64, u64)>,
    /// `linux.resources.cpu.shares` (v1 shares → v2 weight in the cgroup layer).
    pub cpu_shares: Option<u64>,
    /// `linux.resources.pids.limit`.
    pub pids_limit: Option<i64>,
    /// Allocate a controlling pseudo-terminal for the container's main process
    /// (docker `-t`). Sets OCI `process.terminal`; the parent hands the init a
    /// PTY slave as its console so an interactive shell (the image's default
    /// command) stays alive instead of hitting EOF on stdin and exiting at once.
    pub tty: bool,
    /// Static IPv4 on the primary network (`dn7.ip` annotation); `None` = auto.
    pub static_ip: Option<&'a str>,
}

impl<'a> CreateOpts<'a> {
    /// Minimal opts: hostname + net mode, no overrides or limits — the plain
    /// `run-image` case.
    pub fn new(hostname: &'a str, net_mode: &'a str) -> CreateOpts<'a> {
        CreateOpts {
            hostname,
            cmd_override: &[],
            net_mode,
            ports: "",
            volumes: &[],
            env_extra: &[],
            mem_limit: None,
            cpu_quota: None,
            cpu_shares: None,
            pids_limit: None,
            tty: false,
            static_ip: None,
        }
    }
}

/// Write `<bundle_dir>/config.json` from the image config + create options. A
/// non-empty `opts.cmd_override` replaces the image's Entrypoint+Cmd entirely.
pub fn write_config(bundle_dir: &Path, cfg: &ImageConfig, opts: &CreateOpts) -> Result<()> {
    let args = command(cfg, opts.cmd_override);
    if args.is_empty() {
        return Err(Error::Other(
            "image has no Entrypoint/Cmd and no command was given".into(),
        ));
    }

    // Image env first; user overrides replace a matching KEY; then a PATH default.
    let mut env = cfg.config.env.clone();
    for kv in opts.env_extra {
        let key_eq = match kv.split_once('=') {
            Some((k, _)) => format!("{k}="),
            None => format!("{kv}="),
        };
        env.retain(|e| !e.starts_with(&key_eq));
        env.push(kv.clone());
    }
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push(format!("PATH={DEFAULT_PATH}"));
    }

    let cwd = if cfg.config.working_dir.is_empty() {
        "/".to_string()
    } else {
        cfg.config.working_dir.clone()
    };
    let (uid, gid) = parse_user(&cfg.config.user);

    // Host mode shares the host's network namespace → omit it; every other mode
    // gets a private netns the network layer wires up (or leaves isolated).
    let mut namespaces = vec![
        serde_json::json!({"type": "pid"}),
        serde_json::json!({"type": "mount"}),
        serde_json::json!({"type": "uts"}),
        serde_json::json!({"type": "ipc"}),
    ];
    if opts.net_mode != "host" {
        namespaces.push(serde_json::json!({"type": "network"}));
    }

    let mounts: Vec<serde_json::Value> = opts
        .volumes
        .iter()
        .map(|v| {
            serde_json::json!({
                "destination": v.dest,
                "type": "bind",
                "source": v.source.to_string_lossy(),
                "options": ["rbind", if v.ro { "ro" } else { "rw" }],
            })
        })
        .collect();

    let mut linux = serde_json::json!({
        "namespaces": namespaces,
        "maskedPaths": MASKED_PATHS,
        "readonlyPaths": READONLY_PATHS,
        "seccomp": {
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [
                { "names": BLOCKED_SYSCALLS, "action": "SCMP_ACT_ERRNO", "errnoRet": 1 }
            ]
        },
    });
    if let Some(resources) = build_resources(opts) {
        linux["resources"] = resources;
    }

    let mut spec = serde_json::json!({
        "ociVersion": "1.0.2",
        "hostname": opts.hostname,
        "annotations": { "dn7.net": opts.net_mode },
        "process": {
            "terminal": opts.tty,
            "user": { "uid": uid, "gid": gid },
            "args": args,
            "env": env,
            "cwd": cwd,
            "capabilities": {
                "bounding": DEFAULT_CAPS,
                "effective": DEFAULT_CAPS,
                "permitted": DEFAULT_CAPS,
                "inheritable": [],
                "ambient": [],
            },
        },
        "root": { "path": "rootfs", "readonly": false },
        "mounts": mounts,
        "linux": linux,
    });

    if !opts.ports.is_empty() {
        spec["annotations"]["dn7.ports"] = serde_json::Value::String(opts.ports.to_string());
    }
    if let Some(ip) = opts.static_ip.filter(|s| !s.trim().is_empty()) {
        spec["annotations"]["dn7.ip"] = serde_json::Value::String(ip.trim().to_string());
    }

    let p = bundle_dir.join("config.json");
    let bytes = serde_json::to_vec_pretty(&spec)?;
    fs::write(&p, bytes).map_err(Error::io(&p))
}

/// The `linux.resources` block from any set limits, or `None` if none are set
/// (so the unconstrained case emits no resources block, as before).
fn build_resources(opts: &CreateOpts) -> Option<serde_json::Value> {
    let mut res = serde_json::Map::new();
    if let Some(limit) = opts.mem_limit {
        res.insert("memory".into(), serde_json::json!({ "limit": limit }));
    }
    let mut cpu = serde_json::Map::new();
    if let Some(shares) = opts.cpu_shares {
        cpu.insert("shares".into(), serde_json::json!(shares));
    }
    if let Some((quota, period)) = opts.cpu_quota {
        cpu.insert("quota".into(), serde_json::json!(quota));
        cpu.insert("period".into(), serde_json::json!(period));
    }
    if !cpu.is_empty() {
        res.insert("cpu".into(), serde_json::Value::Object(cpu));
    }
    if let Some(limit) = opts.pids_limit {
        res.insert("pids".into(), serde_json::json!({ "limit": limit }));
    }
    if res.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(res))
    }
}

/// The process argv: an explicit override wins; otherwise Entrypoint + Cmd, the
/// way Docker composes them.
fn command(cfg: &ImageConfig, cmd_override: &[String]) -> Vec<String> {
    if !cmd_override.is_empty() {
        return cmd_override.to_vec();
    }
    let mut args = cfg.config.entrypoint.clone();
    args.extend(cfg.config.cmd.iter().cloned());
    args
}

/// Parse an image `User` field. Numeric `uid[:gid]` is honoured; a *name* (e.g.
/// `nginx`) needs `/etc/passwd` resolution inside the rootfs — deferred — so it
/// falls back to root for now.
fn parse_user(user: &str) -> (u32, u32) {
    if user.is_empty() {
        return (0, 0);
    }
    let (u, g) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    let uid = u.parse::<u32>().unwrap_or(0);
    let gid = g.and_then(|g| g.parse::<u32>().ok()).unwrap_or(0);
    (uid, gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_replaces_entrypoint_and_cmd() {
        let mut cfg = ImageConfig {
            architecture: String::new(),
            os: String::new(),
            config: Default::default(),
            rootfs: None,
        };
        cfg.config.entrypoint = vec!["/entry".into()];
        cfg.config.cmd = vec!["default".into()];
        assert_eq!(command(&cfg, &["sh".to_string()]), vec!["sh"]);
        assert_eq!(command(&cfg, &[]), vec!["/entry", "default"]);
    }

    #[test]
    fn parse_user_numeric_only() {
        assert_eq!(parse_user(""), (0, 0));
        assert_eq!(parse_user("1000"), (1000, 0));
        assert_eq!(parse_user("1000:1001"), (1000, 1001));
        assert_eq!(parse_user("nginx"), (0, 0)); // name → root (deferred)
    }

    #[test]
    fn resources_emitted_only_when_a_limit_is_set() {
        assert!(build_resources(&CreateOpts::new("h", "bridge")).is_none());
        let mut o = CreateOpts::new("h", "bridge");
        o.mem_limit = Some(1024);
        o.cpu_quota = Some((50_000, 100_000));
        o.cpu_shares = Some(512);
        o.pids_limit = Some(64);
        let r = build_resources(&o).unwrap();
        assert_eq!(r["memory"]["limit"], 1024);
        assert_eq!(r["cpu"]["quota"], 50_000);
        assert_eq!(r["cpu"]["period"], 100_000);
        assert_eq!(r["cpu"]["shares"], 512);
        assert_eq!(r["pids"]["limit"], 64);
    }
}
