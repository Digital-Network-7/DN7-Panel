//! The OCI runtime-spec `config.json`, as much of it as P1 needs. Faithful to
//! the upstream field names (camelCase) so it can grow toward full coverage in
//! P3 without renaming. Unknown fields are ignored; absent fields default, so a
//! minimal hand-written bundle still parses.

use serde::Deserialize;

/// Top-level `config.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    #[serde(default)]
    pub oci_version: String,
    #[serde(default)]
    pub hostname: String,
    pub process: Option<Process>,
    pub root: Option<Root>,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    pub linux: Option<Linux>,
    /// OCI annotations. The runtime reads `dn7.net` (`bridge`|`none`|`host`) and
    /// `dn7.ports` (published ports) from here; absent `dn7.net` = unmanaged netns.
    #[serde(default)]
    pub annotations: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(default)]
    pub terminal: bool,
    #[serde(default)]
    pub user: User,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default = "default_cwd")]
    pub cwd: String,
    /// `no_new_privileges` bit (set before exec).
    #[serde(default)]
    pub no_new_privileges: bool,
    /// Per-process resource limits (`setrlimit`).
    #[serde(default)]
    pub rlimits: Vec<Rlimit>,
    /// Capability sets to retain (P3b). Parsed now so real Docker configs load.
    pub capabilities: Option<Capabilities>,
}

fn default_cwd() -> String {
    "/".to_string()
}

/// One `setrlimit` entry (e.g. `RLIMIT_NOFILE`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub typ: String,
    pub hard: u64,
    pub soft: u64,
}

/// The five Linux capability sets, each a list of `CAP_*` names.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    #[serde(default)]
    pub bounding: Vec<String>,
    #[serde(default)]
    pub effective: Vec<String>,
    #[serde(default)]
    pub inheritable: Vec<String>,
    #[serde(default)]
    pub permitted: Vec<String>,
    #[serde(default)]
    pub ambient: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default)]
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Root {
    pub path: String,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Mount {
    pub destination: String,
    #[serde(default, rename = "type")]
    pub typ: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    #[serde(default)]
    pub namespaces: Vec<Namespace>,
    pub resources: Option<Resources>,
    /// `cgroupsPath`: where to place the container's cgroup (relative to the v2
    /// root, or an absolute `:`-delimited form we normalise in the cgroup layer).
    pub cgroups_path: Option<String>,
    /// Paths masked from the container (`/dev/null` over files, ro tmpfs over
    /// dirs) — e.g. `/proc/kcore`.
    #[serde(default)]
    pub masked_paths: Vec<String>,
    /// Paths remounted read-only inside the container — e.g. `/proc/sys`.
    #[serde(default)]
    pub readonly_paths: Vec<String>,
    /// Seccomp-BPF syscall filter.
    pub seccomp: Option<Seccomp>,
}

/// An OCI seccomp profile: a default action plus per-syscall overrides.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seccomp {
    pub default_action: String,
    #[serde(default)]
    pub default_errno_ret: Option<u32>,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub syscalls: Vec<SyscallRule>,
}

/// One seccomp rule: a set of syscall names sharing an action. (Argument-value
/// conditions are parsed-but-ignored in the MVP; most profiles don't need them.)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyscallRule {
    #[serde(default)]
    pub names: Vec<String>,
    pub action: String,
    #[serde(default)]
    pub errno_ret: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub typ: NamespaceType,
    /// A path to an existing namespace to *join* (setns) instead of unsharing a
    /// fresh one. `None` = create a new namespace of this type.
    #[serde(default)]
    pub path: Option<String>,
}

/// The OCI namespace kinds. `user`/`cgroup` are accepted so configs parse, but
/// joining/creating them is a P3 concern (user-ns remapping in particular).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NamespaceType {
    Pid,
    Network,
    Mount,
    Ipc,
    Uts,
    User,
    Cgroup,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Resources {
    pub memory: Option<Memory>,
    pub cpu: Option<Cpu>,
    pub pids: Option<Pids>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Memory {
    /// Hard limit in bytes → `memory.max`.
    pub limit: Option<i64>,
    /// Swap limit in bytes → `memory.swap.max` (total mem+swap in OCI terms; we
    /// translate to the v2 swap-only value in the cgroup layer).
    pub swap: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Cpu {
    /// `cpu.weight` derives from `shares` (v1 → v2 conversion in the cgroup layer).
    pub shares: Option<u64>,
    /// `quota`/`period` (µs) → `cpu.max`.
    pub quota: Option<i64>,
    pub period: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Pids {
    /// Max number of processes → `pids.max`.
    pub limit: Option<i64>,
}

impl Spec {
    /// Parse a `config.json` byte slice.
    pub fn parse(bytes: &[u8]) -> crate::error::Result<Spec> {
        serde_json::from_slice(bytes).map_err(crate::error::Error::Json)
    }

    /// The process block, or a config error if the bundle omits it (nothing to
    /// run).
    pub fn require_process(&self) -> crate::error::Result<&Process> {
        self.process
            .as_ref()
            .ok_or_else(|| crate::error::Error::Config("missing `process`".into()))
    }

    /// The rootfs path, or a config error if absent.
    pub fn require_root(&self) -> crate::error::Result<&Root> {
        self.root
            .as_ref()
            .ok_or_else(|| crate::error::Error::Config("missing `root`".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_minimal_bundle() {
        let json = br#"{
            "ociVersion":"1.0.2",
            "hostname":"box",
            "process":{"args":["/bin/sh"],"env":["PATH=/bin"],"cwd":"/srv","noNewPrivileges":true,
                       "user":{"uid":1000,"gid":1000,"additionalGids":[10,20]}},
            "root":{"path":"rootfs","readonly":true},
            "mounts":[{"destination":"/data","type":"bind","source":"/host","options":["rbind","ro"]}],
            "linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"network","path":"/proc/9/ns/net"}],
                     "resources":{"memory":{"limit":67108864,"swap":134217728},
                                  "cpu":{"shares":512,"quota":50000,"period":100000},
                                  "pids":{"limit":64}}}
        }"#;
        let spec = Spec::parse(json).unwrap();
        assert_eq!(spec.hostname, "box");

        let p = spec.require_process().unwrap();
        assert_eq!(p.args, ["/bin/sh"]);
        assert_eq!(p.cwd, "/srv");
        assert!(p.no_new_privileges);
        assert_eq!(p.user.uid, 1000);
        assert_eq!(p.user.additional_gids, [10, 20]);

        assert!(spec.require_root().unwrap().readonly);

        let m = &spec.mounts[0];
        assert_eq!(m.destination, "/data");
        assert_eq!(m.typ.as_deref(), Some("bind"));
        assert_eq!(m.options, ["rbind", "ro"]);

        let lin = spec.linux.as_ref().unwrap();
        assert_eq!(lin.namespaces.len(), 3);
        assert_eq!(lin.namespaces[0].typ, NamespaceType::Pid);
        assert_eq!(lin.namespaces[2].path.as_deref(), Some("/proc/9/ns/net"));
        let res = lin.resources.as_ref().unwrap();
        assert_eq!(res.memory.as_ref().unwrap().limit, Some(67_108_864));
        assert_eq!(res.cpu.as_ref().unwrap().quota, Some(50_000));
        assert_eq!(res.pids.as_ref().unwrap().limit, Some(64));
    }

    #[test]
    fn absent_fields_default_and_require_helpers_error() {
        let spec = Spec::parse(br#"{"root":{"path":"rootfs"}}"#).unwrap();
        assert!(spec.process.is_none());
        assert!(!spec.root.as_ref().unwrap().readonly);
        assert!(spec.require_process().is_err());
        assert!(spec.linux.is_none());
    }

    #[test]
    fn process_cwd_defaults_to_root() {
        let spec =
            Spec::parse(br#"{"process":{"args":["/bin/true"]},"root":{"path":"rootfs"}}"#).unwrap();
        assert_eq!(spec.require_process().unwrap().cwd, "/");
    }
}
