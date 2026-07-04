//! Docker request DTOs (Req/PortMap/NetAttach/VolumeMap/CreateSpec) + the
//! memoized daemon client. Shared across the docker submodules.
use super::*;

/// Connect to the local Docker daemon via its unix socket (or the platform
/// default). Replaces shelling out to the `docker` CLI — works as long as the
/// daemon socket is reachable, with no `docker` binary required on PATH.
///
/// The connected `Docker` is memoized in a `OnceLock` and handed out by clone
/// (the handle is internally an `Arc`, so clones share one connection pool).
/// Without this every op rebuilt a fresh hyper client + pool, defeating
/// keep-alive across the ~46 call sites. The first *successful* connect is
/// cached; a connect failure is not, so a later call retries once the daemon
/// is up. `connect_with_defaults` only sets up the client (it doesn't perform a
/// round-trip), so caching it can't pin a dead socket.
pub fn dkr() -> Result<Docker> {
    static CLIENT: std::sync::OnceLock<Docker> = std::sync::OnceLock::new();
    if let Some(d) = CLIENT.get() {
        return Ok(d.clone());
    }
    let d = Docker::connect_with_defaults()
        .map_err(|e| anyhow!("无法连接 Docker 守护进程：{e}（请确认 Docker 已安装并运行）"))?;
    // Race-tolerant: if another thread set it first, keep the existing one.
    Ok(CLIENT.get_or_init(|| d).clone())
}

#[derive(Debug, Deserialize)]
pub(crate) struct Req {
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) id: i64,
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) image: Option<String>,
    #[serde(default)]
    pub(crate) mirror: Option<String>,
    /// Pull from a configured private registry (host prefix); empty = Docker Hub.
    #[serde(default)]
    pub(crate) registry: Option<String>,
    #[serde(default, rename = "ref")]
    pub(crate) reference: Option<String>,
    #[serde(default)]
    pub(crate) tail: Option<i64>,
    /// Byte offset for incremental log follow (`logs` with the dn7 runtime):
    /// return only bytes appended since this position.
    #[serde(default)]
    pub(crate) offset: Option<u64>,
    #[serde(default)]
    pub(crate) op_id: Option<String>,
    // create_container fields
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) ports: Option<Vec<PortMap>>,
    #[serde(default)]
    pub(crate) env: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) volumes: Option<Vec<VolumeMap>>,
    #[serde(default)]
    pub(crate) restart: Option<String>,
    #[serde(default)]
    pub(crate) start: Option<bool>,
    #[serde(default)]
    pub(crate) network: Option<String>,
    /// Networks to join at create time (each with optional MAC / static IPv4).
    /// A container can be attached to several networks; the first is set on the
    /// create call, the rest are connected right after.
    #[serde(default)]
    pub(crate) networks: Option<Vec<NetAttach>>,
    // network create options
    #[serde(default)]
    pub(crate) driver: Option<String>,
    #[serde(default)]
    pub(crate) subnet: Option<String>,
    #[serde(default)]
    pub(crate) gateway: Option<String>,
    #[serde(default)]
    pub(crate) ip_range: Option<String>,
    // create_container: networking endpoint options
    #[serde(default)]
    pub(crate) mac: Option<String>,
    #[serde(default)]
    pub(crate) ipv4: Option<String>,
    #[serde(default)]
    pub(crate) hostname: Option<String>,
    #[serde(default)]
    pub(crate) domainname: Option<String>,
    #[serde(default)]
    pub(crate) dns: Option<Vec<String>>,
    // create_container: extra resource limits
    #[serde(default)]
    pub(crate) cpu_shares: Option<i64>,
    #[serde(default)]
    pub(crate) pids_limit: Option<i64>,
    #[serde(default)]
    pub(crate) privileged: Option<bool>,
    // create_container: stop behavior (docker --stop-signal / --stop-timeout) and
    // auto-remove-on-exit (docker --rm).
    #[serde(default)]
    pub(crate) stop_signal: Option<String>,
    #[serde(default)]
    pub(crate) stop_timeout: Option<i64>,
    #[serde(default)]
    pub(crate) auto_remove: Option<bool>,
    // edit/upgrade: when set, remove this existing container (by id/name) before
    // creating the new one so it can reuse the same name.
    #[serde(default)]
    pub(crate) replace: Option<String>,
    // rename_container
    #[serde(default)]
    pub(crate) new_name: Option<String>,
    // commit_container -> image repo:tag
    #[serde(default)]
    pub(crate) repo: Option<String>,
    #[serde(default)]
    pub(crate) tag: Option<String>,
    // tag_image -> one or more new repo:tag references to add to an image
    #[serde(default)]
    pub(crate) tags: Option<Vec<String>>,
    // backup file name (list/delete/restore/download)
    #[serde(default)]
    pub(crate) backup: Option<String>,
    // list_dirs: a (partial) absolute host path to suggest directories for.
    #[serde(default)]
    pub(crate) path: Option<String>,
    // optional command override (argv, whitespace-split client-side or here)
    #[serde(default)]
    pub(crate) command: Option<String>,
    // allocate a pseudo-TTY (-t); keeps shells like `ubuntu`/`bash` alive
    #[serde(default)]
    pub(crate) tty: Option<bool>,
    // keep STDIN open (-i); maps to open_stdin so the container accepts input
    #[serde(default)]
    pub(crate) interactive: Option<bool>,
    // resource limits (cgroup v2 only): cpus like "0.5"/"2"; memory like "512m"/"1g"
    #[serde(default)]
    pub(crate) cpus: Option<String>,
    #[serde(default)]
    pub(crate) memory: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PortMap {
    pub(crate) host: i64,
    pub(crate) container: i64,
    #[serde(default)]
    pub(crate) proto: Option<String>, // "tcp" | "udp", default tcp
    #[serde(default)]
    pub(crate) host_ip: Option<String>, // publish only on this host IPv4 (docker -p ip:hp:cp)
    #[serde(default)]
    pub(crate) ipv6: Option<bool>, // also bind the host IPv6 wildcard (::) for this port
}

/// One network attachment for a container: the network name plus an optional
/// MAC address and static IPv4 for the endpoint on that network.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct NetAttach {
    #[serde(default)]
    pub(crate) network: String,
    #[serde(default)]
    pub(crate) mac: Option<String>,
    #[serde(default)]
    pub(crate) ipv4: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct VolumeMap {
    pub(crate) host: String,
    pub(crate) container: String,
    #[serde(default)]
    pub(crate) readonly: bool,
}

/// A validated container creation spec, ready for the bollard create API.
/// Kept in the parent so descendant submodules + tests can read its fields.
pub(crate) struct CreateSpec {
    pub(crate) image: String,
    pub(crate) name: Option<String>,
    pub(crate) start: bool,
    pub(crate) config: bollard::container::Config<String>,
    /// When set, remove this existing container before creating (edit/upgrade).
    pub(crate) replace: Option<String>,
    /// Networks (beyond the first) to connect after creation, each with an
    /// optional MAC / static IPv4.
    pub(crate) extra_networks: Vec<NetAttach>,
}

// ---------------------------------------------------------------------------
// Operation submodules (see .kiro/steering/code-structure.md). Shared structs
// (Req/PortMap/NetAttach/VolumeMap/CreateSpec) stay in this parent so
// descendant modules can read their private fields via `use super::*`.
