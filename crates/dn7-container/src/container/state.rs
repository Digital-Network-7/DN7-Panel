//! Per-container persisted state — the OCI `state.json`, written under the
//! runtime root so `start`/`kill`/`state`/`delete` (separate processes) can find
//! a container the `create` process left behind.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Where the runtime keeps live container state. `/run` is tmpfs on a modern
/// distro, so this is cleared on reboot — matching a fresh container world.
const RUNTIME_ROOT: &str = "/run/dn7-container";

/// The container lifecycle states (the OCI status values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Namespaces + rootfs are set up; the init process is parked on the exec
    /// FIFO waiting for `start`.
    Created,
    /// The user process has been exec'd and (as far as we last saw) is alive.
    Running,
    /// The init process has exited.
    Stopped,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Created => "created",
            Status::Running => "running",
            Status::Stopped => "stopped",
        }
    }
}

/// Create-time + inspect metadata carried alongside the runtime record so the
/// panel's `list`/`inspect`/recreate ops can be reproduced without a daemon. All
/// fields default, so an old `state.json` (pre-metadata) still loads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StateMeta {
    /// Source image reference the container was created from.
    pub image: Option<String>,
    /// The container's display name (the panel name; `id` is derived from it).
    pub name: Option<String>,
    /// Restart policy name (`no`|`unless-stopped`|`always`) — stored for inspect
    /// fidelity; dn7 has no supervisor, so it does NOT auto-restart (noop).
    pub restart_policy: Option<String>,
    pub tty: bool,
    pub open_stdin: bool,
    pub hostname: Option<String>,
    pub domainname: Option<String>,
    pub dns: Vec<String>,
    pub env: Vec<String>,
    pub cmd: Vec<String>,
    pub labels: std::collections::HashMap<String, String>,
    pub mem_limit: Option<i64>,
    pub nano_cpus: Option<i64>,
    pub cpu_shares: Option<i64>,
    pub privileged: bool,
    /// The published-port string (`hp:cp[/proto]` joined by `,`).
    pub ports_spec: String,
    /// The user-requested network name (distinct from the single dn7 bridge the
    /// container actually lands on) — for inspect display only.
    pub net_name_requested: Option<String>,
    /// The panel "recreate body" (container_create_body JSON) so backups + the
    /// edit form round-trip when DN7_RUNTIME=dn7.
    pub create_spec: Option<serde_json::Value>,
    /// Last observed exit code (0 until a supervisor reaps the init — dn7 has none
    /// yet, so this stays 0/unknown for detached containers).
    pub exit_code: i32,
    pub restart_count: u32,
    /// Whether the container is currently frozen (`pause`d) — overlays the
    /// pid-derived running status, which can't distinguish a frozen process.
    pub paused: bool,
}

/// The persisted container record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    /// Host pid of the container init (PID 1 inside the container's pid ns).
    pub pid: i32,
    pub bundle: PathBuf,
    /// Cgroup path relative to the v2 root, e.g. `dn7/<id>`.
    pub cgroup: String,
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Networking receipt, if managed networking was applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<crate::net::NetState>,
    /// Create-time + inspect metadata (see [`StateMeta`]).
    #[serde(default)]
    pub meta: StateMeta,
}

impl State {
    pub fn new(id: &str, pid: i32, bundle: &Path, cgroup: &str, created: u64) -> State {
        State {
            oci_version: "1.0.2".to_string(),
            id: id.to_string(),
            status: Status::Created,
            pid,
            bundle: bundle.to_path_buf(),
            cgroup: cgroup.to_string(),
            created,
            net: None,
            meta: StateMeta::default(),
        }
    }

    /// The creation time as an ISO-8601 UTC string (no `chrono` dependency).
    pub fn created_iso(&self) -> String {
        epoch_to_iso(self.created)
    }

    /// `<runtime-root>/<id>`.
    pub fn dir(id: &str) -> PathBuf {
        Path::new(RUNTIME_ROOT).join(id)
    }

    fn file(id: &str) -> PathBuf {
        Self::dir(id).join("state.json")
    }

    /// The exec FIFO path the init parks on between `create` and `start`.
    pub fn fifo_path(id: &str) -> PathBuf {
        Self::dir(id).join("exec.fifo")
    }

    /// The captured stdout/stderr log of a detached container.
    pub fn log_path(id: &str) -> PathBuf {
        Self::dir(id).join("console.log")
    }

    /// Create the container's state directory (errors if it already exists, so a
    /// duplicate `create` is rejected rather than clobbering a live container).
    pub fn make_dir(id: &str) -> Result<PathBuf> {
        let dir = Self::dir(id);
        match std::fs::create_dir_all(&dir) {
            Ok(()) => Ok(dir),
            Err(e) => Err(Error::Io {
                path: dir,
                source: e,
            }),
        }
    }

    pub fn save(&self) -> Result<()> {
        let file = Self::file(&self.id);
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&file, json).map_err(Error::io(&file))
    }

    pub fn load(id: &str) -> Result<State> {
        let file = Self::file(id);
        match std::fs::read(&file) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(Error::Json),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NotFound(id.into())),
            Err(e) => Err(Error::Io {
                path: file,
                source: e,
            }),
        }
    }

    pub fn exists(id: &str) -> bool {
        Self::file(id).exists()
    }

    /// Remove the whole state directory.
    pub fn remove_dir(id: &str) -> Result<()> {
        let dir = Self::dir(id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io {
                path: dir,
                source: e,
            }),
        }
    }

    /// Refresh `status` against reality: if we think it's running but the init
    /// pid is gone, it's actually stopped. Returns the (possibly updated) status.
    pub fn refresh_status(&mut self) -> Status {
        if self.status == Status::Running && !pid_alive(self.pid) {
            self.status = Status::Stopped;
        }
        self.status
    }

    /// Every known container (one per state dir under the runtime root), each
    /// with its status reconciled. A missing runtime root means "none".
    pub fn all() -> Result<Vec<State>> {
        let root = Path::new(RUNTIME_ROOT);
        let entries = match std::fs::read_dir(root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(Error::Io {
                    path: root.to_path_buf(),
                    source: e,
                })
            }
        };
        let mut out = Vec::new();
        for ent in entries.flatten() {
            if let Ok(id) = ent.file_name().into_string() {
                if let Ok(mut s) = State::load(&id) {
                    s.refresh_status();
                    out.push(s);
                }
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }
}

/// Is `pid` still a live process? `kill(pid, 0)` probes without signalling.
pub fn pid_alive(pid: i32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    // ESRCH ⇒ gone; EPERM ⇒ exists but not ours (still "alive"); Ok ⇒ alive.
    !matches!(kill(Pid::from_raw(pid), None), Err(nix::Error::ESRCH))
}

/// Format a Unix timestamp (seconds, UTC) as `YYYY-MM-DDThh:mm:ssZ`, using
/// Howard Hinnant's `civil_from_days` so we need no date crate.
fn epoch_to_iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day-of-era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_to_iso_known_points() {
        assert_eq!(epoch_to_iso(0), "1970-01-01T00:00:00Z");
        // 2021-01-01T00:00:00Z
        assert_eq!(epoch_to_iso(1_609_459_200), "2021-01-01T00:00:00Z");
        // 2009-02-13T23:31:30Z (1234567890)
        assert_eq!(epoch_to_iso(1_234_567_890), "2009-02-13T23:31:30Z");
    }

    #[test]
    fn state_meta_round_trips_through_json() {
        let mut s = State::new("c1", 42, Path::new("/b"), "dn7/c1", 1_609_459_200);
        s.meta.image = Some("alpine:latest".into());
        s.meta.name = Some("web".into());
        s.meta.restart_policy = Some("unless-stopped".into());
        s.meta.mem_limit = Some(1024);
        s.meta.create_spec = Some(serde_json::json!({"op": "create_container"}));
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: State = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.meta.image.as_deref(), Some("alpine:latest"));
        assert_eq!(back.meta.name.as_deref(), Some("web"));
        assert_eq!(back.meta.restart_policy.as_deref(), Some("unless-stopped"));
        assert_eq!(back.meta.mem_limit, Some(1024));
        assert_eq!(back.created_iso(), "2021-01-01T00:00:00Z");
        // Pre-metadata state.json (no `meta`) still loads.
        let old = serde_json::json!({
            "ociVersion": "1.0.2", "id": "old", "status": "created",
            "pid": 1, "bundle": "/b", "cgroup": "dn7/old", "created": 0
        });
        let parsed: State = serde_json::from_value(old).unwrap();
        assert_eq!(parsed.meta.image, None);
    }
}
