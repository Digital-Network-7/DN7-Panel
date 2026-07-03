//! cgroup v2 (unified hierarchy) resource control. P1 covers the three limits
//! the panel actually exposes today — memory, CPU, PIDs — written straight to the
//! unified `/sys/fs/cgroup` tree. v1 is intentionally *not* supported (it's a P7
//! fallback); modern distros default to v2.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::oci::spec::Resources;

/// A point-in-time resource snapshot read from the cgroup v2 interface files.
/// `cpu_usage_usec` is cumulative (a CPU% needs two samples over an interval).
#[derive(Debug, Clone, Serialize)]
pub struct CgroupStats {
    pub cpu_usage_usec: u64,
    pub memory_current: u64,
    pub memory_max: Option<u64>,
    /// `inactive_file` from `memory.stat` — reclaimable page cache. `docker stats`
    /// reports memory as `memory.current - inactive_file`.
    pub inactive_file: u64,
    pub pids_current: u64,
    pub pids_max: Option<u64>,
    /// Cumulative block-IO bytes across all devices, from `io.stat`.
    pub io_rbytes: u64,
    pub io_wbytes: u64,
}

/// The unified cgroup v2 mount point.
const CG_ROOT: &str = "/sys/fs/cgroup";

/// A live cgroup directory under the v2 root. Dropping it does *not* remove the
/// directory — call [`Cgroup::delete`] explicitly once the container is gone.
#[derive(Debug, Clone)]
pub struct Cgroup {
    /// Absolute path, e.g. `/sys/fs/cgroup/dn7/<id>`.
    path: PathBuf,
}

impl Cgroup {
    /// Create (or reuse) the container's cgroup under `rel` (e.g. `dn7/<id>`),
    /// enabling the controllers we need along the way, then apply `resources`.
    pub fn create(rel: &str, resources: Option<&Resources>) -> Result<Cgroup> {
        ensure_v2()?;
        let rel = rel.trim_matches('/');
        if rel.is_empty() {
            return Err(Error::Other("empty cgroup path".into()));
        }

        // Enable controllers from the root down to each parent so the leaf may use
        // them. The "no internal processes" rule means controllers are enabled on
        // the *parent's* `cgroup.subtree_control`, never the leaf's.
        enable_controllers_along(rel)?;

        let path = Path::new(CG_ROOT).join(rel);
        if !path.exists() {
            std::fs::create_dir_all(&path).map_err(Error::io(&path))?;
        }

        let cg = Cgroup { path };
        if let Some(r) = resources {
            cg.apply(r)?;
        }
        Ok(cg)
    }

    /// A handle to an *existing* cgroup at `rel` (no creation, no controller
    /// setup) — used by `delete` to tear one down by its persisted path.
    pub fn at(rel: &str) -> Cgroup {
        Cgroup {
            path: Path::new(CG_ROOT).join(rel.trim_matches('/')),
        }
    }

    /// Move a process into this cgroup (writes its pid to `cgroup.procs`). All of
    /// the process's future children inherit the cgroup, so the whole container
    /// tree is accounted and limited.
    pub fn add_pid(&self, pid: i32) -> Result<()> {
        self.write("cgroup.procs", &pid.to_string())
    }

    /// Remove the cgroup directory. `rmdir` on a cgroup fails with `EBUSY` while
    /// it still holds a member — including a just-killed process that hasn't been
    /// reaped yet: under the panel the container init is the panel's own child,
    /// and the dedicated reaper thread reaps it ASYNCHRONOUSLY, so a
    /// `stop`→`delete` (e.g. an edit/recreate) can reach here a beat before the
    /// zombie is reaped and the kernel lets the cgroup go. `wait_drained` can't
    /// see this — a zombie is absent from `cgroup.procs`. So retry the `rmdir`
    /// briefly (≈2s) to let the reaper catch up, instead of failing the delete.
    pub fn delete(&self) -> Result<()> {
        for attempt in 0..100u32 {
            match std::fs::remove_dir(&self.path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) && attempt < 99 => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => {
                    return Err(Error::Io {
                        path: self.path.clone(),
                        source: e,
                    })
                }
            }
        }
        unreachable!("loop returns on the final attempt")
    }

    /// Kill every process in the cgroup at once by writing `cgroup.kill` (cgroup
    /// v2, Linux ≥ 5.14). This is atomic and race-free — no PID enumeration, no
    /// fork-bomb escape. A missing file (older kernel) is reported as `NotFound`
    /// so the caller can fall back to signalling the init pid.
    pub fn kill_all(&self) -> Result<()> {
        let p = self.path.join("cgroup.kill");
        match std::fs::write(&p, "1") {
            Ok(()) => Ok(()),
            Err(e) => Err(Error::Io { path: p, source: e }),
        }
    }

    /// Freeze (`1`) or thaw (`0`) every process in the cgroup via `cgroup.freeze`
    /// (cgroup v2). A frozen process is suspended but alive (keeps its pid), which
    /// is how `pause`/`unpause` work.
    pub fn freeze(&self, frozen: bool) -> Result<()> {
        let p = self.path.join("cgroup.freeze");
        match std::fs::write(&p, if frozen { "1" } else { "0" }) {
            Ok(()) => Ok(()),
            Err(e) => Err(Error::Io { path: p, source: e }),
        }
    }

    /// True while any process remains in the cgroup.
    pub fn has_procs(&self) -> bool {
        std::fs::read_to_string(self.path.join("cgroup.procs"))
            .map(|s| s.split_whitespace().next().is_some())
            .unwrap_or(false)
    }

    /// Read a resource snapshot. Missing files (controller not enabled) read as 0
    /// / unlimited, so this never fails for a live container.
    pub fn stats(&self) -> CgroupStats {
        let (io_rbytes, io_wbytes) = sum_io_stat(&self.path.join("io.stat"));
        CgroupStats {
            cpu_usage_usec: read_keyed(&self.path.join("cpu.stat"), "usage_usec").unwrap_or(0),
            memory_current: read_u64(&self.path.join("memory.current")).unwrap_or(0),
            memory_max: read_max_u64(&self.path.join("memory.max")),
            inactive_file: read_keyed(&self.path.join("memory.stat"), "inactive_file").unwrap_or(0),
            pids_current: read_u64(&self.path.join("pids.current")).unwrap_or(0),
            pids_max: read_max_u64(&self.path.join("pids.max")),
            io_rbytes,
            io_wbytes,
        }
    }

    /// Translate OCI resources to v2 interface files.
    fn apply(&self, r: &Resources) -> Result<()> {
        if let Some(mem) = &r.memory {
            if let Some(limit) = mem.limit {
                self.write("memory.max", &bytes_or_max(limit))?;
                // OCI `swap` is mem+swap; v2 `memory.swap.max` is swap-only. Match
                // Docker's mapping: `--memory=X` with no `--memory-swap` ⇒
                // memory-swap=2X ⇒ swap-only budget = the memory limit (so a capped
                // container can't thrash unlimited host swap); a value == limit ⇒
                // swap disabled (0); a larger value ⇒ that much swap-only; -1 ⇒ max.
                match mem.swap {
                    Some(swap) if swap < 0 => self.write("memory.swap.max", "max")?,
                    Some(swap) if swap > limit => {
                        self.write("memory.swap.max", &(swap - limit).to_string())?
                    }
                    Some(_) => self.write("memory.swap.max", "0")?,
                    None => self.write("memory.swap.max", &limit.to_string())?,
                }
            }
        }
        if let Some(cpu) = &r.cpu {
            if let Some(weight) = cpu.shares.map(shares_to_weight) {
                self.write("cpu.weight", &weight.to_string())?;
            }
            if let Some(quota) = cpu.quota {
                let period = cpu.period.unwrap_or(100_000);
                let val = if quota < 0 {
                    format!("max {period}")
                } else {
                    format!("{quota} {period}")
                };
                self.write("cpu.max", &val)?;
            }
        }
        if let Some(pids) = &r.pids {
            if let Some(limit) = pids.limit {
                self.write("pids.max", &bytes_or_max(limit))?;
            }
        }
        Ok(())
    }

    fn write(&self, file: &str, val: &str) -> Result<()> {
        let p = self.path.join(file);
        std::fs::write(&p, val).map_err(Error::io(&p))
    }
}

/// Verify the unified hierarchy is mounted (the v2 marker file exists).
fn ensure_v2() -> Result<()> {
    if Path::new(CG_ROOT).join("cgroup.controllers").is_file() {
        Ok(())
    } else {
        Err(Error::NoCgroupV2(format!(
            "{CG_ROOT}/cgroup.controllers not found (is cgroup v2 mounted?)"
        )))
    }
}

/// For each ancestor of `rel` (root first), enable the controllers we manage in
/// its `cgroup.subtree_control`, so the child level can use them. Already-enabled
/// controllers are a no-op; we tolerate write errors for controllers the host
/// doesn't delegate (a clear error surfaces later when a limit can't be written).
fn enable_controllers_along(rel: &str) -> Result<()> {
    let avail = available_controllers();
    let want: Vec<&str> = ["memory", "cpu", "pids"]
        .into_iter()
        .filter(|c| avail.iter().any(|a| a == c))
        .collect();
    if want.is_empty() {
        return Ok(());
    }
    let line = want
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");

    // Enable at the root, then at each intermediate directory except the leaf.
    let mut dir = PathBuf::from(CG_ROOT);
    let _ = std::fs::write(dir.join("cgroup.subtree_control"), &line);

    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        dir.push(part);
        if !dir.exists() {
            std::fs::create_dir_all(&dir).map_err(Error::io(&dir))?;
        }
        let _ = std::fs::write(dir.join("cgroup.subtree_control"), &line);
    }
    Ok(())
}

/// Controllers the root advertises as available.
fn available_controllers() -> Vec<String> {
    std::fs::read_to_string(Path::new(CG_ROOT).join("cgroup.controllers"))
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Read a single-integer cgroup file.
fn read_u64(p: &Path) -> Option<u64> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

/// Read a cgroup file whose value may be `max` (→ `None`) or an integer.
fn read_max_u64(p: &Path) -> Option<u64> {
    let s = std::fs::read_to_string(p).ok()?;
    let s = s.trim();
    if s == "max" {
        None
    } else {
        s.parse().ok()
    }
}

/// Read `value` for `key` from a `key value`-per-line cgroup file (e.g.
/// `cpu.stat`).
fn read_keyed(p: &Path, key: &str) -> Option<u64> {
    let s = std::fs::read_to_string(p).ok()?;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some(key) {
            return it.next()?.parse().ok();
        }
    }
    None
}

/// Sum `rbytes=`/`wbytes=` across every device line of a cgroup v2 `io.stat`.
fn sum_io_stat(p: &Path) -> (u64, u64) {
    let (mut r, mut w) = (0u64, 0u64);
    if let Ok(txt) = std::fs::read_to_string(p) {
        for tok in txt.split_whitespace() {
            if let Some(v) = tok.strip_prefix("rbytes=") {
                r += v.parse::<u64>().unwrap_or(0);
            } else if let Some(v) = tok.strip_prefix("wbytes=") {
                w += v.parse::<u64>().unwrap_or(0);
            }
        }
    }
    (r, w)
}

/// `-1` (OCI "unlimited") → `max`; any other value verbatim.
fn bytes_or_max(v: i64) -> String {
    if v < 0 {
        "max".to_string()
    } else {
        v.to_string()
    }
}

/// Convert a v1 `cpu.shares` value to a v2 `cpu.weight` using the canonical
/// OCI/runc/containerd mapping `1 + (shares-2)·9999/262142`, clamped to the v2
/// range [1, 10000]. This is *not* systemd's proportional map: the nominal
/// default 1024 lands on 39, exactly as Docker/runc do on a v2 host — keeping the
/// runtime behavior-compatible with the Docker it replaces. `0` (unset) → the v2
/// default 100.
fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 {
        return 100;
    }
    let w = 1 + ((shares.saturating_sub(2)) * 9999) / 262142;
    w.clamp(1, 10000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_conversion_matches_known_points() {
        assert_eq!(shares_to_weight(1024), 39); // runc/OCI map (not systemd's 100)
        assert_eq!(shares_to_weight(0), 100); // unset → v2 default
        assert_eq!(shares_to_weight(2), 1); // floor
        assert!(shares_to_weight(262144) <= 10000); // ceiling clamp
    }

    #[test]
    fn unlimited_renders_as_max() {
        assert_eq!(bytes_or_max(-1), "max");
        assert_eq!(bytes_or_max(0), "0");
        assert_eq!(bytes_or_max(1 << 30), (1 << 30).to_string());
    }
}
