//! Map a host-pidns pid to its dn7 container cgroup directory, by reading
//! `/proc/<pid>/cgroup`. The panel (and thus the FUSE server) runs in the host
//! pid namespace, so a FUSE request's `header.pid` is a host-side pid that
//! resolves directly against the host `/proc`. Returns `None` for host
//! processes and any dn7 pid that isn't a container leaf, so the caller serves
//! the real host `/proc/meminfo` instead.

use std::path::{Path, PathBuf};

/// The unified cgroup v2 mount point.
const CG_ROOT: &str = "/sys/fs/cgroup";

/// Absolute cgroup dir (`/sys/fs/cgroup/dn7/<id>`) for `pid`, or `None` if it
/// isn't a live dn7 container. Every failure mode (dead pid, non-dn7 cgroup,
/// vanished cgroup dir) folds into `None` — never an error — so a read can
/// always fall back to host meminfo.
pub fn container_cgroup_of(pid: u32) -> Option<PathBuf> {
    let txt = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // cgroup v2 (unified) has exactly one entry: "0::<path>".
    let path = txt.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    // `<path>` is like "/dn7/<id>" or "/dn7/<id>/<sub>"; take the "dn7/<id>" leaf
    // that actually holds the memory.* interface files.
    let rel = path.strip_prefix('/').unwrap_or(path);
    let mut segs = rel.split('/');
    if segs.next()? != "dn7" {
        return None; // not one of our containers
    }
    let id = segs.next()?;
    if id.is_empty() || !is_safe_id(id) {
        return None;
    }
    let leaf = Path::new(CG_ROOT).join("dn7").join(id);
    // The cgroup may have vanished (container stopped) between this read and the
    // caller's synth — `synth` fails open to host meminfo in that case too.
    leaf.exists().then_some(leaf)
}

/// A dn7 container id is 64 lowercase hex chars, but accept any non-traversing
/// token defensively: the id comes from a kernel cgroup path (already trusted),
/// yet we still refuse `.`/`..`/slashes before joining it onto a filesystem path.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::is_safe_id;

    #[test]
    fn rejects_traversal_ids() {
        assert!(!is_safe_id(""));
        assert!(!is_safe_id("."));
        assert!(!is_safe_id(".."));
        assert!(!is_safe_id("a/b"));
        assert!(is_safe_id("deadbeef00"));
        assert!(is_safe_id("adjective_surname-1"));
    }
}
