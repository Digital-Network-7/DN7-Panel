//! Host + container file operations: path guards, list/mkdir/delete/download/
//! upload, temp uploads, and the byte-stream type.
use super::*;

pub type ByteStream = Pin<Box<dyn futures::Stream<Item = std::io::Result<Bytes>> + Send>>;

/// Chunk size for streaming file content (256 KiB).
pub(crate) const CHUNK: usize = 256 * 1024;

/// Reject deleting a path that is (or sits at) a critical system directory, to
/// guard against a catastrophic recursive delete (e.g. an accidental `/` or
/// `/etc`). This is a safety net, not an access-control boundary: the server
/// owner already has full file access by design — we only block the handful of
/// paths whose removal would brick the host.
///
/// The path is **lexically normalized first** (resolving `.`/`..`, collapsing
/// repeated/trailing separators) so tricks like `/etc/../etc`, `/var/./`,
/// `/usr//` or `/root/../root` can't slip a protected target past a raw string
/// compare.
pub(crate) fn is_protected_path(path: &str) -> bool {
    let norm = normalize_lexical(path);
    if norm == "/" {
        return true;
    }
    const PROTECTED: &[&str] = &[
        "/bin", "/sbin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
        "/root", "/run", "/sys", "/usr", "/var",
    ];
    PROTECTED.contains(&norm.as_str())
}

/// Stricter guard for **host-side** mutations (write / mkdir / delete): refuses
/// the exact protected dirs (`is_protected_path`) **and any descendant** of the
/// most sensitive trees, so writing/deleting e.g. `/etc/shadow` or
/// `/root/.ssh/authorized_keys` is blocked — not just the bare directory. The
/// super-admin runs host ops as root, so without this a single file write could
/// clobber credentials or kernel state. Host-only: container paths keep the
/// looser exact-dir guard so in-container `/etc` management still works.
pub(crate) fn is_protected_host_mutation(path: &str) -> bool {
    let norm = normalize_lexical(path);
    if is_protected_path(&norm) {
        return true;
    }
    const TREES: &[&str] = &["/etc", "/root", "/boot", "/proc", "/sys", "/dev"];
    TREES.iter().any(|t| norm.starts_with(&format!("{t}/")))
}

/// Symlink-aware host-mutation guard for create paths (write / mkdir). The
/// lexical guard catches `..`/`//`/`.` tricks, but not a *symlinked ancestor*:
/// writing to `/srv/link/x` where `/srv/link -> /etc` resolves into a protected
/// tree. This resolves the longest existing prefix (following symlinks),
/// re-appends the not-yet-existing tail, and re-checks — so a symlinked
/// ancestor can't smuggle a write into `/etc`/`/root`/etc. Delete already does
/// the equivalent post-`canonicalize` check on the (existing) target.
pub(crate) async fn resolves_into_protected(path: &str) -> bool {
    let mut existing = Path::new(path).to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => break,
        }
    }
    let Ok(mut resolved) = tokio::fs::canonicalize(&existing).await else {
        return false; // nothing resolvable — the lexical guard already ran
    };
    for seg in tail.iter().rev() {
        resolved.push(seg);
    }
    is_protected_host_mutation(&resolved.to_string_lossy())
}

// ---------------------------------------------------------------------------
// Container-scoped file transfer (Docker daemon API; no `docker` CLI).
//
// Mirrors the host file protocol but every operation targets a container:
//   - list/mkdir/delete run via the daemon exec API (`/bin/sh -c '<script>' sh
//     "<path>"`), the path passed as a positional arg ($1), never interpolated
//     into the script — no shell-injection surface.
//   - download streams the container archive (tar) API, parsing the single
//     entry incrementally and forwarding its bytes in chunks (no full buffering).
//   - upload buffers chunks into a host temp file, then streams a tar of it into
//     the container via the archive API (works on shell-less images too).
// Paths must be absolute (so they can't be mistaken for flags), and deletes of
// critical system directories are refused (see `is_protected_path`).
// ---------------------------------------------------------------------------

/// Reject container refs that could smuggle extra docker flags.
pub(crate) fn valid_container_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
}

/// Require an absolute path (so it can't be read as a CLI flag).
pub(crate) fn check_abs(path: &str) -> Result<()> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(anyhow!("路径必须为绝对路径"))
    }
}

/// Standard listing order shared by every lister: directories first, then by
/// name within each group.
pub(crate) fn sort_entries(entries: &mut [serde_json::Value]) {
    entries.sort_by(|a, b| {
        let ad = a["is_dir"].as_bool().unwrap_or(false);
        let bd = b["is_dir"].as_bool().unwrap_or(false);
        bd.cmp(&ad).then_with(|| {
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
        })
    });
}

/// Build one listing entry from filesystem metadata. `lmd` is the entry's own
/// (no-follow) metadata — `mode` (octal permission string), `mtime` (unix secs)
/// and `is_symlink` come from it; `fmd` is the *followed* metadata a caller may
/// resolve for symlinks (None for plain entries) — `is_dir`/`size` prefer it so
/// a link to a directory navigates like a directory.
pub(crate) fn fs_entry_json(
    name: &str,
    lmd: Option<&std::fs::Metadata>,
    fmd: Option<&std::fs::Metadata>,
) -> serde_json::Value {
    use std::os::unix::fs::MetadataExt;
    let eff = fmd.or(lmd);
    let is_dir = eff.map(|m| m.is_dir()).unwrap_or(false);
    let size = if is_dir {
        0
    } else {
        eff.map(|m| m.len()).unwrap_or(0)
    };
    serde_json::json!({
        "name": name,
        "is_dir": is_dir,
        "size": size,
        "mtime": lmd.map(|m| m.mtime()).unwrap_or(0),
        "mode": lmd.map(|m| format!("{:o}", m.mode() & 0o7777)).unwrap_or_default(),
        "is_symlink": lmd.map(|m| m.file_type().is_symlink()).unwrap_or(false),
    })
}

/// Parse a text lister's output (tab-separated `type\tsize\tmtime\tmode\tname`
/// lines; type `d`/`f`, with an `l` prefix for symlinks) into sorted directory
/// entries (dirs first). Tolerates the legacy 3-field `type\tsize\tname` shape
/// (mtime/mode default to 0/empty).
pub(crate) fn parse_list_output(stdout: &str, dir: &str) -> serde_json::Value {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let cols: Vec<&str> = line.splitn(5, '\t').collect();
        let (t, sz, mt, md, name) = match cols[..] {
            [t, sz, mt, md, name] => (t, sz, mt, md, name),
            [t, sz, name] => (t, sz, "0", "", name),
            _ => continue,
        };
        if name.is_empty() {
            continue;
        }
        entries.push(serde_json::json!({
            "name": name,
            "is_dir": t.ends_with('d'),
            "size": sz.trim().parse::<u64>().unwrap_or(0),
            "mtime": mt.trim().parse::<i64>().unwrap_or(0),
            "mode": md.trim(),
            "is_symlink": t.starts_with('l'),
        }));
    }
    sort_entries(&mut entries);
    serde_json::json!({ "path": dir, "entries": entries })
}

/// Run a single host file operation **as another system user** by re-exec'ing the
/// panel binary as a privilege-dropping `__fshelper` (see
/// [`crate::infra::file::run_fs_helper_main`]) — the pure-Rust replacement for
/// `su` (no `su`, no `/bin/sh`). `op` is one of `list`/`mkdir`/`remove`; `path`
/// is a separate argv entry (no shell). Returns (exit_code, stdout bytes). The
/// helper drops to `user` (initgroups+setgid+setuid) so the OS enforces access.
pub(crate) async fn run_fs_helper(
    user: &str,
    op: &str,
    path: &str,
    stdin: Option<&[u8]>,
) -> Result<(i32, Vec<u8>)> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let exe = std::env::current_exe().map_err(|e| anyhow!("无法定位自身：{e}"))?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(["__fshelper", op, user, path]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("无法以用户身份执行：{e}"))?;
    if let Some(data) = stdin {
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(data).await;
            let _ = si.shutdown().await;
        }
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| anyhow!("以用户身份执行失败：{e}"))?;
    Ok((out.status.code().unwrap_or(-1), out.stdout))
}

/// Create a fresh staging file for a streamed upload in the system temp dir,
/// opened with O_EXCL and mode 0600. The name is unpredictable (random) and
/// O_EXCL refuses to follow a pre-planted symlink, so a local low-privilege
/// user can't hijack the path to make the (high-privilege) panel overwrite an
/// arbitrary file. Returns the open file and its path.
pub fn create_temp_upload() -> std::io::Result<(std::fs::File, std::path::PathBuf)> {
    let dir = std::env::temp_dir();
    let mut last_err = None;
    for _ in 0..16 {
        let path = dir.join(format!(
            "dn7-up-{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true); // O_CREAT | O_EXCL
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temp file name collision",
        )
    }))
}

// Container exec + tar helpers live in a submodule (see code-structure steering).
#[cfg(test)]
mod tests {
    use super::{
        is_protected_host_mutation, is_protected_path, parse_tar_header, valid_container_ref,
    };

    #[test]
    fn host_mutation_blocks_sensitive_descendants() {
        // Bare protected dirs (same as is_protected_path).
        assert!(is_protected_host_mutation("/etc"));
        assert!(is_protected_host_mutation("/"));
        // Descendants of credential / kernel trees — the new coverage.
        assert!(is_protected_host_mutation("/etc/shadow"));
        assert!(is_protected_host_mutation("/etc/ssh/sshd_config"));
        assert!(is_protected_host_mutation("/root/.ssh/authorized_keys"));
        assert!(is_protected_host_mutation("/proc/sys/kernel"));
        assert!(is_protected_host_mutation("/sys/class"));
        assert!(is_protected_host_mutation("/dev/sda"));
        assert!(is_protected_host_mutation("/boot/grub/grub.cfg"));
        assert!(is_protected_host_mutation("/etc/../etc/passwd")); // traversal -> /etc/passwd
                                                                   // Ordinary writable locations stay allowed.
        assert!(!is_protected_host_mutation("/home/user/file.txt"));
        assert!(!is_protected_host_mutation("/var/www/site/index.html"));
        assert!(!is_protected_host_mutation("/srv/data/x"));
        assert!(!is_protected_host_mutation("/etcd/data")); // not under /etc
    }

    #[test]
    fn protected_paths() {
        assert!(is_protected_path("/"));
        assert!(is_protected_path(""));
        assert!(is_protected_path("/etc"));
        assert!(is_protected_path("/etc/"));
        assert!(is_protected_path("/usr"));
        assert!(is_protected_path("/var"));
        assert!(is_protected_path("  /bin  "));
        assert!(!is_protected_path("/etc/nginx"));
        assert!(!is_protected_path("/root/data")); // /root is protected, subdir isn't
        assert!(!is_protected_path("/home/user/file.txt"));
        assert!(!is_protected_path("/data"));
    }

    #[test]
    fn protected_paths_resist_traversal_bypass() {
        // Path tricks that resolve back onto a protected root must be blocked.
        assert!(is_protected_path("/etc/../etc"));
        assert!(is_protected_path("/var/./"));
        assert!(is_protected_path("/usr//"));
        assert!(is_protected_path("/root/../root"));
        assert!(is_protected_path("/etc/..")); // -> /
        assert!(is_protected_path("//")); // -> /
        assert!(is_protected_path("/./")); // -> /
        assert!(is_protected_path("/etc/nginx/..")); // -> /etc
        assert!(is_protected_path("/var/lib/../../var")); // -> /var
        assert!(is_protected_path("/usr/./bin/..")); // -> /usr
        assert!(is_protected_path("/../../../etc")); // -> /etc (can't climb above root)
                                                     // Legitimate subdirectory deletes must still be allowed after normalize.
        assert!(!is_protected_path("/etc/../etc/nginx")); // -> /etc/nginx
        assert!(!is_protected_path("/var/www//site/")); // -> /var/www/site
        assert!(!is_protected_path("/root/./data")); // -> /root/data
    }

    #[test]
    fn normalize_lexical_cases() {
        use super::normalize_lexical;
        assert_eq!(normalize_lexical("/etc/../etc"), "/etc");
        assert_eq!(normalize_lexical("/var/./"), "/var");
        assert_eq!(normalize_lexical("/usr//"), "/usr");
        assert_eq!(normalize_lexical("/root/../root"), "/root");
        assert_eq!(normalize_lexical("/"), "/");
        assert_eq!(normalize_lexical("//"), "/");
        assert_eq!(normalize_lexical("/etc/.."), "/");
        assert_eq!(normalize_lexical("/../../etc"), "/etc");
        assert_eq!(normalize_lexical("/etc/nginx/conf.d"), "/etc/nginx/conf.d");
    }

    #[test]
    fn parse_list_output_five_and_legacy_three_field() {
        use super::parse_list_output;
        // New 5-field shape: type\tsize\tmtime\tmode\tname (l prefix = symlink)…
        let out = "f\t42\t1700000000\t644\tb.txt\nd\t0\t1700000001\t755\tsub\nlf\t7\t0\t777\tlink";
        let v = parse_list_output(out, "/x");
        let entries = v["entries"].as_array().unwrap();
        // …sorted dirs-first, then by name.
        assert_eq!(entries[0]["name"], "sub");
        assert_eq!(entries[0]["is_dir"], true);
        assert_eq!(entries[0]["mode"], "755");
        assert_eq!(entries[1]["name"], "b.txt");
        assert_eq!(entries[1]["size"], 42);
        assert_eq!(entries[1]["mtime"], 1700000000i64);
        assert_eq!(entries[1]["is_symlink"], false);
        assert_eq!(entries[2]["name"], "link");
        assert_eq!(entries[2]["is_symlink"], true);
        // Legacy 3-field lines still parse (mtime/mode default).
        let v = parse_list_output("f\t9\told.txt", "/y");
        let e = &v["entries"].as_array().unwrap()[0];
        assert_eq!(e["size"], 9);
        assert_eq!(e["mtime"], 0);
        assert_eq!(e["mode"], "");
    }

    #[test]
    fn container_ref_validation() {
        assert!(valid_container_ref("my-app"));
        assert!(valid_container_ref("a1b2c3"));
        assert!(!valid_container_ref(""));
        assert!(!valid_container_ref("-rm"));
        assert!(!valid_container_ref("a b"));
    }

    #[test]
    fn tar_header_roundtrip() {
        // Build a real tar header with the `tar` crate, then parse it back.
        let mut h = tar::Header::new_gnu();
        h.set_size(1234);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::file());
        h.set_path("hello.txt").unwrap();
        h.set_cksum();
        let bytes = h.as_bytes();
        let (name, size) = parse_tar_header(bytes).expect("parse");
        assert_eq!(name, "hello.txt");
        assert_eq!(size, 1234);
    }

    #[test]
    fn tar_header_rejects_dir() {
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Directory);
        h.set_path("adir/").unwrap();
        h.set_cksum();
        assert!(parse_tar_header(h.as_bytes()).is_none());
    }
}
