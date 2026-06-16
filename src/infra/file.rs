//! On-box file transfer for the web console.
//!
//! Plain request/response operations (list / mkdir / delete / download /
//! upload) against the host filesystem and inside Docker containers (via the
//! daemon archive + exec APIs — no `docker` CLI). Used directly by
//! `web::server`; there is no backend relay.

use std::path::Path;
use std::pin::Pin;

use anyhow::{anyhow, Result};
use bytes::Bytes;

// The sensitive-path guards normalize first via the shared domain rule (a raw
// prefix match is bypassable by `//etc`, `/./etc`, `/srv/../etc`).
use crate::domain::path::normalize_lexical;

/// A chunked byte stream used for streaming downloads (no full-file buffering).
pub type ByteStream = Pin<Box<dyn futures::Stream<Item = std::io::Result<Bytes>> + Send>>;

/// Chunk size for streaming file content (256 KiB).
const CHUNK: usize = 256 * 1024;

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
fn is_protected_path(path: &str) -> bool {
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
fn is_protected_host_mutation(path: &str) -> bool {
    let norm = normalize_lexical(path);
    if is_protected_path(&norm) {
        return true;
    }
    const TREES: &[&str] = &["/etc", "/root", "/boot", "/proc", "/sys", "/dev"];
    TREES.iter().any(|t| norm.starts_with(&format!("{t}/")))
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
fn valid_container_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
}

/// Require an absolute path (so it can't be read as a CLI flag).
fn check_abs(path: &str) -> Result<()> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(anyhow!("路径必须为绝对路径"))
    }
}

/// Shell script (POSIX sh) that lists a directory as tab-separated
/// `type\tsize\tname` lines. Shared by the container exec path and the
/// run-as-user host path. The directory is `$1` (a separate argv entry).
const LIST_SCRIPT: &str = r#"cd "$1" 2>/dev/null || exit 7
for name in * .[!.]* ..?*; do
  [ -e "$name" ] || [ -L "$name" ] || continue
  if [ -d "$name" ]; then
    printf 'd\t0\t%s\n' "$name"
  else
    sz=$(stat -c %s "$name" 2>/dev/null || stat -f %z "$name" 2>/dev/null || echo 0)
    printf 'f\t%s\t%s\n' "$sz" "$name"
  fi
done"#;

/// Parse the `LIST_SCRIPT` output into sorted directory entries (dirs first).
fn parse_list_output(stdout: &str, dir: &str) -> serde_json::Value {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let mut it = line.splitn(3, '\t');
        let t = it.next().unwrap_or("");
        let sz = it.next().unwrap_or("0");
        let name = match it.next() {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let is_dir = t == "d";
        let size: u64 = sz.trim().parse().unwrap_or(0);
        entries.push(serde_json::json!({ "name": name, "is_dir": is_dir, "size": size }));
    }
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
    serde_json::json!({ "path": dir, "entries": entries })
}

/// Run a POSIX-sh script **as another system user** via `su` (root → user needs
/// no password). `arg` is passed as `$1` (a separate argv entry — no shell
/// injection). Optional `stdin` is streamed in. Returns (exit_code, stdout).
/// Used so a non-admin panel user's file operations run with *their* uid and the
/// OS enforces access (no privilege escalation).
async fn run_as_user(
    user: &str,
    script: &str,
    arg: &str,
    stdin: Option<&[u8]>,
) -> Result<(i32, Vec<u8>)> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let mut cmd = tokio::process::Command::new("su");
    // options first, then user, then positional args ($0, $1...) for `-c`.
    cmd.args(["-s", "/bin/sh", "-c", script, user, "sh", arg]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
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
mod ctn;
use ctn::*;
mod ctnfs;
mod hostfs;
pub(crate) use ctnfs::*;
pub(crate) use hostfs::*;

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
