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

/// Lexically normalize a path: resolve `.` and `..` segments, collapse repeated
/// and trailing separators. Purely textual — no filesystem or symlink
/// resolution — so it's safe to use for container paths too. `..` can never
/// climb above the root. Always returns an absolute path; "/" for the root.
fn normalize_lexical(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.trim().split('/') {
        match seg {
            "" | "." => {} // leading/repeated '/', trailing '/', or '.'
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
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

// ---------------------------------------------------------------------------
// Web console (axum) file operations — plain request/response over HTTP, no
// WebSocket relay. Host paths use tokio::fs directly; container paths reuse the
// daemon exec / archive helpers above. Used by `web::server`.
// ---------------------------------------------------------------------------

/// List a host directory → `{ path, entries:[{name,is_dir,size}] }`. When
/// `as_user` is set, the listing runs as that system user (OS perms enforced).
pub async fn web_host_list(path: &str, as_user: Option<&str>) -> Result<serde_json::Value> {
    let dir = if path.trim().is_empty() { "/" } else { path };
    if let Some(u) = as_user {
        check_abs(dir)?;
        let (code, out) = run_as_user(u, LIST_SCRIPT, dir, None).await?;
        if code != 0 {
            return Err(anyhow!("目录不存在或无权限"));
        }
        return Ok(parse_list_output(&String::from_utf8_lossy(&out), dir));
    }
    let mut entries = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        let name = ent.file_name().to_string_lossy().to_string();
        let md = ent.metadata().await.ok();
        let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
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
    Ok(serde_json::json!({ "path": dir, "entries": entries }))
}

/// Create a host directory (recursive). Runs as `as_user` when set.
pub async fn web_host_mkdir(path: &str, as_user: Option<&str>) -> Result<()> {
    if path.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    if let Some(u) = as_user {
        check_abs(path)?;
        let (code, _) = run_as_user(u, "mkdir -p -- \"$1\"", path, None).await?;
        return if code == 0 {
            Ok(())
        } else {
            Err(anyhow!("创建目录失败（无权限？）"))
        };
    }
    tokio::fs::create_dir_all(path).await?;
    Ok(())
}

/// Delete a host path (file or directory), refusing protected system dirs.
/// Runs as `as_user` when set (OS perms enforced).
pub async fn web_host_delete(path: &str, as_user: Option<&str>) -> Result<()> {
    // Lexical guard (handles `..`, `.`, `//`, trailing slashes).
    if is_protected_path(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    if let Some(u) = as_user {
        check_abs(path)?;
        let (code, _) = run_as_user(u, "rm -rf -- \"$1\"", path, None).await?;
        return if code == 0 {
            Ok(())
        } else {
            Err(anyhow!("删除失败（无权限？）"))
        };
    }
    // Stronger host guard (root path): resolve the real on-disk target
    // (following symlinks) and re-check, so a path that *resolves* to a
    // protected root — e.g. via a symlink — is still refused.
    if let Ok(canon) = tokio::fs::canonicalize(path).await {
        if is_protected_path(&canon.to_string_lossy()) {
            return Err(anyhow!("该系统目录受保护，禁止删除"));
        }
    }
    let p = Path::new(path);
    if p.is_dir() {
        tokio::fs::remove_dir_all(path).await?;
    } else {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

/// Open a host file for **streaming** download → (file name, byte stream).
/// Refuses directories. When `as_user` is set the read runs as that system
/// user (a `su` child whose stdout is streamed; OS perms enforced).
pub async fn web_host_read_stream(
    path: &str,
    as_user: Option<&str>,
) -> Result<(String, ByteStream)> {
    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    if let Some(u) = as_user {
        use std::process::Stdio;
        check_abs(path)?;
        let mut child = tokio::process::Command::new("su")
            .args([
                "-s",
                "/bin/sh",
                "-c",
                "[ -f \"$1\" ] || exit 9; exec cat -- \"$1\"",
                u,
                "sh",
                path,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("无法以用户身份读取：{e}"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("无法读取文件"))?;
        // Reap the child once its stdout is drained (avoids a zombie).
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        return Ok((name, Box::pin(tokio_util::io::ReaderStream::new(stdout))));
    }
    let md = tokio::fs::metadata(path).await?;
    if md.is_dir() {
        return Err(anyhow!("不能下载目录"));
    }
    let file = tokio::fs::File::open(path).await?;
    Ok((name, Box::pin(tokio_util::io::ReaderStream::new(file))))
}

/// Write an already-staged temp file to a host destination, **streaming** the
/// bytes (never holding the whole file in memory). Runs as `as_user` when set.
pub async fn web_host_write_file(dest: &str, temp: &Path, as_user: Option<&str>) -> Result<()> {
    if dest.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    if let Some(u) = as_user {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        check_abs(dest)?;
        let mut child = tokio::process::Command::new("su")
            .args(["-s", "/bin/sh", "-c", "cat > \"$1\"", u, "sh", dest])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("无法以用户身份写入：{e}"))?;
        if let Some(mut si) = child.stdin.take() {
            let mut f = tokio::fs::File::open(temp).await?;
            let _ = tokio::io::copy(&mut f, &mut si).await; // streamed, chunked
            let _ = si.shutdown().await;
        }
        let out = child.wait_with_output().await.map_err(|e| anyhow!("{e}"))?;
        return if out.status.success() {
            Ok(())
        } else {
            Err(anyhow!("写入失败（无权限？）"))
        };
    }
    tokio::fs::copy(temp, dest).await?; // chunked copy, bounded memory
    Ok(())
}

/// List a container directory → `{ path, entries:[{name,is_dir,size}] }`.
pub async fn web_ctn_list(container: &str, path: &str) -> Result<serde_json::Value> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    let dir = if path.trim().is_empty() { "/" } else { path };
    check_abs(dir)?;
    let script = r#"cd "$1" 2>/dev/null || exit 7
for name in * .[!.]* ..?*; do
  [ -e "$name" ] || [ -L "$name" ] || continue
  if [ -d "$name" ]; then
    printf 'd\t0\t%s\n' "$name"
  else
    sz=$(stat -c %s "$name" 2>/dev/null || stat -f %z "$name" 2>/dev/null || echo 0)
    printf 'f\t%s\t%s\n' "$sz" "$name"
  fi
done"#;
    let (code, stdout) = ctn_exec_collect(container, script, dir).await?;
    if code != 0 {
        return Err(anyhow!("目录不存在或无权限"));
    }
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
    Ok(serde_json::json!({ "path": dir, "entries": entries }))
}

/// Create a directory inside a container.
pub async fn web_ctn_mkdir(container: &str, path: &str) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    ctn_exec_ok(container, "mkdir -p \"$1\"", path).await
}

/// Delete a path inside a container (refusing protected system dirs).
pub async fn web_ctn_delete(container: &str, path: &str) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    if is_protected_path(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    ctn_exec_ok(container, "rm -rf \"$1\"", path).await
}

/// Open a file in a container for **streaming** download → (file name, byte
/// stream), via the archive (tar) API. The tar header is parsed up front (to
/// learn the name + size), then content bytes are forwarded chunk-by-chunk as
/// they arrive — never buffering the whole file.
pub async fn web_ctn_read_stream(container: &str, path: &str) -> Result<(String, ByteStream)> {
    use futures::StreamExt;

    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    check_abs(path)?;
    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::DownloadFromContainerOptions {
        path: path.to_string(),
    };
    let mut stream = dkr.download_from_container(container, Some(opts));

    // Read just enough leading bytes to parse the 512-byte tar header.
    let mut header: Vec<u8> = Vec::with_capacity(512);
    let mut leftover: Bytes = Bytes::new();
    let mut name = String::from("download");
    let mut remaining: u64 = 0;
    let mut begun = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!(friendly_archive_err(&e)))?;
        if header.len() < 512 {
            let need = 512 - header.len();
            let take = need.min(chunk.len());
            header.extend_from_slice(&chunk[..take]);
            if header.len() < 512 {
                continue;
            }
            let (n, size) =
                parse_tar_header(&header).ok_or_else(|| anyhow!("不能下载目录或空文件"))?;
            if size == 0 {
                return Err(anyhow!("不能下载目录或空文件"));
            }
            name = n;
            remaining = size;
            begun = true;
            leftover = chunk.slice(take..); // content bytes already in this chunk
            break;
        }
    }
    if !begun {
        return Err(anyhow!("文件不存在"));
    }
    // Emit the leftover content first, then keep pulling from the archive
    // stream until `remaining` content bytes have been forwarded.
    let s = futures::stream::unfold(
        (stream, remaining, leftover),
        |(mut stream, mut remaining, mut leftover)| async move {
            if remaining == 0 {
                return None;
            }
            if !leftover.is_empty() {
                let n = (remaining as usize).min(leftover.len());
                let out = leftover.split_to(n);
                remaining -= n as u64;
                return Some((Ok(out), (stream, remaining, leftover)));
            }
            match stream.next().await {
                Some(Ok(chunk)) => {
                    let n = (remaining as usize).min(chunk.len());
                    let out = chunk.slice(0..n);
                    remaining -= n as u64;
                    Some((Ok(out), (stream, remaining, Bytes::new())))
                }
                Some(Err(e)) => Some((
                    Err(std::io::Error::other(friendly_archive_err(&e))),
                    (stream, 0, Bytes::new()),
                )),
                None => None,
            }
        },
    );
    Ok((name, Box::pin(s)))
}

/// Upload an already-staged temp file into a container at `dest_path` via the
/// archive (tar) API (the tar body is streamed from the temp file). Works on
/// shell-less images.
pub async fn web_ctn_write_file(container: &str, dest_path: &str, temp: &Path) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    check_abs(dest_path)?;
    ctn_upload_file(container, temp, dest_path).await
}

#[cfg(test)]
mod tests {
    use super::{is_protected_path, parse_tar_header, valid_container_ref};

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
