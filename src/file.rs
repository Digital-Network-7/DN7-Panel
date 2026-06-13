//! On-box file transfer for the web console.
//!
//! Plain request/response operations (list / mkdir / delete / download /
//! upload) against the host filesystem and inside Docker containers (via the
//! daemon archive + exec APIs — no `docker` CLI). Used directly by
//! `web::server`; there is no backend relay.

use std::path::Path;

use anyhow::{anyhow, Result};

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

/// A short, collision-resistant suffix for a host temp file name (pid + a
/// monotonic counter). Avoids pulling in a uuid dependency just for this.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}", std::process::id(), n)
}

/// Run `sh -c '<script>' sh "<arg>"` inside the container via the daemon exec
/// API. `arg` becomes `$1` (a separate argv entry — no shell injection). Returns
/// (exit_code, stdout, stderr-ish combined). No `docker` CLI required.
async fn ctn_exec_collect(container: &str, script: &str, arg: &str) -> Result<(i64, String)> {
    use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
    use futures::StreamExt;

    let dkr = crate::docker::dkr()?;
    let exec = dkr
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    script.to_string(),
                    "sh".to_string(),
                    arg.to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{e}"))?;
    let started = dkr
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{e}"))?;

    let mut buf = String::new();
    if let StartExecResults::Attached { mut output, .. } = started {
        while let Some(item) = output.next().await {
            if let Ok(msg) = item {
                buf.push_str(&String::from_utf8_lossy(&msg.into_bytes()));
            }
        }
    }
    // Inspect for the real exit code.
    let code = dkr
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|i| i.exit_code)
        .unwrap_or(0);
    Ok((code, buf))
}

/// Run a container script expecting a zero exit (mkdir/delete).
async fn ctn_exec_ok(container: &str, script: &str, arg: &str) -> Result<()> {
    check_abs(arg)?;
    let (code, out) = ctn_exec_collect(container, script, arg).await?;
    if code == 0 {
        Ok(())
    } else {
        let msg = out.trim();
        Err(anyhow!(if msg.is_empty() {
            "操作失败".to_string()
        } else {
            msg.chars().take(300).collect::<String>()
        }))
    }
}

/// Upload a host temp file into the container at `dest_path` using the archive
/// (tar) API, **streaming** the tar body (header + file content read in chunks +
/// padding + footer) so we never hold the whole file in memory. Works even on
/// shell-less images.
async fn ctn_upload_file(container: &str, temp_path: &Path, dest_path: &str) -> Result<()> {
    check_abs(dest_path)?;
    let dest = Path::new(dest_path);
    let parent = dest
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());
    let fname = dest
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .ok_or_else(|| anyhow!("目标路径无效"))?;

    // File size (for the tar header) from metadata — no full read.
    let size = tokio::fs::metadata(temp_path).await?.len();

    // Build the 512-byte tar header up front (size is known).
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::file());
    header
        .set_path(&fname)
        .map_err(|e| anyhow!("打包失败：{e}"))?;
    header.set_cksum();

    let body = upload_tar_stream(header, temp_path.to_path_buf(), size);

    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::UploadToContainerOptions {
        path: parent,
        ..Default::default()
    };
    dkr.upload_to_container_streaming(container, Some(opts), body)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// Build a streaming tar body for a single file: 512-byte header, then the file
/// content read in CHUNK pieces, then NUL padding to a 512 boundary, then the
/// two zero blocks that terminate a tar. Never buffers the whole file.
fn upload_tar_stream(
    header: tar::Header,
    temp_path: std::path::PathBuf,
    size: u64,
) -> impl futures::Stream<Item = bytes::Bytes> + Send + 'static {
    use bytes::Bytes;

    // Tar stages emitted in order.
    enum Stage {
        Header,
        Body { file: tokio::fs::File, left: u64 },
        Pad,
        Footer,
        Done,
    }

    let header_bytes = Bytes::copy_from_slice(header.as_bytes());
    let pad = ((512 - (size % 512)) % 512) as usize;

    futures::stream::unfold(Stage::Header, move |stage| {
        let header_bytes = header_bytes.clone();
        let temp_path = temp_path.clone();
        async move {
            use tokio::io::AsyncReadExt;
            match stage {
                Stage::Header => {
                    // Open the file lazily for the body stage.
                    let next = if size > 0 {
                        match tokio::fs::File::open(&temp_path).await {
                            Ok(file) => Stage::Body { file, left: size },
                            // On open failure, end the stream early (upload fails
                            // server-side with a truncated/invalid tar).
                            Err(_) => Stage::Done,
                        }
                    } else if pad > 0 {
                        Stage::Pad
                    } else {
                        Stage::Footer
                    };
                    Some((header_bytes, next))
                }
                Stage::Body { mut file, left } => {
                    let want = (left as usize).min(CHUNK);
                    let mut buf = vec![0u8; want];
                    match file.read(&mut buf).await {
                        Ok(0) => {
                            // Unexpected EOF; move on to padding/footer.
                            let next = if pad > 0 { Stage::Pad } else { Stage::Footer };
                            // Emit nothing this step — recurse via an empty chunk.
                            Some((Bytes::new(), next))
                        }
                        Ok(n) => {
                            buf.truncate(n);
                            let remaining = left - n as u64;
                            let next = if remaining > 0 {
                                Stage::Body {
                                    file,
                                    left: remaining,
                                }
                            } else if pad > 0 {
                                Stage::Pad
                            } else {
                                Stage::Footer
                            };
                            Some((Bytes::from(buf), next))
                        }
                        Err(_) => Some((Bytes::new(), Stage::Footer)),
                    }
                }
                Stage::Pad => Some((Bytes::from(vec![0u8; pad]), Stage::Footer)),
                // Tar archives end with two 512-byte zero blocks.
                Stage::Footer => Some((Bytes::from(vec![0u8; 1024]), Stage::Done)),
                Stage::Done => None,
            }
        }
    })
}

/// Parse a POSIX/GNU tar header: file base name (bytes 0..100, NUL-terminated)
/// and content size (octal ASCII, bytes 124..136). Returns None if the entry
/// isn't a regular file or the header is malformed.
fn parse_tar_header(h: &[u8]) -> Option<(String, u64)> {
    if h.len() < 512 {
        return None;
    }
    // Type flag at offset 156: '0' or '\0' == regular file.
    let typeflag = h[156];
    if !(typeflag == b'0' || typeflag == 0) {
        return None;
    }
    // Name (may be empty if using a GNU long-name extension, which docker
    // doesn't emit for a single file copy).
    let name_end = h[0..100].iter().position(|&b| b == 0).unwrap_or(100);
    let raw_name = String::from_utf8_lossy(&h[0..name_end]).to_string();
    let base = raw_name
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download")
        .to_string();
    // Size: octal ASCII in bytes 124..136.
    let size_field = &h[124..136];
    let size_str = String::from_utf8_lossy(size_field);
    let size = u64::from_str_radix(size_str.trim().trim_end_matches('\0').trim(), 8).ok()?;
    Some((base, size))
}

/// Map a bollard archive error to a friendly message.
fn friendly_archive_err(e: &bollard::errors::Error) -> String {
    let s = e.to_string();
    if s.contains("no such file") || s.contains("not found") || s.contains("404") {
        "文件不存在".to_string()
    } else {
        s.chars().take(300).collect()
    }
}

// ---------------------------------------------------------------------------
// Web console (axum) file operations — plain request/response over HTTP, no
// WebSocket relay. Host paths use tokio::fs directly; container paths reuse the
// daemon exec / archive helpers above. Used by `web::server`.
// ---------------------------------------------------------------------------

/// List a host directory → `{ path, entries:[{name,is_dir,size}] }`.
pub async fn web_host_list(path: &str) -> Result<serde_json::Value> {
    let dir = if path.trim().is_empty() { "/" } else { path };
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

/// Create a host directory (recursive).
pub async fn web_host_mkdir(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    tokio::fs::create_dir_all(path).await?;
    Ok(())
}

/// Delete a host path (file or directory), refusing protected system dirs.
pub async fn web_host_delete(path: &str) -> Result<()> {
    // Lexical guard (handles `..`, `.`, `//`, trailing slashes).
    if is_protected_path(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    // Stronger host guard: resolve the real on-disk target (following symlinks
    // and any remaining indirection) and re-check, so a path that *resolves* to
    // a protected root — e.g. via a symlink — is still refused.
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

/// Read a whole host file → (file name, bytes). Refuses directories.
pub async fn web_host_read(path: &str) -> Result<(String, Vec<u8>)> {
    let md = tokio::fs::metadata(path).await?;
    if md.is_dir() {
        return Err(anyhow!("不能下载目录"));
    }
    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    let bytes = tokio::fs::read(path).await?;
    Ok((name, bytes))
}

/// Write bytes to a host file (overwrite/create).
pub async fn web_host_write(path: &str, bytes: &[u8]) -> Result<()> {
    if path.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    tokio::fs::write(path, bytes).await?;
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

/// Read a whole file out of a container → (file name, bytes), via the archive
/// (tar) API. Buffers the file in memory (web console transfers are modest).
pub async fn web_ctn_read(container: &str, path: &str) -> Result<(String, Vec<u8>)> {
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

    let mut header: Vec<u8> = Vec::with_capacity(512);
    let mut begun = false;
    let mut remaining: u64 = 0;
    let mut name = String::from("download");
    let mut content: Vec<u8> = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!(friendly_archive_err(&e)))?;
        let mut data: &[u8] = &chunk;
        if !begun {
            let need = 512 - header.len();
            let take = need.min(data.len());
            header.extend_from_slice(&data[..take]);
            data = &data[take..];
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
        }
        if remaining > 0 && !data.is_empty() {
            let content_len = (remaining as usize).min(data.len());
            content.extend_from_slice(&data[..content_len]);
            remaining -= content_len as u64;
        }
        if begun && remaining == 0 {
            break;
        }
    }
    if !begun {
        return Err(anyhow!("文件不存在"));
    }
    Ok((name, content))
}

/// Write bytes into a container at `dest_path` (via a host temp file + the
/// archive API). Works on shell-less images.
pub async fn web_ctn_write(container: &str, dest_path: &str, bytes: &[u8]) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    check_abs(dest_path)?;
    let temp_path = std::env::temp_dir().join(format!("dn7-ctn-web-{}", unique_suffix()));
    tokio::fs::write(&temp_path, bytes).await?;
    let res = ctn_upload_file(container, &temp_path, dest_path).await;
    let _ = tokio::fs::remove_file(&temp_path).await;
    res
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
