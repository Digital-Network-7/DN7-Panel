//! In-container filesystem operations (list/mkdir/delete/read/write) (split from file.rs).
use super::*;

/// List a container directory → `{ path, entries:[{name,is_dir,size,mtime,
/// mode,is_symlink}] }`. The in-container script emits the 5-field lines
/// [`parse_list_output`] expects (`t\tsize\tmtime\tmode\tname`, `l` prefix =
/// symlink); a missing/limited `stat` degrades to zeros, never fails the list.
pub async fn web_ctn_list(container: &str, path: &str) -> Result<serde_json::Value> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    if super::ctn_dn7::active() {
        return super::ctn_dn7::list(container, path).await;
    }
    let dir = if path.trim().is_empty() { "/" } else { path };
    check_abs(dir)?;
    let script = r#"cd "$1" 2>/dev/null || exit 7
for name in * .[!.]* ..?*; do
  [ -e "$name" ] || [ -L "$name" ] || continue
  t=f; [ -d "$name" ] && t=d
  [ -L "$name" ] && t=l$t
  set -- $(stat -c '%s %Y %a' "$name" 2>/dev/null || echo 0 0 0)
  sz=$1
  case "$t" in
    d|ld) sz=0;;
    lf) sz=$(stat -Lc %s "$name" 2>/dev/null || echo 0);;
  esac
  printf '%s\t%s\t%s\t%s\t%s\n' "$t" "$sz" "$2" "$3" "$name"
done"#;
    let (code, stdout) = ctn_exec_collect(container, script, &[dir]).await?;
    if code != 0 {
        return Err(anyhow!("目录不存在或无权限"));
    }
    Ok(parse_list_output(&stdout, dir))
}

/// Whether a path exists inside a container (upload-conflict checks).
pub async fn web_ctn_exists(container: &str, path: &str) -> Result<bool> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    if super::ctn_dn7::active() {
        return super::ctn_dn7::exists(container, path).await;
    }
    check_abs(path)?;
    let (code, _) = ctn_exec_collect(container, r#"[ -e "$1" ] || [ -L "$1" ]"#, &[path]).await?;
    Ok(code == 0)
}

/// Rename/move a path inside a container (`to` is the full new path), refusing
/// protected system dirs on both ends and an existing destination.
pub async fn web_ctn_rename(container: &str, from: &str, to: &str) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    if super::ctn_dn7::active() {
        return super::ctn_dn7::rename(container, from, to).await;
    }
    if is_protected_path(from) || is_protected_path(to) {
        return Err(anyhow!("该系统目录受保护，禁止移动"));
    }
    check_abs(from)?;
    check_abs(to)?;
    // `{ a || b; } && exit 8`: refuse an existing destination (no clobber).
    let script = r#"{ [ -e "$2" ] || [ -L "$2" ]; } && exit 8; mv "$1" "$2""#;
    let (code, out) = ctn_exec_collect(container, script, &[from, to]).await?;
    match code {
        0 => Ok(()),
        8 => Err(anyhow!("目标已存在")),
        _ => {
            let msg = out.trim();
            Err(anyhow!(if msg.is_empty() {
                "重命名失败".to_string()
            } else {
                msg.chars().take(300).collect::<String>()
            }))
        }
    }
}

/// Create a directory inside a container.
pub async fn web_ctn_mkdir(container: &str, path: &str) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    if super::ctn_dn7::active() {
        return super::ctn_dn7::mkdir(container, path).await;
    }
    ctn_exec_ok(container, "mkdir -p \"$1\"", &[path]).await
}

/// Delete a path inside a container (refusing protected system dirs).
pub async fn web_ctn_delete(container: &str, path: &str) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    if super::ctn_dn7::active() {
        return super::ctn_dn7::delete(container, path).await;
    }
    if is_protected_path(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    ctn_exec_ok(container, "rm -rf \"$1\"", &[path]).await
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
    if super::ctn_dn7::active() {
        return super::ctn_dn7::read_stream(container, path).await;
    }
    check_abs(path)?;
    let dkr = crate::infra::docker::dkr()?;
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
                // Archive ended before all `remaining` content bytes arrived:
                // surface an error so the client sees a failed transfer rather
                // than a silently-truncated file reported as success.
                None => Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "容器归档流意外结束，文件可能不完整",
                    )),
                    (stream, 0, Bytes::new()),
                )),
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
    if super::ctn_dn7::active() {
        return super::ctn_dn7::write_file(container, dest_path, temp).await;
    }
    check_abs(dest_path)?;
    ctn_upload_file(container, temp, dest_path).await
}
