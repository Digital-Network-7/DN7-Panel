//! Host filesystem operations (list/mkdir/delete/read/write) (split from file.rs).
use super::*;

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
