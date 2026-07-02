//! Host filesystem operations (list/mkdir/delete/read/write) (split from file.rs).
use super::*;

// ---------------------------------------------------------------------------
// Web console (axum) file operations — plain request/response over HTTP, no
// WebSocket relay. Host paths use tokio::fs directly; container paths reuse the
// daemon exec / archive helpers above. Used by `web::server`.
// ---------------------------------------------------------------------------

/// List a host directory → `{ path, entries:[{name,is_dir,size,mtime,mode,
/// is_symlink}] }`. When `as_user` is set, the listing runs as that system
/// user (OS perms enforced).
pub async fn web_host_list(path: &str, as_user: Option<&str>) -> Result<serde_json::Value> {
    let dir = if path.trim().is_empty() { "/" } else { path };
    if let Some(u) = as_user {
        check_abs(dir)?;
        let (code, out) = run_fs_helper(u, "list", dir, None).await?;
        if code != 0 {
            return Err(anyhow!("目录不存在或无权限"));
        }
        return Ok(parse_list_output(&String::from_utf8_lossy(&out), dir));
    }
    let mut entries = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        let name = ent.file_name().to_string_lossy().to_string();
        // No-follow metadata for the entry itself; resolve symlinks once more
        // so a link to a directory navigates like a directory.
        let lmd = ent.metadata().await.ok();
        let fmd = match &lmd {
            Some(m) if m.file_type().is_symlink() => tokio::fs::metadata(ent.path()).await.ok(),
            _ => None,
        };
        entries.push(fs_entry_json(&name, lmd.as_ref(), fmd.as_ref()));
    }
    sort_entries(&mut entries);
    Ok(serde_json::json!({ "path": dir, "entries": entries }))
}

/// Whether a host path exists (no-follow lstat), for upload-conflict checks.
/// Runs as `as_user` when set, so the probe can't leak paths the caller's own
/// OS permissions wouldn't reveal.
pub async fn web_host_exists(path: &str, as_user: Option<&str>) -> Result<bool> {
    if let Some(u) = as_user {
        check_abs(path)?;
        let (code, _) = run_fs_helper(u, "stat", path, None).await?;
        return Ok(code == 0);
    }
    Ok(tokio::fs::symlink_metadata(path).await.is_ok())
}

/// Create a host directory (recursive). Runs as `as_user` when set.
pub async fn web_host_mkdir(path: &str, as_user: Option<&str>) -> Result<()> {
    if path.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    if is_protected_host_mutation(path) {
        return Err(anyhow!("该系统目录受保护，禁止写入"));
    }
    if let Some(u) = as_user {
        check_abs(path)?;
        let (code, _) = run_fs_helper(u, "mkdir", path, None).await?;
        return if code == 0 {
            Ok(())
        } else {
            Err(anyhow!("创建目录失败（无权限？）"))
        };
    }
    // Root path: also refuse a target that resolves into a protected tree via a
    // symlinked ancestor (the lexical guard above can't see symlinks).
    if resolves_into_protected(path).await {
        return Err(anyhow!("该系统目录受保护，禁止写入"));
    }
    tokio::fs::create_dir_all(path).await?;
    Ok(())
}

/// Delete a host path (file or directory), refusing protected system dirs.
/// Runs as `as_user` when set (OS perms enforced).
pub async fn web_host_delete(path: &str, as_user: Option<&str>) -> Result<()> {
    // Lexical guard (handles `..`, `.`, `//`, trailing slashes) — now also
    // blocks descendants of the sensitive trees (e.g. /etc/shadow).
    if is_protected_host_mutation(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    if let Some(u) = as_user {
        check_abs(path)?;
        let (code, _) = run_fs_helper(u, "remove", path, None).await?;
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
        if is_protected_host_mutation(&canon.to_string_lossy()) {
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

/// Rename/move a host path (`to` is the full new path). Refuses protected
/// system trees on BOTH ends and an existing destination (no silent clobber).
/// Runs as `as_user` when set (OS perms enforced).
pub async fn web_host_rename(from: &str, to: &str, as_user: Option<&str>) -> Result<()> {
    if from.trim().is_empty() || to.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    if is_protected_host_mutation(from) || is_protected_host_mutation(to) {
        return Err(anyhow!("该系统目录受保护，禁止移动"));
    }
    check_abs(from)?;
    check_abs(to)?;
    if let Some(u) = as_user {
        // Destination travels on stdin (the helper takes ONE path argv slot).
        let (code, _) = run_fs_helper(u, "rename", from, Some(to.as_bytes())).await?;
        return match code {
            0 => Ok(()),
            8 => Err(anyhow!("目标已存在")),
            _ => Err(anyhow!("重命名失败（无权限？）")),
        };
    }
    // Root path: refuse either end resolving into a protected tree via a
    // symlinked ancestor (the lexical guard above can't see symlinks).
    if resolves_into_protected(from).await || resolves_into_protected(to).await {
        return Err(anyhow!("该系统目录受保护，禁止移动"));
    }
    if tokio::fs::symlink_metadata(to).await.is_ok() {
        return Err(anyhow!("目标已存在"));
    }
    if let Err(e) = tokio::fs::rename(from, to).await {
        // A rename across filesystems fails with EXDEV (os error 18); the raw
        // message ("Invalid cross-device link") is opaque. Surface a stable code
        // the client localizes into "download & re-upload" guidance. A copy+
        // unlink fallback is out of scope — the clear error is enough.
        if e.raw_os_error() == Some(18) {
            return Err(anyhow!("ERR_CODE:files.cross_device"));
        }
        return Err(e.into());
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
        use futures::StreamExt;
        use std::process::Stdio;
        check_abs(path)?;
        // Re-exec the privilege-dropping `__fshelper read` (replaces `su … cat`):
        // the helper drops to user `u` and streams the file to stdout.
        let exe = std::env::current_exe().map_err(|e| anyhow!("无法定位自身：{e}"))?;
        let mut child = tokio::process::Command::new(exe)
            .args(["__fshelper", "read", u, path])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("无法以用户身份读取：{e}"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("无法读取文件"))?;
        // Forward the helper's stdout, THEN observe its exit code at EOF: the
        // `read` op exits non-zero (9) for a missing file / no permission / dir
        // while emitting zero bytes. The old fire-and-forget `wait()` discarded
        // that, so a failed read looked like a clean empty file — the editor
        // showed "" AND the audit recorded success. Surface the non-zero exit as
        // a stream error so the buffered read (files_read) returns Err → the
        // client sees a real failure and the audit records false. The download
        // path drains this same stream inside `AuditedStream`, which likewise
        // turns the trailing error into an `ok=false` record (a valid file exits
        // 0, so its bytes are forwarded unchanged).
        let reader = tokio_util::io::ReaderStream::new(stdout);
        let s = futures::stream::unfold(
            (reader, Some(child), false),
            |(mut reader, mut child, done)| async move {
                if done {
                    return None;
                }
                match reader.next().await {
                    Some(chunk) => Some((chunk, (reader, child, false))),
                    // stdout drained: reap the child and check its exit status.
                    None => {
                        let ok = match child.as_mut() {
                            Some(c) => c.wait().await.map(|s| s.success()).unwrap_or(false),
                            None => true,
                        };
                        if ok {
                            None
                        } else {
                            Some((
                                Err(std::io::Error::other("ERR_CODE:files.read_failed")),
                                (reader, None, true),
                            ))
                        }
                    }
                }
            },
        );
        return Ok((name, Box::pin(s)));
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
    if is_protected_host_mutation(dest) {
        return Err(anyhow!("该系统目录受保护，禁止写入"));
    }
    if let Some(u) = as_user {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        check_abs(dest)?;
        // Re-exec the privilege-dropping `__fshelper write` (replaces `su … cat >`):
        // the helper drops to user `u` and streams stdin into the destination.
        let exe = std::env::current_exe().map_err(|e| anyhow!("无法定位自身：{e}"))?;
        let mut child = tokio::process::Command::new(exe)
            .args(["__fshelper", "write", u, dest])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
    // Root path: refuse a destination that resolves into a protected tree via a
    // symlinked ancestor (lexical guard above can't see symlinks).
    if resolves_into_protected(dest).await {
        return Err(anyhow!("该系统目录受保护，禁止写入"));
    }
    // A symlinked *final component* would let a pre-planted link redirect this
    // root write outside the intended path (e.g. a dangling `x -> /etc/cron.d/y`,
    // whose missing target makes `resolves_into_protected` above miss it). No-follow
    // lstat the destination and refuse any symlink leaf — `fs::copy` follows it.
    if let Ok(md) = tokio::fs::symlink_metadata(dest).await {
        if md.file_type().is_symlink() {
            return Err(anyhow!("目标为符号链接，禁止写入"));
        }
    }
    tokio::fs::copy(temp, dest).await?; // chunked copy, bounded memory
    Ok(())
}
