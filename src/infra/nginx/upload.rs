//! Static-site content upload: ZIP extraction / per-file (split from nginx.rs).
use super::*;

// Static-site content upload (ZIP extraction / per-file), used by the web
// console's "static" site type. Writes into <www_store>/<root>/.
// ---------------------------------------------------------------------------

/// Static-site ZIP extraction limits. The upload body itself is capped at the
/// HTTP boundary, but compressed archives can expand far beyond that cap or
/// contain huge file counts. Keep both bounded while still allowing ordinary
/// static bundles.
pub(crate) const MAX_STATIC_ZIP_FILES: usize = 20_000;
pub(crate) const MAX_STATIC_ZIP_UNPACKED: u64 = 512 * 1024 * 1024;

/// Inputs for a static-site content upload (bundled to keep the entrypoints
/// within the param-count limit and make the call site self-documenting).
/// `mode` is "zip" (extract `temp` as a ZIP) or "file" (write it at `rel`);
/// `clear` wipes the webroot first; `temp` is the streamed-upload host temp file.
pub struct StaticUpload<'a> {
    pub root: &'a str,
    pub mode: &'a str,
    pub rel: Option<&'a str>,
    pub clear: bool,
    pub temp: &'a std::path::Path,
}

/// Public entrypoint for the web console's static-site upload. Returns the
/// number of files written. The body is never buffered fully in memory.
pub async fn web_static_upload(up: StaticUpload<'_>) -> Result<usize> {
    // The body is entirely synchronous (dir wipe + ZIP/DEFLATE extraction +
    // blocking file writes), which would pin a runtime worker for the whole
    // extraction. Run it on the blocking pool.
    let (root, mode, rel, clear, temp) = (
        up.root.to_string(),
        up.mode.to_string(),
        up.rel.map(str::to_string),
        up.clear,
        up.temp.to_path_buf(),
    );
    tokio::task::spawn_blocking(move || {
        web_static_upload_blocking(&StaticUpload {
            root: &root,
            mode: &mode,
            rel: rel.as_deref(),
            clear,
            temp: &temp,
        })
    })
    .await
    .map_err(|e| anyhow!("静态站点上传任务失败：{e}"))?
}

/// Synchronous implementation of [`web_static_upload`] — runs on the blocking
/// pool. See the async wrapper for the parameter contract.
fn web_static_upload_blocking(up: &StaticUpload) -> Result<usize> {
    let StaticUpload {
        root,
        mode,
        rel,
        clear,
        temp,
    } = *up;
    let lo = layout()?;
    if !valid_root_segment(root) {
        return Err(nginx_err(NginxError::BadStaticDir));
    }
    let dest = lo.www_store.join(root);
    std::fs::create_dir_all(&dest)?;
    if clear {
        // Wipe contents but keep the directory itself.
        if let Ok(entries) = std::fs::read_dir(&dest) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    let _ = std::fs::remove_dir_all(&p);
                } else {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    match mode {
        "zip" => {
            let f = std::fs::File::open(temp)?;
            extract_zip_from(f, &dest)
        }
        "file" => {
            let rel = rel.ok_or_else(|| nginx_err(NginxError::MissingFilePath))?;
            let safe = sanitize_rel(rel).ok_or_else(|| nginx_err(NginxError::BadFilePath))?;
            let target = dest.join(&safe);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(temp, &target)?; // streamed copy, bounded memory
            Ok(1)
        }
        _ => Err(nginx_err(NginxError::UnknownUploadMode)),
    }
}

/// Sanitize a relative path from an upload: reject absolute paths, `..`
/// traversal, and empty/oversized names. Returns a safe relative PathBuf.
pub(crate) fn sanitize_rel(rel: &str) -> Option<std::path::PathBuf> {
    let rel = rel.trim().replace('\\', "/");
    if rel.is_empty() || rel.len() > 1024 {
        return None;
    }
    let mut out = std::path::PathBuf::new();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None; // no traversal
        }
        // Reject NUL and control chars; allow normal filename characters.
        if seg.chars().any(|c| c.is_control()) {
            return None;
        }
        out.push(seg);
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    Some(out)
}

/// Extract a ZIP archive (pure-Rust `zip` crate) into `dest`, guarding against
/// path traversal. Returns the number of files written.
pub(crate) fn extract_zip_from<R: std::io::Read + std::io::Seek>(
    reader: R,
    dest: &std::path::Path,
) -> Result<usize> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| anyhow!("无法读取 ZIP：{e}"))?;
    let mut count = 0usize;
    let mut written = 0u64;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| anyhow!("读取 ZIP 条目失败：{e}"))?;
        // Use the archive's declared name; sanitize against traversal.
        let name = match entry.enclosed_name() {
            Some(p) => p.to_string_lossy().to_string(),
            None => continue,
        };
        if entry.is_dir() {
            let safe = match sanitize_rel(&name) {
                Some(p) => p,
                None => continue,
            };
            // Count directory entries against the same cap, else a ZIP of
            // millions of empty dirs is an uncounted inode/directory bomb.
            if count >= MAX_STATIC_ZIP_FILES {
                return Err(anyhow!(
                    "ZIP 文件数量超过限制（最多 {MAX_STATIC_ZIP_FILES} 个文件）"
                ));
            }
            std::fs::create_dir_all(dest.join(safe))?;
            count += 1;
            continue;
        }
        let safe = match sanitize_rel(&name) {
            Some(p) => p,
            None => continue,
        };
        let target = dest.join(&safe);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if count >= MAX_STATIC_ZIP_FILES {
            return Err(anyhow!(
                "ZIP 文件数量超过限制（最多 {MAX_STATIC_ZIP_FILES} 个文件）"
            ));
        }
        let declared = entry.size();
        if written.saturating_add(declared) > MAX_STATIC_ZIP_UNPACKED {
            return Err(anyhow!("ZIP 解压后体积超过限制（最多 512 MiB）"));
        }
        let mut out = std::fs::File::create(&target)?;
        let copied = match copy_zip_entry_limited(
            &mut entry,
            &mut out,
            MAX_STATIC_ZIP_UNPACKED.saturating_sub(written),
        ) {
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_file(&target);
                return Err(e);
            }
        };
        written += copied;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn copy_zip_entry_limited<R: std::io::Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        total = total.saturating_add(n as u64);
        if total > limit {
            return Err(anyhow!("ZIP 解压后体积超过限制（最多 512 MiB）"));
        }
        writer.write_all(&buf[..n])?;
    }
}
