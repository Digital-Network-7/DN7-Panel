//! Static-site content upload: ZIP extraction / per-file (split from nginx.rs).
use super::*;

// Static-site content upload (ZIP extraction / per-file), used by the web
// console's "static" site type. Writes into <www_store>/<root>/.
// ---------------------------------------------------------------------------

/// Public entrypoint for the web console's static-site upload. `mode` is "zip"
/// (extract `body` as a ZIP archive) or "file" (write `body` as a single file
/// at `rel` within the webroot). `clear` wipes the webroot first. Returns the
/// number of files written. `temp` is a host temp file holding the streamed
/// upload body (never buffered fully in memory).
pub async fn web_static_upload(
    root: &str,
    mode: &str,
    rel: Option<&str>,
    clear: bool,
    temp: &std::path::Path,
) -> Result<usize> {
    // The body is entirely synchronous (dir wipe + ZIP/DEFLATE extraction +
    // blocking file writes), which would pin a runtime worker for the whole
    // extraction. Run it on the blocking pool.
    let (root, mode, rel, temp) = (
        root.to_string(),
        mode.to_string(),
        rel.map(str::to_string),
        temp.to_path_buf(),
    );
    tokio::task::spawn_blocking(move || {
        web_static_upload_blocking(&root, &mode, rel.as_deref(), clear, &temp)
    })
    .await
    .map_err(|e| anyhow!("静态站点上传任务失败：{e}"))?
}

/// Synchronous implementation of [`web_static_upload`] — runs on the blocking
/// pool. See the async wrapper for the parameter contract.
fn web_static_upload_blocking(
    root: &str,
    mode: &str,
    rel: Option<&str>,
    clear: bool,
    temp: &std::path::Path,
) -> Result<usize> {
    let lo = layout()?;
    if !valid_root_segment(root) {
        return Err(anyhow!("ERR_CODE:nginx.bad_static_dir"));
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
            let rel = rel.ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_file_path"))?;
            let safe = sanitize_rel(rel).ok_or_else(|| anyhow!("ERR_CODE:nginx.bad_file_path"))?;
            let target = dest.join(&safe);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(temp, &target)?; // streamed copy, bounded memory
            Ok(1)
        }
        _ => Err(anyhow!("ERR_CODE:nginx.unknown_upload_mode")),
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
            std::fs::create_dir_all(dest.join(safe))?;
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
        let mut out = std::fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut out)?;
        count += 1;
    }
    Ok(count)
}
