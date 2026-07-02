//! In-container file operations for the dn7 backend (`DN7_RUNTIME=dn7`).
//!
//! dn7 knows each container's overlay rootfs path on the host, so list / mkdir /
//! delete / download / upload are direct filesystem operations on that merged
//! view (writes land in the overlay upper layer) — no Docker archive/exec API,
//! and they work whether or not the container is running. Path traversal (`..`)
//! is rejected so an operation can't escape the container's rootfs.
use super::*;

/// Whether the dn7 backend is active (Linux-only; the runtime is Linux-only).
#[cfg(target_os = "linux")]
pub(crate) fn active() -> bool {
    matches!(std::env::var("DN7_RUNTIME").as_deref(), Ok("dn7"))
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn active() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn rootfs(container: &str) -> Result<std::path::PathBuf> {
    let id = dn7_container::container::resolve(container)
        .map_err(|_| anyhow!("no such container: {container}"))?;
    dn7_container::container::rootfs_of(&id).map_err(|e| anyhow!("{e}"))
}

/// Map an absolute in-container path to a host path under `root`.
///
/// Two layers of defense against escaping the container's rootfs:
///  1. reject any `..` component in the *requested* path;
///  2. canonicalize the target's longest existing prefix (resolving every
///     symlink, including the final component when it already exists) and
///     require the real location to stay inside the canonicalized rootfs.
///
/// (2) is the important one: `std::fs` follows symlinks *on disk*, so without it
/// a container could plant `escape -> /` (or `-> /etc/shadow`) in its own rootfs
/// and have the panel — running as root on the host — read/write/delete the host
/// file the link points at. Step 2 makes such a link resolve outside `root` and
/// be rejected.
#[cfg(target_os = "linux")]
fn host_path(root: &std::path::Path, path: &str) -> Result<std::path::PathBuf> {
    let mut p = root.to_path_buf();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => return Err(anyhow!("路径非法")),
            c => p.push(c),
        }
    }
    // Resolve the rootfs itself once (it may sit under symlinked parent dirs).
    let croot = std::fs::canonicalize(root).map_err(|_| anyhow!("容器根目录不可用"))?;
    if !canonical_prefix(&p).starts_with(&croot) {
        return Err(anyhow!("路径非法"));
    }
    Ok(p)
}

/// The would-be canonical location of `p`: canonicalize its longest existing
/// ancestor (so a symlink anywhere in the existing portion is resolved) and
/// re-append the not-yet-existing tail verbatim. Used purely for containment
/// checks — the caller still operates on the original `p`.
#[cfg(target_os = "linux")]
fn canonical_prefix(p: &std::path::Path) -> std::path::PathBuf {
    let mut cur: &std::path::Path = p;
    loop {
        if let Ok(real) = std::fs::canonicalize(cur) {
            return match p.strip_prefix(cur) {
                Ok(tail) => real.join(tail),
                Err(_) => real,
            };
        }
        match cur.parent() {
            Some(par) => cur = par,
            None => return p.to_path_buf(),
        }
    }
}

/// Reject a CREATE path (write / mkdir) if ANY component under `root` is a
/// symlink. `canonical_prefix` containment catches a symlink pointing at an
/// *existing* host target, but a DANGLING symlink (target not yet created)
/// slips past `canonicalize` — and `create_dir_all` / an `O_CREAT` open would
/// then follow it and create the file/dir on the HOST. Walking the path
/// component-by-component with no-follow `symlink_metadata` blocks that; a
/// component that simply doesn't exist yet is fine (it gets created in place,
/// not via a link).
#[cfg(target_os = "linux")]
fn reject_symlink_components(root: &std::path::Path, path: &str) -> Result<()> {
    let mut cur = root.to_path_buf();
    for comp in path.split('/') {
        match comp {
            "" | "." => continue,
            ".." => return Err(anyhow!("路径非法")),
            c => cur.push(c),
        }
        if let Ok(md) = std::fs::symlink_metadata(&cur) {
            if md.file_type().is_symlink() {
                return Err(anyhow!("路径非法（不允许经符号链接写入）"));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) async fn list(container: &str, path: &str) -> Result<serde_json::Value> {
    let dir = if path.trim().is_empty() { "/" } else { path };
    let root = rootfs(container)?;
    let host = host_path(&root, dir)?;
    let rd = std::fs::read_dir(&host).map_err(|_| anyhow!("目录不存在或无权限"))?;
    let mut entries = Vec::new();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        let Ok(md) = ent.metadata() else { continue };
        let is_dir = md.is_dir();
        entries.push(serde_json::json!({
            "name": name,
            "is_dir": is_dir,
            "size": if is_dir { 0 } else { md.len() },
        }));
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

#[cfg(target_os = "linux")]
pub(crate) async fn mkdir(container: &str, path: &str) -> Result<()> {
    let root = rootfs(container)?;
    let host = host_path(&root, path)?;
    reject_symlink_components(&root, path)?;
    std::fs::create_dir_all(&host).map_err(|e| anyhow!("创建目录失败：{e}"))
}

#[cfg(target_os = "linux")]
pub(crate) async fn delete(container: &str, path: &str) -> Result<()> {
    if is_protected_path(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    let root = rootfs(container)?;
    let host = host_path(&root, path)?;
    let md = std::fs::symlink_metadata(&host).map_err(|_| anyhow!("路径不存在"))?;
    let r = if md.is_dir() {
        std::fs::remove_dir_all(&host)
    } else {
        std::fs::remove_file(&host)
    };
    r.map_err(|e| anyhow!("删除失败：{e}"))
}

#[cfg(target_os = "linux")]
pub(crate) async fn read_stream(container: &str, path: &str) -> Result<(String, ByteStream)> {
    use futures::StreamExt;
    let root = rootfs(container)?;
    let host = host_path(&root, path)?;
    let md = std::fs::metadata(&host).map_err(|_| anyhow!("文件不存在"))?;
    if md.is_dir() || md.len() == 0 {
        return Err(anyhow!("不能下载目录或空文件"));
    }
    let name = host
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    let f = tokio::fs::File::open(&host)
        .await
        .map_err(|e| anyhow!("无法打开文件：{e}"))?;
    let stream = tokio_util::codec::FramedRead::new(f, tokio_util::codec::BytesCodec::new())
        .map(|r| r.map(|b| b.freeze()));
    Ok((name, Box::pin(stream)))
}

#[cfg(target_os = "linux")]
pub(crate) async fn write_file(container: &str, dest_path: &str, temp: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let root = rootfs(container)?;
    let host = host_path(&root, dest_path)?;
    // Refuse to write through ANY symlink component (a dangling symlink isn't
    // caught by canonical_prefix), then open the leaf with O_NOFOLLOW so the
    // final component can't be a symlink even under a TOCTOU swap.
    reject_symlink_components(&root, dest_path)?;
    if let Some(parent) = host.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(&host)
        .map_err(|e| anyhow!("写入失败：{e}"))?;
    let mut src = std::fs::File::open(temp).map_err(|e| anyhow!("写入失败：{e}"))?;
    std::io::copy(&mut src, &mut dst).map_err(|e| anyhow!("写入失败：{e}"))?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{host_path, reject_symlink_components};
    use std::os::unix::fs::symlink;

    fn mkdir_unique(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut d = std::env::temp_dir();
        d.push(format!("dn7-ctnfs-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    #[test]
    fn host_path_blocks_symlink_and_dotdot_escapes() {
        let root = mkdir_unique("root");

        // Normal in-rootfs paths resolve fine — existing and creatable.
        std::fs::create_dir_all(root.join("var/log")).unwrap();
        assert!(host_path(&root, "/var/log").is_ok());
        assert!(host_path(&root, "/does/not/exist/yet").is_ok());

        // A literal `..` in the requested path is rejected outright.
        assert!(host_path(&root, "/../etc").is_err());

        // A symlink planted inside the rootfs that points OUTSIDE must be
        // rejected (the classic container->host escape).
        let outside = mkdir_unique("outside");
        std::fs::write(outside.join("secret"), b"top").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        assert!(host_path(&root, "/escape").is_err());
        assert!(host_path(&root, "/escape/secret").is_err());

        // An absolute-root symlink (`-> /`) cannot reach host files either.
        symlink("/", root.join("slash")).unwrap();
        assert!(host_path(&root, "/slash/etc/shadow").is_err());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    // The case canonicalize-containment alone MISSED: a dangling symlink (target
    // doesn't exist) used as a write/mkdir target. canonicalize fails on it, so
    // host_path lets it through, but reject_symlink_components blocks the create.
    #[test]
    fn reject_symlink_components_blocks_dangling_and_intermediate_links() {
        let root = mkdir_unique("create");
        std::fs::create_dir_all(root.join("ok/sub")).unwrap();

        // A normal path (existing dirs + a not-yet-existing leaf) is allowed.
        assert!(reject_symlink_components(&root, "/ok/sub/newfile").is_ok());

        // A DANGLING symlink leaf (-> a host path that doesn't exist) is the
        // escape canonicalize misses; it must be rejected here.
        symlink("/tmp/dn7-nonexistent-escape-xyz", root.join("dangle")).unwrap();
        assert!(reject_symlink_components(&root, "/dangle").is_err());
        assert!(reject_symlink_components(&root, "/dangle/child").is_err());

        // A symlink as an INTERMEDIATE component is rejected too.
        symlink("/etc", root.join("etclink")).unwrap();
        assert!(reject_symlink_components(&root, "/etclink/passwd").is_err());

        let _ = std::fs::remove_dir_all(&root);
    }
}
