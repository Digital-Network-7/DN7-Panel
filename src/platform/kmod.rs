//! Best-effort kernel-module loading (pure Rust — no modprobe shell-out).
//!
//! A fresh boot doesn't auto-load filesystem / netfilter modules until something
//! first uses them, so the first-run prerequisite check (which reads
//! /proc/filesystems) can be a false negative even though the module ships with
//! the kernel. We proactively load the needed modules via finit_module(2) — the
//! same syscall modprobe uses — which works before any mount has triggered the
//! kernel's own on-demand autoload, and needs no external program.

use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Load `name` (and its dependencies) if it isn't already active. Best-effort and
/// silent — the caller re-checks with [`available`]. Needs CAP_SYS_MODULE (root).
pub fn ensure_loaded(name: &str) {
    if is_active(name) {
        return;
    }
    let Some(moddir) = mod_dir() else { return };
    let Some((path, deps)) = resolve(&moddir, name) else {
        return;
    };
    // modules.dep lists a module's full transitive deps; load them first (an
    // EEXIST "already loaded" is fine), then the module itself.
    for d in &deps {
        let _ = load_ko(d);
    }
    let _ = load_ko(&path);
}

/// Whether the fs/module is usable: already active, or present on disk (so the
/// kernel will autoload it on first mount/use even if we couldn't finit it here).
pub fn available(name: &str) -> bool {
    is_active(name) || mod_dir().and_then(|d| resolve(&d, name)).is_some()
}

/// Active now — loaded (by /proc/modules name) or built in (fs in /proc/filesystems).
fn is_active(name: &str) -> bool {
    let want = name.replace('-', "_");
    file_has_first_token("/proc/modules", &want) || fs_registered(&want)
}

fn fs_registered(name: &str) -> bool {
    std::fs::read_to_string("/proc/filesystems")
        .map(|c| c.lines().any(|l| l.split_whitespace().last() == Some(name)))
        .unwrap_or(false)
}

fn file_has_first_token(path: &str, tok: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|c| c.lines().any(|l| l.split_whitespace().next() == Some(tok)))
        .unwrap_or(false)
}

fn mod_dir() -> Option<String> {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let rel = rel.trim();
    if rel.is_empty() {
        return None;
    }
    Some(format!("/lib/modules/{rel}"))
}

/// Find `name`'s .ko path + dependency .ko paths (absolute) from modules.dep.
/// Module names normalise '-' → '_'; filenames may use either.
fn resolve(moddir: &str, name: &str) -> Option<(PathBuf, Vec<PathBuf>)> {
    let dep = std::fs::read_to_string(format!("{moddir}/modules.dep")).ok()?;
    let want = name.replace('-', "_");
    for line in dep.lines() {
        let (path, rest) = line.split_once(':')?;
        if ko_base(path).replace('-', "_") == want {
            let deps = rest
                .split_whitespace()
                .map(|d| PathBuf::from(format!("{moddir}/{d}")))
                .collect();
            return Some((PathBuf::from(format!("{moddir}/{path}")), deps));
        }
    }
    None
}

/// Module base name from a relative .ko path (strip dir + ".ko"/".ko.gz"/… suffix).
fn ko_base(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.split(".ko").next().unwrap_or(file).to_string()
}

/// finit_module(2) the file. Compressed modules (.ko.gz/.xz/.zst) set the kernel
/// decompress flag (Linux 5.17+). EEXIST (already loaded) counts as success.
fn load_ko(path: &Path) -> std::io::Result<()> {
    const MODULE_INIT_COMPRESSED_FILE: libc::c_long = 4;
    let f = File::open(path)?;
    let params = CString::new("").unwrap();
    let flags = if path.extension().and_then(|e| e.to_str()) == Some("ko") {
        0
    } else {
        MODULE_INIT_COMPRESSED_FILE
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_finit_module,
            f.as_raw_fd() as libc::c_long,
            params.as_ptr(),
            flags,
        )
    };
    if r == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EEXIST) {
        Ok(()) // already loaded
    } else {
        Err(e)
    }
}
