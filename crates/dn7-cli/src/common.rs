//! Shared helpers: install paths, root check, bilingual output, prompts, and a
//! few pure-Rust host probes (panel processes, listening ports, web.json).

use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const INSTALL_DIR: &str = "/var/dn7/panel";
pub const INSTALL_BIN: &str = "/var/dn7/panel/dn7-panel";
pub const SERVICE: &str = "dn7-panel";
pub const SYSTEMD_UNIT: &str = "/etc/systemd/system/dn7-panel.service";
pub const WANTS_LINK: &str = "/etc/systemd/system/multi-user.target.wants/dn7-panel.service";
pub const CRON_D: &str = "/etc/cron.d/dn7-panel";
pub const INITD: &str = "/etc/init.d/dn7-panel";
pub const GLOBAL_DN7: &str = "/usr/local/bin/dn7";
pub const GLOBAL_DN7CRUN: &str = "/usr/local/bin/dn7crun";

pub fn is_root() -> bool {
    // SAFETY: getuid takes no args and can't fail.
    unsafe { libc::getuid() == 0 }
}

/// Enforce root for a privileged command; returns `Err(exit_code)` if not root.
pub fn require_root() -> Result<(), i32> {
    if !is_root() {
        eprintln!("需要 root 权限 / must run as root (try: sudo dn7 …)");
        return Err(1);
    }
    Ok(())
}

pub fn stdin_is_tty() -> bool {
    // SAFETY: isatty on fd 0.
    unsafe { libc::isatty(0) == 1 }
}

/// Panel base dir (`DN7_RUNTIME_DIR` override, else the canonical install dir).
pub fn base_dir() -> PathBuf {
    std::env::var("DN7_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(INSTALL_DIR))
}

pub fn data_dir() -> PathBuf {
    base_dir().join("data")
}

// --- bilingual output -----------------------------------------------------

pub fn ok(zh: &str, en: &str) {
    println!("  ✓ {zh} / {en}");
}
pub fn warn(zh: &str, en: &str) {
    println!("  ! {zh} / {en}");
}

/// Free-text prompt with an optional default (shown in brackets, returned on an
/// empty line). Used by the `dn7 site add` wizard.
pub fn prompt_line(zh: &str, en: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{zh} / {en}: ");
    } else {
        print!("{zh} / {en} [{default}]: ");
    }
    let _ = io::stdout().flush();
    let mut s = String::new();
    if io::stdin().read_line(&mut s).is_err() {
        return default.to_string();
    }
    let s = s.trim().to_string();
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

/// `[y/N]` prompt. Returns true only on an explicit yes.
pub fn prompt_yes_no(zh: &str, en: &str) -> bool {
    print!("[y/N] {zh} / {en} ");
    let _ = io::stdout().flush();
    let mut s = String::new();
    if io::stdin().read_line(&mut s).is_err() {
        return false;
    }
    matches!(s.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// --- process helpers ------------------------------------------------------

/// Run a command, suppressing its output; returns whether it succeeded.
pub fn run_quiet(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run a command with inherited stdio; returns its exit code.
pub fn run_inherit(bin: &str, args: &[&str]) -> i32 {
    Command::new(bin)
        .args(args)
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or_else(|_| {
            eprintln!("dn7: 无法执行 / cannot run `{bin}`");
            1
        })
}

// --- host probes (pure Rust) ----------------------------------------------

/// PIDs of running `dn7-panel` processes (scan /proc/<pid>/comm).
pub fn panel_pids() -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return out;
    };
    for ent in rd.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            if comm.trim() == "dn7-panel" {
                out.push(pid);
            }
        }
    }
    out
}

/// Whether something is listening on `127.0.0.1:port` (a cheap connect probe).
pub fn port_listening(port: u16) -> bool {
    let addr = format!("127.0.0.1:{port}");
    match addr.parse() {
        Ok(sa) => TcpStream::connect_timeout(&sa, Duration::from_millis(300))
            .map(|s| {
                let _ = s.shutdown(Shutdown::Both);
            })
            .is_ok(),
        Err(_) => false,
    }
}

/// The panel's persisted console settings (status fields), if present.
pub fn read_web_json() -> Option<serde_json::Value> {
    let bytes = std::fs::read(data_dir().join("web.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}
