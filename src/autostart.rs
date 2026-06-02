//! Boot-time auto-start, installed via several mechanisms at once.
//!
//! A single agent install should survive a reboot. Rather than rely on one
//! init system (which might be absent, disabled, or misconfigured), we install
//! *several redundant* mechanisms and let whichever the host honors win:
//!
//!   1. **systemd unit** (`/etc/systemd/system/teaops-agent.service`) — the
//!      primary path on modern Linux. `enable` wires it to boot.
//!   2. **cron `@reboot`** (a `/etc/cron.d/teaops-agent` drop-in, falling back
//!      to the root user crontab) — covers hosts without systemd or where the
//!      unit didn't take.
//!   3. **`/etc/rc.local`** — last-resort for older SysV-style systems.
//!
//! These don't conflict: the agent is single-instance (the supervisor holds a
//! lock; a second launch just re-pairs instead of starting a duplicate), so if
//! two mechanisms both fire at boot, only one supervisor actually runs.
//!
//! All steps are best-effort and idempotent. They run only when we can write
//! the relevant system paths (i.e. effectively root); an unprivileged run skips
//! them silently. We never install autostart for the inner `agent` child role.

use std::path::Path;

use crate::paths::{INSTALL_BIN, INSTALL_DIR};

const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/teaops-agent.service";
const CRON_D_PATH: &str = "/etc/cron.d/teaops-agent";
const RC_LOCAL_PATH: &str = "/etc/rc.local";
/// Marker line so we can find/replace our rc.local entry idempotently.
const RC_LOCAL_MARKER: &str = "# teaops-agent autostart";

/// Are we effectively root (can write system unit/cron files)?
fn is_root() -> bool {
    // SAFETY: geteuid() just reads the effective uid; always safe.
    unsafe { libc_geteuid() == 0 }
}

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Install every available autostart mechanism (best-effort, idempotent).
///
/// `backend_url` is baked into the unit/cron env so a boot-time start reports to
/// the right backend even without an external env file. Returns immediately for
/// non-root runs.
pub fn install_all(backend_url: &str) {
    if !is_root() {
        tracing::debug!("not root; skipping autostart installation");
        return;
    }
    let mut installed: Vec<&str> = Vec::new();
    if install_systemd(backend_url) {
        installed.push("systemd");
    }
    if install_cron(backend_url) {
        installed.push("cron@reboot");
    }
    if install_rc_local(backend_url) {
        installed.push("rc.local");
    }
    if installed.is_empty() {
        tracing::warn!("could not install any autostart mechanism");
    } else {
        tracing::info!(methods = ?installed, "installed boot autostart");
    }
}

/// Common shell to launch the agent at boot: ensure the dir, then exec the
/// canonical binary in the background. The supervisor self-detaches, but for
/// cron/rc.local (no service manager) we background it explicitly.
fn boot_launch_cmd(backend_url: &str, background: bool) -> String {
    let bg = if background { " &" } else { "" };
    format!("TEAOPS_BACKEND_URL={backend_url} {INSTALL_BIN}{bg}",)
}

/// Mechanism 1: systemd unit + enable.
fn install_systemd(backend_url: &str) -> bool {
    // Only meaningful if systemd is actually the init system.
    if !Path::new("/run/systemd/system").is_dir() {
        return false;
    }
    let unit = format!(
        "[Unit]\n\
         Description=TeaOps Agent\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         Environment=TEAOPS_BACKEND_URL={backend_url}\n\
         WorkingDirectory={INSTALL_DIR}\n\
         ExecStart={INSTALL_BIN} --foreground\n\
         Restart=always\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    if std::fs::write(SYSTEMD_UNIT_PATH, unit).is_err() {
        return false;
    }
    // Reload + enable (start at boot). Don't `start` here — the foreground
    // launcher that called us is already bringing the agent up.
    let _ = run("systemctl", &["daemon-reload"]);
    let _ = run("systemctl", &["enable", "teaops-agent"]);
    true
}

/// Mechanism 2: cron @reboot — a /etc/cron.d drop-in if that dir exists, else
/// the root crontab. Either way, idempotent.
fn install_cron(backend_url: &str) -> bool {
    let launch = boot_launch_cmd(backend_url, true);
    // Prefer a cron.d drop-in (clean, isolated, no crontab parsing).
    if Path::new("/etc/cron.d").is_dir() {
        // cron.d entries need a user field.
        let line = format!("@reboot root {launch}\n");
        let body = format!("{RC_LOCAL_MARKER}\nSHELL=/bin/sh\n{line}");
        if std::fs::write(CRON_D_PATH, body).is_ok() {
            let _ = std::fs::set_permissions(
                CRON_D_PATH,
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            );
            return true;
        }
    }
    // Fallback: edit root's crontab via `crontab`.
    if which("crontab") {
        // Read existing crontab (may be empty), strip any prior teaops line,
        // append a fresh one, and load it back.
        let existing = std::process::Command::new("crontab")
            .arg("-l")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let mut lines: Vec<String> = existing
            .lines()
            .filter(|l| !l.contains("teaops-agent"))
            .map(|l| l.to_string())
            .collect();
        lines.push(format!("@reboot {launch}"));
        let new_tab = format!("{}\n", lines.join("\n"));
        if let Ok(mut child) = std::process::Command::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(new_tab.as_bytes());
            }
            let _ = child.wait();
            return true;
        }
    }
    false
}

/// Mechanism 3: /etc/rc.local — append our launch line before `exit 0`,
/// idempotently. Create the file with a shebang if it doesn't exist, and make
/// it executable.
fn install_rc_local(backend_url: &str) -> bool {
    let launch = boot_launch_cmd(backend_url, true);
    let our_block = format!("{RC_LOCAL_MARKER}\n{launch}\n");

    let existing = std::fs::read_to_string(RC_LOCAL_PATH).unwrap_or_default();
    let new_contents = if existing.is_empty() {
        format!("#!/bin/sh -e\n{our_block}exit 0\n")
    } else if existing.contains(RC_LOCAL_MARKER) {
        // Already present — replace our line (in case the path/url changed).
        rewrite_rc_local(&existing, &launch)
    } else if existing.contains("exit 0") {
        existing.replacen("exit 0", &format!("{our_block}exit 0"), 1)
    } else {
        format!("{existing}\n{our_block}")
    };

    if std::fs::write(RC_LOCAL_PATH, new_contents).is_err() {
        return false;
    }
    let _ = std::fs::set_permissions(
        RC_LOCAL_PATH,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    );
    true
}

/// Replace the line following our marker in an existing rc.local.
fn rewrite_rc_local(existing: &str, launch: &str) -> String {
    let mut out = String::with_capacity(existing.len());
    let mut lines = existing.lines().peekable();
    while let Some(line) = lines.next() {
        out.push_str(line);
        out.push('\n');
        if line.trim() == RC_LOCAL_MARKER {
            // Skip the old launch line that immediately follows the marker.
            if lines.peek().is_some() {
                lines.next();
            }
            out.push_str(launch);
            out.push('\n');
        }
    }
    out
}

/// Run a command, ignoring output; returns true on a zero exit status.
fn run(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether a command exists on PATH.
fn which(cmd: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc_local_block_inserted_before_exit() {
        let existing = "#!/bin/sh -e\nfoo\nexit 0\n";
        let out = existing.replacen("exit 0", &format!("{RC_LOCAL_MARKER}\nLAUNCH\nexit 0"), 1);
        assert!(out.contains(RC_LOCAL_MARKER));
        // The launch must come before the final exit 0.
        let marker_idx = out.find(RC_LOCAL_MARKER).unwrap();
        let exit_idx = out.rfind("exit 0").unwrap();
        assert!(marker_idx < exit_idx);
    }

    #[test]
    fn rewrite_replaces_old_launch_line() {
        let existing = format!("#!/bin/sh -e\n{RC_LOCAL_MARKER}\nOLD_LAUNCH\nexit 0\n");
        let out = rewrite_rc_local(&existing, "NEW_LAUNCH");
        assert!(out.contains("NEW_LAUNCH"));
        assert!(!out.contains("OLD_LAUNCH"));
        // Marker preserved exactly once.
        assert_eq!(out.matches(RC_LOCAL_MARKER).count(), 1);
    }

    #[test]
    fn boot_cmd_has_backend_and_binary() {
        let c = boot_launch_cmd("https://api.example.cn", true);
        assert!(c.contains("TEAOPS_BACKEND_URL=https://api.example.cn"));
        assert!(c.contains(INSTALL_BIN));
        assert!(c.trim_end().ends_with('&'));
    }
}
