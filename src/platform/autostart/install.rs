//! Boot-time auto-start, installed via several mechanisms at once.
//!
//! A single panel install should survive a reboot. Rather than rely on one
//! init system (which might be absent, disabled, or misconfigured), we install
//! *several redundant* mechanisms and let whichever the host honors win:
//!
//!   1. **systemd unit** (`/etc/systemd/system/dn7-panel.service`) — the
//!      primary path on modern Linux. `enable` wires it to boot.
//!   2. **cron `@reboot`** (a `/etc/cron.d/dn7-panel` drop-in, falling back
//!      to the root user crontab) — covers hosts without systemd or where the
//!      unit didn't take.
//!   3. **`/etc/rc.local`** — last-resort for older SysV-style systems.
//!
//! These don't conflict: the panel is single-instance (the supervisor holds a
//! lock; a second launch just re-pairs instead of starting a duplicate), so if
//! two mechanisms both fire at boot, only one supervisor actually runs.
//!
//! All steps are best-effort and idempotent. They run only when we can write
//! the relevant system paths (i.e. effectively root); an unprivileged run skips
//! them silently. We never install autostart for the inner `panel` child role.

use std::path::Path;

use crate::platform::paths::{INSTALL_BIN, INSTALL_DIR};

const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/dn7-panel.service";
const CRON_D_PATH: &str = "/etc/cron.d/dn7-panel";
const RC_LOCAL_PATH: &str = "/etc/rc.local";
/// Marker line so we can find/replace our rc.local entry idempotently.
const RC_LOCAL_MARKER: &str = "# dn7-panel autostart";

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
/// Returns immediately for non-root runs.
pub fn install_all() {
    if !is_root() {
        tracing::debug!("not root; skipping autostart installation");
        return;
    }
    let mut installed: Vec<&str> = Vec::new();
    if install_systemd() {
        installed.push("systemd");
    }
    if install_cron() {
        installed.push("cron@reboot");
    }
    if install_rc_local() {
        installed.push("rc.local");
    }
    if installed.is_empty() {
        tracing::warn!("could not install any autostart mechanism");
    } else {
        tracing::info!(methods = ?installed, "installed boot autostart");
    }
}

/// Common shell to launch the panel at boot: exec the canonical binary,
/// backgrounding it for cron/rc.local (which have no service manager).
fn boot_launch_cmd(background: bool) -> String {
    let bg = if background { " &" } else { "" };
    format!("{INSTALL_BIN}{bg}")
}

/// Mechanism 1: systemd unit + enable.
fn install_systemd() -> bool {
    // Only meaningful if systemd is actually the init system.
    if !Path::new("/run/systemd/system").is_dir() {
        return false;
    }
    let unit = format!(
        "[Unit]\n\
         Description=DN7 Panel\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
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
    // Enable at boot WITHOUT the `systemctl` binary: `systemctl enable` for a unit
    // with `WantedBy=multi-user.target` is just a symlink into that target's
    // `.wants/` dir. Create it ourselves (idempotent). No `daemon-reload` needed —
    // systemd reads units fresh at boot, and we don't start it now (the foreground
    // launcher already brought the panel up).
    let wants_dir = "/etc/systemd/system/multi-user.target.wants";
    let _ = std::fs::create_dir_all(wants_dir);
    let link = format!("{wants_dir}/dn7-panel.service");
    let _ = std::fs::remove_file(&link); // replace any stale link
    let _ = std::os::unix::fs::symlink(SYSTEMD_UNIT_PATH, &link);
    true
}

/// Mechanism 2: cron @reboot — a /etc/cron.d drop-in if that dir exists, else
/// the root crontab. Either way, idempotent.
fn install_cron() -> bool {
    let launch = boot_launch_cmd(true);
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
    // Fallback (no /etc/cron.d): write root's crontab spool file DIRECTLY — no
    // `crontab` binary. Debian/Ubuntu use /var/spool/cron/crontabs, RHEL uses
    // /var/spool/cron. cron rescans the spool by mtime, so a fresh write is picked
    // up. The spool format has no user field (unlike cron.d). Idempotent: strip
    // any prior dn7 line first.
    for dir in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
        if !Path::new(dir).is_dir() {
            continue;
        }
        let path = format!("{dir}/root");
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let mut lines: Vec<String> = existing
            .lines()
            .filter(|l| !l.contains("dn7-panel"))
            .map(|l| l.to_string())
            .collect();
        lines.push(format!("@reboot {launch}"));
        let body = format!("{}\n", lines.join("\n"));
        if std::fs::write(&path, body).is_ok() {
            let _ = std::fs::set_permissions(
                &path,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            );
            return true;
        }
    }
    false
}

/// Mechanism 3: /etc/rc.local — append our launch line before `exit 0`,
/// idempotently. Create the file with a shebang if it doesn't exist, and make
/// it executable.
fn install_rc_local() -> bool {
    let launch = boot_launch_cmd(true);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn boot_cmd_has_binary() {
        let c = boot_launch_cmd(true);
        assert!(c.contains(INSTALL_BIN));
        assert!(c.trim_end().ends_with('&'));
    }
}
