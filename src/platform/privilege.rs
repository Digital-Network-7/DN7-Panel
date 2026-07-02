//! Privilege bootstrap for the serving / install launch.
//!
//! The panel manages the host (system accounts, containers, firewall) and binds
//! the privileged ports :80/:443, so the serving and install paths require root.
//! Rather than start a half-working non-root panel that only fails later — when
//! the operator clicks "start" on the web server and hits
//! [`WebsiteError::NeedRoot`](crate::core::website) — we resolve privilege up
//! front:
//!   - already root → proceed;
//!   - non-root **with a TTY** → re-exec under `sudo` (which prompts for the
//!     password on the terminal), forwarding our `DN7_*` environment and the
//!     original arguments; on success `exec` replaces this process and the
//!     re-run comes back in as root;
//!   - non-root **without a TTY or without sudo** → refuse loudly (bilingual,
//!     non-zero) so the operator re-runs as root instead of getting a degraded
//!     console.
//!
//! Utility subcommands (`version`/`reset`/`port`/…) short-circuit before this in
//! `main`, so only the launch that actually serves is escalated.

use std::os::unix::process::CommandExt;

use anyhow::{anyhow, bail, Result};

/// Effective uid; `0` is root.
fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Whether stdin is a terminal — i.e. an interactive launch where `sudo` can
/// prompt for a password.
fn stdin_is_tty() -> bool {
    // SAFETY: isatty on fd 0 (stdin).
    unsafe { libc::isatty(0) == 1 }
}

/// Ensure the process runs as root, escalating via `sudo` when possible.
///
/// Returns `Ok(())` only when already root (the caller then proceeds). On a
/// non-root interactive launch this `exec`s `sudo` and never returns on success.
/// On a non-root launch with no TTY or no `sudo`, returns a bilingual error so
/// the caller aborts non-zero.
pub fn ensure_root_or_reexec() -> Result<()> {
    if euid() == 0 {
        return Ok(());
    }
    if !stdin_is_tty() {
        bail!(
            "需要以 root 运行(账户管理、容器、防火墙、绑定 80/443 都需要)，且当前没有终端可用于 sudo 提权。请用 root 重新运行 DN7 Panel。 \
             Must run as root (account management, containers, firewall, binding :80/:443), and there is no TTY to prompt for sudo. Re-run DN7 Panel as root."
        );
    }

    // Re-exec under sudo. We forward our `DN7_*` environment through `env` (as an
    // explicit argument list) rather than relying on `sudo -E`, so the vars
    // survive sudo's env reset regardless of the host's sudoers policy. With no
    // DN7_* vars set (the normal operator launch) this degenerates to a plain
    // `sudo <self> <args>`.
    let self_exe = std::env::current_exe()
        .map_err(|e| anyhow!("cannot resolve own executable path for sudo re-exec: {e}"))?;
    let mut sudo_args: Vec<String> = vec!["env".into()];
    for (k, v) in std::env::vars() {
        if k.starts_with("DN7_") {
            sudo_args.push(format!("{k}={v}"));
        }
    }
    sudo_args.push(self_exe.to_string_lossy().into_owned());
    // Forward the original subcommand/arguments (everything after argv[0]) so the
    // re-run resumes the same role (e.g. `panel`, or the bare install launch).
    sudo_args.extend(std::env::args().skip(1));

    eprintln!(
        "DN7 Panel 需要 root 权限，正在通过 sudo 提权(可能需要输入密码)… / \
         DN7 Panel needs root privileges; escalating via sudo (you may be prompted for your password)…"
    );

    // `exec` replaces this process image with sudo on success and only returns on
    // failure (e.g. sudo is not installed / not on PATH).
    let err = std::process::Command::new("sudo").args(&sudo_args).exec();
    bail!(
        "无法通过 sudo 提权({err})。请安装 sudo，或直接以 root 运行 DN7 Panel。 \
         Could not escalate via sudo ({err}). Install sudo, or run DN7 Panel as root."
    )
}
