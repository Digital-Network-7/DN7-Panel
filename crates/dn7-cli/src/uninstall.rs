//! `dn7 uninstall` — remove the panel's entire footprint, gated by FOUR grouped
//! confirmations. Any "N" cancels and removes NOTHING; only all-"y" proceeds.
//! `--yes`/`-y` skips the prompts (for automation).

use crate::common::*;
use std::path::Path;

const STORE_ROOT: &str = "/var/lib/dn7-container";

pub fn run(args: &[String]) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    let assume_yes = args.iter().any(|a| a == "--yes" || a == "-y");
    if !assume_yes && !stdin_is_tty() {
        eprintln!("卸载需要交互确认,请在终端运行(或加 --yes)。");
        eprintln!("Uninstall needs interactive confirmation; run in a terminal (or pass --yes).");
        return 1;
    }

    println!("即将卸载 DN7 Panel / About to uninstall DN7 Panel.");
    println!("以下每一项都需确认;任意一项回 N 即取消,不删除任何内容。");
    println!("Each item must be confirmed; any \"N\" cancels and removes NOTHING.\n");

    let confirm = |zh: &str, en: &str| assume_yes || prompt_yes_no(zh, en);
    let c1 = confirm(
        "1. 停止并移除服务与开机自启动",
        "Stop + remove the service and boot autostart",
    );
    let c2 = confirm(
        "2. 删除全部容器、镜像与容器网络",
        "Delete all containers, images and container networking",
    );
    let c3 = confirm(
        "3. 删除面板数据:配置、TLS 证书、面板登录凭据(不含系统登录账户)",
        "Delete panel data: config, TLS certs, panel login credentials (not OS login accounts)",
    );
    let c4 = confirm(
        "4. 删除程序文件与安装目录 /var/dn7",
        "Delete the binaries and the install dir /var/dn7",
    );

    if !(c1 && c2 && c3 && c4) {
        println!("\n已取消,未删除任何内容。 / Cancelled — nothing was removed.");
        return 0;
    }

    println!("\n开始卸载 / Uninstalling…");

    // 1. service + autostart. `systemctl kill` takes the whole service cgroup so
    // the panel's own guardian can't resurrect it; then strip every autostart.
    let _ = run_quiet("systemctl", &["disable", SERVICE]);
    let _ = run_quiet("systemctl", &["kill", "-s", "SIGKILL", SERVICE]);
    let _ = run_quiet("systemctl", &["stop", SERVICE]);
    rm(SYSTEMD_UNIT);
    rm(WANTS_LINK);
    rm(CRON_D);
    rm(INITD);
    strip_cron_spool();
    strip_rc_local();
    let _ = run_quiet("systemctl", &["daemon-reload"]);
    kill_remaining_panels();
    ok(
        "已停止并移除服务与开机自启动",
        "service + autostart removed",
    );

    // 2. container runtime: stop+delete every container, reclaim networking, drop
    // the nft table, and remove the image/bundle store.
    teardown_containers();
    ok(
        "已删除容器、镜像与容器网络",
        "containers, images and networking removed",
    );

    // 3 + 4. panel data + program files both live under /var/dn7, so one removal
    // covers them; also drop the other global launcher.
    rm(GLOBAL_DN7CRUN);
    rm_dir("/var/dn7");
    ok(
        "已删除面板数据与程序文件",
        "panel data + program files removed",
    );

    // Remove the `dn7` launcher LAST. On Linux unlinking a running binary is safe
    // — the inode lives until this process exits. Drop both the primary symlink
    // and the /usr/bin fallback (install picks whichever dir exists).
    rm(GLOBAL_DN7);
    rm(GLOBAL_DN7_FALLBACK);

    println!("\n卸载完成。 / Uninstall complete.");
    0
}

fn rm(p: &str) {
    let _ = std::fs::remove_file(p);
}

fn rm_dir(p: &str) {
    let _ = std::fs::remove_dir_all(p);
}

/// SIGKILL any lingering panel process (the supervisor/guardian pair) so removing
/// its files doesn't race a respawn.
fn kill_remaining_panels() {
    for pid in panel_pids() {
        // SAFETY: kill(2) on a pid with SIGKILL.
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
}

fn teardown_containers() {
    if let Ok(list) = dn7_container::container::list() {
        for s in list {
            let _ = dn7_container::container::delete(&s.id, true);
        }
    }
    let _ = dn7_container::net::NetworkManager::new().gc();
    let _ = dn7_container::net::firewall::nuke_table();
    if Path::new(STORE_ROOT).exists() {
        rm_dir(STORE_ROOT);
    }
}

/// Drop the `# dn7-panel autostart` line + its command from /etc/rc.local.
fn strip_rc_local() {
    if let Ok(content) = std::fs::read_to_string("/etc/rc.local") {
        if content.contains("dn7-panel") {
            let kept: Vec<&str> = content
                .lines()
                .filter(|l| !l.contains("dn7-panel"))
                .collect();
            let _ = std::fs::write("/etc/rc.local", kept.join("\n") + "\n");
        }
    }
}

/// Drop our `@reboot` entry from root's crontab spool. When `/etc/cron.d` was
/// absent, install wrote the `@reboot …/dn7-panel &` line straight into the
/// spool file (Debian: /var/spool/cron/crontabs/root, RHEL: /var/spool/cron/root)
/// rather than the cron.d drop-in. Mirror install's `dn7-panel` line filter so
/// any non-dn7 crontab entries are preserved.
fn strip_cron_spool() {
    for path in ["/var/spool/cron/crontabs/root", "/var/spool/cron/root"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            if content.contains("dn7-panel") {
                let kept: Vec<&str> = content
                    .lines()
                    .filter(|l| !l.contains("dn7-panel"))
                    .collect();
                let _ = std::fs::write(path, kept.join("\n") + "\n");
            }
        }
    }
}
