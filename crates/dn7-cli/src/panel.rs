//! `dn7 panel <start|stop|restart|status|version|reset|logs>` — panel service
//! lifecycle. start/stop/restart/logs go through the host service manager;
//! version/reset delegate to the installed `dn7-panel` binary's own subcommands.

use crate::common::*;
use std::path::Path;

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("status") {
        "start" => svc("start", "已启动", "started"),
        "stop" => svc("stop", "已停止", "stopped"),
        "restart" => svc("restart", "已重启", "restarted"),
        "status" => {
            if Path::new(SYSTEMD_UNIT).exists() {
                return run_inherit("systemctl", &["status", SERVICE, "--no-pager"]);
            }
            crate::status::run(&[])
        }
        "version" => run_inherit(INSTALL_BIN, &["version"]),
        "reset" => {
            if let Err(c) = require_root() {
                return c;
            }
            run_inherit(INSTALL_BIN, &["reset"])
        }
        "logs" => run_inherit("journalctl", &["-u", SERVICE, "-n", "200", "--no-pager"]),
        "rotate-token" => rotate_token(),
        other => {
            eprintln!(
                "dn7 panel: 未知子命令 / unknown '{other}' \
                 (start|stop|restart|status|version|reset|logs|rotate-token)"
            );
            2
        }
    }
}

/// Rotate the root-only CLI control token: remove `<data>/cli.token` and restart
/// the panel, which re-mints it through its hardened 0600 writer on startup. We
/// don't write the token here — the panel owns the single hardened writer (no
/// duplicated, weaker file write). The running console keeps validating the OLD
/// in-memory token until the restart completes, so the restart MUST succeed for
/// rotation to take effect — a failed restart returns non-zero.
fn rotate_token() -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    let path = data_dir().join("cli.token");
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!(
                "dn7: 删除旧令牌失败 / cannot remove {}: {e}",
                path.display()
            );
            return 1;
        }
    }
    println!("  · 重启面板以生成新令牌 / restarting the panel to mint a new token…");
    if run_quiet("systemctl", &["restart", SERVICE]) {
        ok(
            "面板已重启,新的 CLI 控制令牌已生效",
            "panel restarted; a new CLI control token is active",
        );
        0
    } else {
        warn(
            "重启失败:新令牌未生成、旧令牌仍有效,请手动 `dn7 panel restart`",
            "restart failed: old token still valid; run `dn7 panel restart`",
        );
        1
    }
}

fn svc(verb: &str, done_zh: &str, done_en: &str) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    if run_quiet("systemctl", &[verb, SERVICE]) {
        ok(&format!("面板{done_zh}"), &format!("panel {done_en}"));
        0
    } else {
        warn(
            &format!("面板 {verb} 失败,见 `dn7 panel logs`"),
            &format!("panel {verb} failed; see `dn7 panel logs`"),
        );
        1
    }
}
