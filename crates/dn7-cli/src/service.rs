//! `dn7 service <enable|disable|status>` — boot autostart of the panel service.
//! Uses the host service manager (systemd); the unit itself is written by the
//! panel at install/first-run.

use crate::common::*;

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("status") {
        "enable" => {
            if let Err(c) = require_root() {
                return c;
            }
            if run_quiet("systemctl", &["enable", SERVICE]) {
                ok("已设为开机自启动", "enabled at boot");
                0
            } else {
                warn("设置开机自启动失败", "failed to enable at boot");
                1
            }
        }
        "disable" => {
            if let Err(c) = require_root() {
                return c;
            }
            if run_quiet("systemctl", &["disable", SERVICE]) {
                ok("已取消开机自启动", "disabled at boot");
                0
            } else {
                warn("取消开机自启动失败", "failed to disable at boot");
                1
            }
        }
        "status" => {
            let enabled = run_quiet("systemctl", &["is-enabled", "--quiet", SERVICE]);
            println!(
                "开机自启动 / boot autostart: {}",
                if enabled {
                    "已启用 / enabled"
                } else {
                    "未启用 / disabled"
                }
            );
            0
        }
        other => {
            eprintln!("dn7 service: 未知子命令 / unknown '{other}' (enable|disable|status)");
            2
        }
    }
}
