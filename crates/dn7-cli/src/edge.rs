//! `dn7 edge <status|restart>` — the in-process reverse proxy.
//!
//! v1 is intentionally minimal: `status` (probe the listeners) and `restart`
//! (the edge runs INSIDE the panel, so restart the panel). Live `reload` of the
//! edge config (and `site`/`cert` management) needs the panel control channel
//! and lands in v2.

use crate::common::*;
use dn7_edge::CONSOLE_LOOPBACK_PORT;

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => {
            println!("Edge 状态 / status");
            println!("  :80                  : {}", up(port_listening(80)));
            println!("  :443                 : {}", up(port_listening(443)));
            println!(
                "  控制台 :{CONSOLE_LOOPBACK_PORT}        : {}",
                up(port_listening(CONSOLE_LOOPBACK_PORT))
            );
            0
        }
        "restart" => {
            if let Err(c) = require_root() {
                return c;
            }
            // The edge runs inside the panel process; restart the panel to reload
            // it (a live edge-only reload needs the v2 control channel).
            if run_quiet("systemctl", &["restart", SERVICE]) {
                ok("Edge 已随面板重启", "edge restarted (with the panel)");
                0
            } else {
                warn(
                    "重启失败,见 `dn7 panel logs`",
                    "restart failed; see `dn7 panel logs`",
                );
                1
            }
        }
        "reload" => {
            if let Err(c) = require_root() {
                return c;
            }
            // Tell the running panel to rebuild the edge route table from the
            // persisted manifests (no panel restart) — via the control channel.
            crate::client::act(
                crate::client::website("reload", serde_json::json!({})),
                "Edge 已重载",
                "edge reloaded",
            )
        }
        other => {
            eprintln!("dn7 edge: 未知子命令 / unknown '{other}' (status|restart)");
            2
        }
    }
}

fn up(b: bool) -> &'static str {
    if b {
        "监听中 / listening"
    } else {
        "未监听 / down"
    }
}
