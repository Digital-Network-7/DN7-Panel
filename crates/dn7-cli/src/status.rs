//! `dn7 status` — a one-shot overview, probed in-process (works even when the
//! panel is down): panel process, :80 / loopback-console listeners, the persisted
//! address/SSL, and the container count.

use crate::common::*;
use dn7_edge::CONSOLE_LOOPBACK_PORT;

pub fn run(_args: &[String]) -> i32 {
    let web = read_web_json();
    let field = |k: &str| {
        web.as_ref()
            .and_then(|v| v.get(k))
            .and_then(|x| x.as_str())
            .unwrap_or("-")
            .to_string()
    };
    let initialized = web
        .as_ref()
        .and_then(|v| v.get("initialized"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let pids = panel_pids();
    let (total, running) = match dn7_container::container::list() {
        Ok(v) => (
            v.len(),
            v.iter().filter(|s| s.status.as_str() == "running").count(),
        ),
        Err(_) => (0, 0),
    };

    println!("DN7 Panel 状态 / status");
    println!("  初始化 / initialized : {}", yesno(initialized));
    println!(
        "  面板进程 / panel     : {}",
        match pids.first() {
            Some(p) => format!("运行中 / running (pid {p})"),
            None => "未运行 / not running".to_string(),
        }
    );
    println!("  Edge :80             : {}", up(port_listening(80)));
    println!(
        "  控制台 :{CONSOLE_LOOPBACK_PORT}        : {}",
        up(port_listening(CONSOLE_LOOPBACK_PORT))
    );
    println!("  地址 / address       : {}", field("external_address"));
    println!("  SSL                  : {}", field("https_mode"));
    println!("  容器 / containers    : {running}/{total} 运行中 / running");
    0
}

fn yesno(b: bool) -> &'static str {
    if b {
        "是 / yes"
    } else {
        "否 / no"
    }
}

fn up(b: bool) -> &'static str {
    if b {
        "监听中 / listening"
    } else {
        "未监听 / down"
    }
}
