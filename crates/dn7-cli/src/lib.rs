//! `dn7` — the unified on-box CLI, shipped INSIDE the `dn7-panel` binary and
//! invoked via the `dn7` symlink (argv[0] dispatch). This crate is the CLI
//! library; `dn7-panel`'s `main` calls [`run`] when it was launched as `dn7`.
//! Keeping the CLI a library (not a second binary) means one shipped artifact —
//! no duplicated runtime, no second download.

#[cfg(target_os = "linux")]
mod cert;
#[cfg(target_os = "linux")]
mod client;
#[cfg(target_os = "linux")]
mod common;
#[cfg(target_os = "linux")]
mod container;
#[cfg(target_os = "linux")]
mod edge;
#[cfg(target_os = "linux")]
mod info;
#[cfg(target_os = "linux")]
mod kdf;
#[cfg(target_os = "linux")]
mod panel;
#[cfg(target_os = "linux")]
mod service;
#[cfg(target_os = "linux")]
mod site;
#[cfg(target_os = "linux")]
mod status;
#[cfg(target_os = "linux")]
mod uninstall;
#[cfg(target_os = "linux")]
mod user;
#[cfg(target_os = "linux")]
mod util;

/// Run the unified CLI with the argv tail (`[command, ...]`); returns the process
/// exit code. The caller (dn7-panel's `main`) has already handled the
/// container-init re-exec and any `version` interception.
#[cfg(target_os = "linux")]
pub fn run(args: &[String]) -> i32 {
    let top = args.first().map(String::as_str).unwrap_or("");
    let rest = &args[1.min(args.len())..];
    match top {
        "" | "-h" | "--help" | "help" => {
            print_help();
            0
        }
        "version" | "-V" | "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            0
        }
        "container" | "ct" => container::run(rest),
        "edge" => edge::run(rest),
        "site" => site::run(rest),
        "cert" => cert::run(rest),
        "user" => user::run(rest),
        "logs" => info::logs(rest),
        "metrics" => info::metrics(rest),
        "update" => info::update(rest),
        "status" => status::run(rest),
        "panel" => panel::run(rest),
        "service" => service::run(rest),
        "uninstall" => uninstall::run(rest),
        other => {
            eprintln!("dn7: 未知命令 / unknown command '{other}' (try `dn7 help`)");
            2
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run(_args: &[String]) -> i32 {
    eprintln!("dn7 runs on Linux only (it drives the container runtime + host services).");
    2
}

#[cfg(target_os = "linux")]
fn print_help() {
    println!(
        "DN7 CLI — 本机管理工具 / on-box management tool\n\
\n\
用法 / usage: dn7 <command> [args]\n\
\n\
  status                     总览 / overview (panel, edge, containers)\n\
  container|ct <verb> …      容器运行时 / container runtime\n\
                             (ls|create-image|start|stop|rm|logs|exec|stats|\n\
                              images|rmi|volumes|pull|save|load|commit|net …)\n\
  edge <status|restart|reload>  内置反向代理 / built-in reverse proxy\n\
  site <ls|add|rm|setup|reload>  网站站点 / websites (add = 向导/wizard)\n\
  cert <ls|issue|renew|rm>   TLS 证书 / certificates\n\
                             issue <le|self|manual> <domain>   (le 加 --wait 等待签发)\n\
  user <ls|add|passwd|rm>    面板用户 / panel users\n\
                             add <name> [--admin] [--password|--stdin]\n\
  logs                       审计日志 / audit log\n\
  metrics                    资源指标 / resource metrics\n\
  update                     更新状态 / update status\n\
                             (ls/logs/metrics/update 加 --json 输出机器可读 JSON)\n\
  panel <start|stop|restart|status|version|reset|logs|rotate-token>\n\
                             面板服务生命周期 / panel service lifecycle\n\
                             rotate-token: 轮换 CLI 控制令牌 / rotate the CLI token\n\
  service <enable|disable|status>\n\
                             开机自启动 / boot autostart\n\
  uninstall                  卸载(多次确认)/ uninstall (multi-confirm)\n\
  version                    打印版本 / print version\n\
  help                       本帮助 / this help\n"
    );
}
