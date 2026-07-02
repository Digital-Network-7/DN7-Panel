//! `dn7 site <ls|add|rm|setup|reload>` — website sites, via the panel control
//! channel. `add` is an interactive wizard (the site config has many fields);
//! it auto-initializes the website subsystem on first use.

use crate::common::*;
use crate::{client, util};
use serde_json::json;
use std::{thread, time::Duration};

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("ls") {
        "ls" | "list" => list(util::wants_json(args)),
        "add" | "new" => add(),
        "rm" | "remove" => rm(args.get(1)),
        "setup" => setup_cmd(),
        "reload" => {
            if let Err(c) = require_root() {
                return c;
            }
            client::act(
                client::website("reload", json!({})),
                "Edge 已重载",
                "edge reloaded",
            )
        }
        other => {
            eprintln!("dn7 site: 未知子命令 / unknown '{other}' (ls|add|rm|setup|reload)");
            2
        }
    }
}

fn rm(id: Option<&String>) -> i32 {
    let Some(id) = id else {
        eprintln!("用法 / usage: dn7 site rm <site-id>  (id 见 dn7 site ls)");
        return 2;
    };
    if let Err(c) = require_root() {
        return c;
    }
    if !prompt_yes_no(
        &format!("确认删除站点 {id}?"),
        &format!("delete site {id}?"),
    ) {
        println!("已取消 / cancelled");
        return 0;
    }
    client::act(
        client::website("remove_site", json!({ "site_id": id })),
        "已删除站点",
        "site removed",
    )
}

fn setup_cmd() -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    // `setup` is detached + idempotent (mark_setup is safe to re-run); the heavy
    // part — binding the edge listener — already happened at panel startup.
    match client::website("setup", json!({})) {
        Ok(r) if r.is_ok() => {
            thread::sleep(Duration::from_millis(1000));
            ok("网站子系统已初始化", "website subsystem initialized");
            0
        }
        Ok(r) => {
            eprintln!("dn7 site: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 site: {e}");
            1
        }
    }
}

fn add() -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    if !stdin_is_tty() {
        eprintln!("dn7 site add 需要交互终端 / needs an interactive terminal");
        return 2;
    }

    println!("== 新建站点 / new site ==");
    let kind = loop {
        let k = prompt_line(
            "类型 1)反代主机 2)反代容器 3)静态 / type 1)proxy 2)container 3)static",
            "",
            "1",
        );
        match k.as_str() {
            "1" | "proxy" | "proxy_host" => break "proxy_host",
            "2" | "container" | "proxy_container" => break "proxy_container",
            "3" | "static" => break "static",
            _ => println!("  ! 请输入 1/2/3 / enter 1, 2 or 3"),
        }
    };

    let server_name = prompt_line("域名(空格分隔多个)/ server name(s)", "", "");
    if server_name.is_empty() {
        eprintln!("dn7 site: 域名必填 / server name is required");
        return 2;
    }

    let mut body = json!({ "kind": kind, "server_name": server_name });
    match kind {
        "proxy_host" => {
            let target = prompt_line("上游目标 host:port / upstream target", "", "");
            if target.is_empty() {
                eprintln!("dn7 site: 上游目标必填 / target is required");
                return 2;
            }
            body["target_url"] = json!(target);
            body["scheme"] = json!(prompt_line("上游协议 / upstream scheme", "", "http"));
        }
        "proxy_container" => {
            let container = prompt_line("容器名 / container name", "", "");
            let port = prompt_line("容器端口 / container port", "", "");
            let Ok(port) = port.parse::<u16>() else {
                eprintln!("dn7 site: 端口无效 / invalid port");
                return 2;
            };
            body["container"] = json!(container);
            body["container_port"] = json!(port);
        }
        "static" => {
            let root = prompt_line(
                "本地目录(绝对路径)或站点子目录名 / local dir (absolute) or webroot subdir",
                "",
                "",
            );
            if root.is_empty() {
                eprintln!("dn7 site: 目录必填 / a directory is required");
                return 2;
            }
            if root.starts_with('/') {
                body["local_root"] = json!(root);
            } else {
                body["root"] = json!(root);
            }
        }
        _ => unreachable!(),
    }

    if prompt_yes_no("启用 HTTPS", "enable HTTPS") {
        body["ssl"] = json!(true);
        let mode = loop {
            let m = prompt_line(
                "证书 1)自签 2)Let's Encrypt 3)手动PEM 4)已有命名证书 / cert 1)self 2)le 3)manual 4)named",
                "",
                "1",
            );
            match m.as_str() {
                "1" | "self" => break "self",
                "2" | "le" => break "le",
                "3" | "manual" => break "manual",
                "4" | "named" => break "named",
                _ => println!("  ! 请输入 1-4 / enter 1-4"),
            }
        };
        body["cert_mode"] = json!(mode);
        if matches!(mode, "self" | "le") {
            let kt = loop {
                let k = prompt_line(
                    "密钥类型 1)ECDSA P-256(推荐) 2)ECDSA P-384 / key 1)P-256(recommended) 2)P-384",
                    "",
                    "1",
                );
                match k.as_str() {
                    "1" | "p256" | "ecdsa-p256" => break "ecdsa-p256",
                    "2" | "p384" | "ecdsa-p384" => break "ecdsa-p384",
                    _ => println!("  ! 请输入 1/2 / enter 1 or 2"),
                }
            };
            body["key_type"] = json!(kt);
        }
        match mode {
            "manual" => match read_pem_pair() {
                Ok((cert, key)) => {
                    body["cert_pem"] = json!(cert);
                    body["key_pem"] = json!(key);
                }
                Err(e) => {
                    eprintln!("dn7 site: {e}");
                    return 2;
                }
            },
            "named" => {
                let name = prompt_line("命名证书名 / named cert", "", "");
                if name.is_empty() {
                    eprintln!("dn7 site: 证书名必填 / cert name required");
                    return 2;
                }
                body["cert_name"] = json!(name);
            }
            _ => {}
        }
    }

    // Don't create a site that would spawn a duplicate ACME order for a host that
    // already has an issuance in flight.
    if body.get("cert_mode").and_then(|m| m.as_str()) == Some("le")
        && client::running_cert_op(&server_name).is_some()
    {
        warn(
            &format!("{server_name} 已有 LE 签发在进行,请等待完成后再建站"),
            &format!(
                "an LE issuance for {server_name} is already running; wait for it, then retry"
            ),
        );
        return 1;
    }

    match client::website_setup_aware("add_site", body) {
        Ok(r) if r.is_ok() => {
            let d = r.data();
            if let Some(op_id) = d.get("op_id").and_then(|x| x.as_str()) {
                ok(
                    "站点已创建,正在签发 Let's Encrypt 证书",
                    "site created; issuing Let's Encrypt certificate",
                );
                let op_id = op_id.to_string();
                match client::wait_for_op(&op_id) {
                    Ok(()) => ok("证书已签发", "certificate issued"),
                    Err(e) => warn(
                        &format!("证书签发失败(站点已建,可稍后 `dn7 cert renew`):{e}"),
                        &format!(
                            "cert issuance failed (site created; retry with `dn7 cert renew`): {e}"
                        ),
                    ),
                }
            } else {
                let id = d
                    .get("site")
                    .and_then(|s| s.get("id"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("?");
                ok(
                    &format!("站点已创建 (id={id})"),
                    &format!("site created (id={id})"),
                );
            }
            0
        }
        Ok(r) => {
            eprintln!("dn7 site: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 site: {e}");
            1
        }
    }
}

/// Prompt for cert + key PEM file paths and read them.
fn read_pem_pair() -> Result<(String, String), String> {
    let cp = prompt_line("证书 PEM 文件路径 / certificate PEM file", "", "");
    let kp = prompt_line("私钥 PEM 文件路径 / private-key PEM file", "", "");
    let cert = std::fs::read_to_string(&cp)
        .map_err(|e| format!("读取证书失败 / cannot read {cp}: {e}"))?;
    let key = std::fs::read_to_string(&kp)
        .map_err(|e| format!("读取私钥失败 / cannot read {kp}: {e}"))?;
    Ok((cert, key))
}

fn list(json: bool) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    match client::website("list_sites", json!({})) {
        Ok(r) if r.is_ok() => {
            let v = r.data();
            if json {
                util::print_json(&v);
                return 0;
            }
            let Some(sites) = v.get("sites").and_then(|s| s.as_array()) else {
                println!("{}", r.body.trim());
                return 0;
            };
            println!("{:<22} {:<30} {:<11} TARGET", "ID", "SERVER NAME", "KIND");
            for s in sites {
                println!(
                    "{:<22} {:<30} {:<11} {}",
                    util::sf(s, &["id"]),
                    util::sf(s, &["server_name", "primary_host", "host"]),
                    util::sf(s, &["kind"]),
                    util::sf(s, &["target_url", "container", "local_root", "root"]),
                );
            }
            0
        }
        Ok(r) => {
            eprintln!("dn7 site: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 site: {e}");
            1
        }
    }
}
