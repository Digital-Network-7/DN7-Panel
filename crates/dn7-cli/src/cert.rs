//! `dn7 cert <ls|issue|renew|rm>` — named TLS certificates, via the control
//! channel. Issuance has explicit modes: `le` (Let's Encrypt, async), `self`
//! (self-signed, sync), `manual` (user-supplied PEM pair).

use crate::common::*;
use crate::{client, util};
use serde_json::json;

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("ls") {
        "ls" | "list" => list(util::wants_json(args)),
        "issue" | "new" => issue(&args[1..]),
        "renew" => {
            let Some(name) = args.get(1) else {
                eprintln!("用法 / usage: dn7 cert renew <name>");
                return 2;
            };
            if let Err(c) = require_root() {
                return c;
            }
            client::act(
                client::website_setup_aware("renew_cert", json!({ "cert_name": name })),
                "证书已续期",
                "certificate renewed",
            )
        }
        "rm" | "remove" => {
            let Some(name) = args.get(1) else {
                eprintln!("用法 / usage: dn7 cert rm <name>");
                return 2;
            };
            if let Err(c) = require_root() {
                return c;
            }
            if !prompt_yes_no(
                &format!("确认删除证书 {name}?"),
                &format!("delete cert {name}?"),
            ) {
                println!("已取消 / cancelled");
                return 0;
            }
            client::act(
                client::website_setup_aware("delete_cert", json!({ "cert_name": name })),
                "证书已删除",
                "certificate removed",
            )
        }
        other => {
            eprintln!("dn7 cert: 未知子命令 / unknown '{other}' (ls|issue|renew|rm)");
            2
        }
    }
}

fn issue(rest: &[String]) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    let usage = || {
        eprintln!(
            "用法 / usage:\n  \
             dn7 cert issue le <domain> [--key-type p256|p384]     # Let's Encrypt (异步/async)\n  \
             dn7 cert issue self <domain> [--key-type p256|p384]   # 自签 / self-signed\n  \
             dn7 cert issue manual <domain> --cert <pem-file> --key <pem-file>"
        );
        2
    };
    let Some(mode) = rest.first().map(String::as_str) else {
        return usage();
    };
    let Some(domain) = rest.get(1) else {
        return usage();
    };
    // ECDSA curve for auto-generated (le/self) certs; "" = server default (P-256).
    let key_type = norm_key_type(util::flag_val(rest, "--key-type").unwrap_or(""));
    match mode {
        "le" => {
            let wait = util::has_flag(rest, "--wait");
            // Don't start a second ACME order for a host that already has one in
            // flight (the server's dup guard can't see an unfinished issuance).
            if let Some(existing) = client::running_cert_op(domain) {
                if wait {
                    println!(
                        "  · 该域名已有签发在进行,改为等待其完成 / an issuance for this host is already running; waiting for it…"
                    );
                    return match client::wait_for_op(&existing) {
                        Ok(()) => {
                            ok("证书已签发", "certificate issued");
                            0
                        }
                        Err(e) => {
                            warn(&format!("签发失败:{e}"), &format!("issuance failed: {e}"));
                            1
                        }
                    };
                }
                warn(
                    &format!("{domain} 已在签发中(加 --wait 等待,或 `dn7 cert ls` 查看)"),
                    &format!(
                        "issuance for {domain} is already running (use --wait, or `dn7 cert ls`)"
                    ),
                );
                return 1;
            }
            match client::website_setup_aware(
                "create_cert",
                json!({ "cert_mode": "le", "server_name": domain, "key_type": key_type }),
            ) {
                Ok(r) if r.is_ok() => {
                    let op = r
                        .data()
                        .get("op_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    if wait && !op.is_empty() {
                        println!(
                            "  · Let's Encrypt 签发中(可能 1-2 分钟)/ issuing (may take 1-2 min)…"
                        );
                        match client::wait_for_op(&op) {
                            Ok(()) => {
                                ok("证书已签发", "certificate issued");
                                0
                            }
                            Err(e) => {
                                warn(&format!("签发失败:{e}"), &format!("issuance failed: {e}"));
                                1
                            }
                        }
                    } else {
                        ok(
                            "Let's Encrypt 签发已开始(异步)",
                            "Let's Encrypt issuance started (async)",
                        );
                        println!("  op: {op} — 用 `dn7 cert ls` 查看,或加 --wait 等待完成");
                        0
                    }
                }
                Ok(r) => {
                    eprintln!("dn7 cert: {}", r.err_text());
                    1
                }
                Err(e) => {
                    eprintln!("dn7 cert: {e}");
                    1
                }
            }
        }
        "self" => client::act(
            client::website_setup_aware(
                "create_cert",
                json!({ "cert_mode": "self", "server_name": domain, "key_type": key_type }),
            ),
            "自签证书已生成",
            "self-signed certificate created",
        ),
        "manual" => {
            let Some(cert_path) = util::flag_val(rest, "--cert") else {
                return usage();
            };
            let Some(key_path) = util::flag_val(rest, "--key") else {
                return usage();
            };
            let cert = match std::fs::read_to_string(cert_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("dn7 cert: 读取证书失败 / cannot read {cert_path}: {e}");
                    return 2;
                }
            };
            let key = match std::fs::read_to_string(key_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("dn7 cert: 读取私钥失败 / cannot read {key_path}: {e}");
                    return 2;
                }
            };
            client::act(
                client::website_setup_aware(
                    "create_cert",
                    json!({ "cert_mode": "manual", "server_name": domain, "cert_pem": cert, "key_pem": key }),
                ),
                "证书已导入",
                "certificate imported",
            )
        }
        _ => usage(),
    }
}

/// Normalize a `--key-type` value to a wire `key_type` ("" = server default P-256).
fn norm_key_type(s: &str) -> String {
    match s.trim().to_ascii_lowercase().as_str() {
        "p384" | "ecdsa-p384" | "384" => "ecdsa-p384".to_string(),
        "p256" | "ecdsa-p256" | "256" => "ecdsa-p256".to_string(),
        _ => String::new(),
    }
}

fn list(json: bool) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    match client::website("list_named_certs", json!({})) {
        // The cert list gates on setup; before the first site/cert it's just empty.
        Ok(r) if !r.is_ok() && r.has_code("website.not_setup") => {
            if json {
                util::print_json(&json!({ "certs": [] }));
                return 0;
            }
            println!(
                "{:<22} {:<22} {:<6} {:<6} {:<20} USED-BY",
                "NAME", "DOMAIN", "MODE", "KEY", "EXPIRES"
            );
            0
        }
        Ok(r) if r.is_ok() => {
            let v = r.data();
            if json {
                util::print_json(&v);
                return 0;
            }
            let Some(certs) = v.get("certs").and_then(|c| c.as_array()) else {
                println!("{}", r.body.trim());
                return 0;
            };
            println!(
                "{:<22} {:<22} {:<6} {:<6} {:<20} USED-BY",
                "NAME", "DOMAIN", "MODE", "KEY", "EXPIRES"
            );
            for c in certs {
                let used = c
                    .get("used_by")
                    .and_then(|u| u.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "-".into());
                let expires = util::sf(c, &["not_after"]);
                let expires = if expires == "-" || expires.is_empty() {
                    "—".to_string()
                } else {
                    expires
                };
                let key = util::sf(c, &["key_type"]);
                let key = key.strip_prefix("ecdsa-").unwrap_or(&key);
                println!(
                    "{:<22} {:<22} {:<6} {:<6} {:<20} {}",
                    util::sf(c, &["name"]),
                    util::sf(c, &["domain"]),
                    util::sf(c, &["cert_mode"]),
                    key,
                    expires,
                    used,
                );
            }
            0
        }
        Ok(r) => {
            eprintln!("dn7 cert: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 cert: {e}");
            1
        }
    }
}
