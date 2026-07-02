//! `dn7 logs` / `dn7 metrics` / `dn7 update` — read-only views over the running
//! panel, via the control channel.

use crate::client;
use crate::common::require_root;
use crate::util;

pub fn logs(args: &[String]) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    match client::api("GET", "/api/logs", None) {
        Ok(r) if r.is_ok() => {
            let v = r.data();
            if util::wants_json(args) {
                util::print_json(&v);
                return 0;
            }
            let Some(rows) = v.get("entries").and_then(|l| l.as_array()) else {
                println!("{}", r.body.trim());
                return 0;
            };
            println!(
                "{:<22} {:<10} {:<10} {:<16} RESULT",
                "TIME", "ACCOUNT", "MODULE", "ACTION"
            );
            for row in rows {
                println!(
                    "{:<22} {:<10} {:<10} {:<16} {}",
                    util::sf(row, &["time", "ts", "at"]),
                    util::sf(row, &["account", "user"]),
                    util::sf(row, &["module", "capability"]),
                    util::sf(row, &["action", "op"]),
                    util::sf(row, &["result", "ok", "status"]),
                );
            }
            0
        }
        Ok(r) => {
            eprintln!("dn7 logs: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 logs: {e}");
            1
        }
    }
}

pub fn metrics(args: &[String]) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    match client::api("GET", "/api/metrics", None) {
        Ok(r) if r.is_ok() => {
            let v = r.data();
            if util::wants_json(args) {
                util::print_json(&v);
                return 0;
            }
            let num = |k: &str| v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
            println!("DN7 指标 / metrics");
            println!(
                "  CPU    : {:.1}% ({} 核 / cores)",
                num("cpu_usage"),
                v.get("cpu_cores").and_then(|x| x.as_u64()).unwrap_or(0)
            );
            println!("  内存/mem: {:.1}%", num("memory_usage"));
            println!("  磁盘/disk: {:.1}%", num("disk_usage"));
            0
        }
        Ok(r) => {
            eprintln!("dn7 metrics: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 metrics: {e}");
            1
        }
    }
}

pub fn update(args: &[String]) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    match client::api("GET", "/api/update/status", None) {
        Ok(r) if r.is_ok() => {
            let v = r.data();
            if util::wants_json(args) {
                util::print_json(&v);
                return 0;
            }
            let avail = v
                .get("available")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let latest = v.get("latest").and_then(|x| x.as_str()).unwrap_or("-");
            let current = v.get("current").and_then(|x| x.as_str()).unwrap_or("-");
            println!("当前 / current: {current}   最新 / latest: {latest}");
            if avail {
                println!("有可用更新 / update available — 用 `dn7 panel restart` 在自动更新启用时应用,或在控制台更新。");
            } else {
                println!("已是最新 / up to date。");
            }
            0
        }
        Ok(r) => {
            eprintln!("dn7 update: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 update: {e}");
            1
        }
    }
}
