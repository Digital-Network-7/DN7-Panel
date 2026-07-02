//! `dn7 user <ls|add|passwd|rm>` — panel users (each a real system account),
//! via the control channel. `add`/`passwd` derive the password verifier
//! client-side (the panel wraps it in Argon2id at rest) and also sync the OS
//! account password.

use crate::common::*;
use crate::{client, kdf, util};
use serde_json::json;

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("ls") {
        "ls" | "list" => list(util::wants_json(args)),
        "add" | "new" => add(&args[1..]),
        "passwd" | "password" => passwd(&args[1..]),
        "rm" | "remove" => rm(args.get(1)),
        other => {
            eprintln!("dn7 user: 未知子命令 / unknown '{other}' (ls|add|passwd|rm)");
            2
        }
    }
}

fn add(rest: &[String]) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    let Some(username) = rest
        .first()
        .map(String::as_str)
        .filter(|s| !s.starts_with('-'))
    else {
        eprintln!(
            "用法 / usage: dn7 user add <username> [--admin] [--full-name <name>] \
             [--password <pw> | --stdin]"
        );
        return 2;
    };
    let role = if util::has_flag(rest, "--admin") {
        "admin"
    } else {
        "user"
    };
    let full_name = util::flag_val(rest, "--full-name").unwrap_or("");
    let password = match kdf::resolve_password(
        util::flag_val(rest, "--password"),
        util::has_flag(rest, "--stdin"),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("dn7 user: {e}");
            return 2;
        }
    };
    let cred = kdf::make_credential(&password);
    let body = json!({
        "username": username,
        "role": role,
        "full_name": full_name,
        "pw_salt": cred.salt,
        "pw_hash": cred.hash,
        "pw_kdf": cred.kdf,
        "password": password,
    });
    client::act(
        client::api("POST", "/api/users", Some(&body)),
        &format!("已创建用户 {username} ({role})"),
        &format!("user {username} created ({role})"),
    )
}

fn passwd(rest: &[String]) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    let Some(username) = rest
        .first()
        .map(String::as_str)
        .filter(|s| !s.starts_with('-'))
    else {
        eprintln!("用法 / usage: dn7 user passwd <username> [--password <pw> | --stdin]");
        return 2;
    };
    let password = match kdf::resolve_password(
        util::flag_val(rest, "--password"),
        util::has_flag(rest, "--stdin"),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("dn7 user: {e}");
            return 2;
        }
    };
    let cred = kdf::make_credential(&password);
    let body = json!({
        "username": username,
        "pw_salt": cred.salt,
        "pw_hash": cred.hash,
        "pw_kdf": cred.kdf,
        "password": password,
    });
    client::act(
        client::api("POST", "/api/users/update", Some(&body)),
        &format!("已修改 {username} 的密码"),
        &format!("password updated for {username}"),
    )
}

fn rm(name: Option<&String>) -> i32 {
    let Some(name) = name else {
        eprintln!("用法 / usage: dn7 user rm <username>");
        return 2;
    };
    if let Err(c) = require_root() {
        return c;
    }
    if !prompt_yes_no(
        &format!("确认删除用户 {name}(含系统账号)?"),
        &format!("delete user {name} (incl. OS account)?"),
    ) {
        println!("已取消 / cancelled");
        return 0;
    }
    client::act(
        client::api(
            "POST",
            "/api/users/delete",
            Some(&json!({ "username": name })),
        ),
        "用户已删除",
        "user removed",
    )
}

fn list(json: bool) -> i32 {
    if let Err(c) = require_root() {
        return c;
    }
    match client::api("GET", "/api/users", None) {
        Ok(r) if r.is_ok() => {
            let v = r.data();
            if json {
                util::print_json(&v);
                return 0;
            }
            let users = v
                .get("users")
                .and_then(|u| u.as_array())
                .or_else(|| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!("{:<20} {:<8} {:<7} 2FA", "USERNAME", "ROLE", "UID");
            for u in &users {
                let twofa = u
                    .get("totp_enabled")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let is_super = u.get("is_super").and_then(|x| x.as_bool()).unwrap_or(false);
                let role = if is_super {
                    "owner".to_string()
                } else {
                    util::sf(u, &["role"])
                };
                println!(
                    "{:<20} {:<8} {:<7} {}",
                    util::sf(u, &["username"]),
                    role,
                    util::sf(u, &["uid"]),
                    if twofa { "on" } else { "off" },
                );
            }
            0
        }
        Ok(r) => {
            eprintln!("dn7 user: {}", r.err_text());
            1
        }
        Err(e) => {
            eprintln!("dn7 user: {e}");
            1
        }
    }
}
