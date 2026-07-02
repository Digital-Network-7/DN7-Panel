//! The runtime's command dispatch — a runc-style CLI over the container runtime,
//! shared by the `dn7crun` test binary and the unified `dn7 container` CLI.
//!
//! [`run`] takes the argv tail (`[verb, ...]`) and returns a process exit code.
//! Linux-only (it drives namespaces/cgroups/overlayfs/nftables directly).
#![cfg(target_os = "linux")]

use std::path::Path;
use std::str::FromStr;

use nix::sys::signal::Signal;

use crate::{container, image, net};

/// Dispatch one runtime command. `args` is the argv tail: `args[0]` is the verb.
pub fn run(args: &[String]) -> Result<i32, String> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "run" => {
            let (id, bundle) = two(args)?;
            container::run(id, Path::new(bundle)).map_err(|e| e.to_string())
        }
        "pull" => {
            let reference = one(args)?;
            let store = image::Store::open().map_err(|e| e.to_string())?;
            let rec = image::pull(reference, &store).map_err(|e| e.to_string())?;
            println!("{}", rec.reference);
            println!("  config {}", rec.config_digest);
            for l in &rec.layers {
                println!("  layer  {l}");
            }
            Ok(0)
        }
        "save" => {
            let (reference, out) = two(args)?;
            let store = image::Store::open().map_err(|e| e.to_string())?;
            image::archive::save(&store, reference, Path::new(out)).map_err(|e| e.to_string())?;
            eprintln!("saved {reference} → {out}");
            Ok(0)
        }
        "load" => {
            let (input, reference) = two(args)?;
            let store = image::Store::open().map_err(|e| e.to_string())?;
            let rec = image::archive::load(&store, Path::new(input), reference)
                .map_err(|e| e.to_string())?;
            println!("{}", rec.reference);
            Ok(0)
        }
        "commit" => {
            let (id, new_ref) = two(args)?;
            let store = image::Store::open().map_err(|e| e.to_string())?;
            let bundle = container::bundle_dir(id);
            let rec = image::commit::commit(&store, &bundle, new_ref).map_err(|e| e.to_string())?;
            println!("{}", rec.reference);
            Ok(0)
        }
        "run-image" => {
            let (id, reference) = two(args)?;
            let sep = args.iter().position(|a| a == "--");
            let pre = match sep {
                Some(i) => &args[..i],
                None => args,
            };
            let mut volumes = Vec::new();
            for vs in flag_values(pre, "-v") {
                volumes.push(image::volume::resolve(&vs).map_err(|e| e.to_string())?);
            }
            let cmd: Vec<String> = match sep {
                Some(i) => args[i + 1..].to_vec(),
                None => Vec::new(),
            };
            let spec = container::ImageRunSpec {
                id: id.to_string(),
                reference: reference.to_string(),
                cmd,
                net_mode: flag_value(pre, "--net").unwrap_or("bridge").to_string(),
                ports: flag_values(pre, "-p").join(","),
                volumes,
                env_extra: flag_values(pre, "-e"),
                dns: Vec::new(),
                hostname: None,
                mem_limit: None,
                cpu_quota: None,
                cpu_shares: None,
                pids_limit: None,
            };
            container::run_image(&spec).map_err(|e| e.to_string())
        }
        "create-image" => {
            let (id, reference) = two(args)?;
            let sep = args.iter().position(|a| a == "--");
            let pre = match sep {
                Some(i) => &args[..i],
                None => args,
            };
            let mut volumes = Vec::new();
            for vs in flag_values(pre, "-v") {
                volumes.push(image::volume::resolve(&vs).map_err(|e| e.to_string())?);
            }
            let cmd: Vec<String> = match sep {
                Some(i) => args[i + 1..].to_vec(),
                None => Vec::new(),
            };
            let mem_limit = flag_value(pre, "--mem").and_then(|s| s.parse::<i64>().ok());
            let cpu_quota = flag_value(pre, "--cpus")
                .and_then(|s| s.parse::<f64>().ok())
                .map(|c| ((c * 100_000.0) as i64, 100_000u64));
            let spec = container::ImageRunSpec {
                id: id.to_string(),
                reference: reference.to_string(),
                cmd,
                net_mode: flag_value(pre, "--net").unwrap_or("bridge").to_string(),
                ports: flag_values(pre, "-p").join(","),
                volumes,
                env_extra: flag_values(pre, "-e"),
                dns: Vec::new(),
                hostname: None,
                mem_limit,
                cpu_quota,
                cpu_shares: None,
                pids_limit: None,
            };
            let meta = container::state::StateMeta {
                image: Some(reference.to_string()),
                name: Some(id.to_string()),
                mem_limit,
                ..Default::default()
            };
            let cid = container::create_from_image(&spec, meta).map_err(|e| e.to_string())?;
            println!("{cid}");
            Ok(0)
        }
        "create" => {
            let (id, bundle) = two(args)?;
            container::create(id, Path::new(bundle)).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "start" => {
            let id = one(args)?;
            container::start_or_rerun(id).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "state" => {
            let id = one(args)?;
            let st = container::state(id).map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?;
            println!("{json}");
            Ok(0)
        }
        "kill" => {
            let id = one(args)?;
            let sig = args
                .get(2)
                .map(|s| parse_signal(s))
                .transpose()?
                .unwrap_or(Signal::SIGTERM);
            container::kill(id, sig).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "stop" => {
            let id = one(args)?;
            container::stop(id, std::time::Duration::from_secs(10)).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "restart" => {
            let id = one(args)?;
            container::restart(id).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "pause" => {
            let id = one(args)?;
            container::pause(id).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "unpause" => {
            let id = one(args)?;
            container::unpause(id).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "delete" | "rm" => {
            let force = args.iter().any(|a| a == "--force" || a == "-f");
            let id = args
                .iter()
                .skip(1)
                .find(|a| !a.starts_with('-'))
                .map(String::as_str)
                .ok_or("delete needs <id>")?;
            container::delete(id, force).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "list" | "ls" => {
            let items = container::list().map_err(|e| e.to_string())?;
            println!("{:<24} {:<9} {:>8}  CREATED", "ID", "STATUS", "PID");
            for s in items {
                println!(
                    "{:<24} {:<9} {:>8}  {}",
                    s.id,
                    s.status.as_str(),
                    s.pid,
                    s.created
                );
            }
            Ok(0)
        }
        "logs" => {
            let id = one(args)?;
            let bytes = container::logs(id).map_err(|e| e.to_string())?;
            use std::io::Write;
            std::io::stdout()
                .write_all(&bytes)
                .map_err(|e| e.to_string())?;
            Ok(0)
        }
        "exec-cap" => {
            use std::io::Write;
            let id = one(args)?;
            let sep = args.iter().position(|a| a == "--");
            let pre = match sep {
                Some(i) => &args[..i],
                None => args,
            };
            let env: Vec<(String, String)> = flag_values(pre, "-e")
                .iter()
                .filter_map(|a| {
                    a.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect();
            let cmd: Vec<String> = match sep {
                Some(i) => args[i + 1..].to_vec(),
                None => Vec::new(),
            };
            let (code, out) = container::exec_capture(id, &cmd, &env).map_err(|e| e.to_string())?;
            let _ = std::io::stdout().write_all(out.as_bytes());
            Ok(code)
        }
        "exec" => {
            let id = one(args)?;
            let cmd = &args[2.min(args.len())..];
            if cmd.is_empty() {
                return Err("exec needs <id> <cmd> [args...]".into());
            }
            container::exec(id, cmd).map_err(|e| e.to_string())
        }
        "exec-pty" => {
            use std::io::{Read, Write};
            let id = one(args)?;
            let sep = args.iter().position(|a| a == "--");
            let cmd: Vec<String> = match sep {
                Some(i) => args[i + 1..].to_vec(),
                None => vec!["/bin/sh".to_string()],
            };
            let container::ExecPty { master, mut child } =
                container::exec_pty(id, &cmd).map_err(|e| e.to_string())?;
            let mut f = std::fs::File::from(master);
            let mut buf = [0u8; 4096];
            loop {
                match f.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = std::io::stdout().write_all(&buf[..n]);
                    }
                }
            }
            let _ = child.wait();
            Ok(0)
        }
        "stats" => {
            let id = one(args)?;
            let st = container::stats(id).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?
            );
            Ok(0)
        }
        "images" => {
            let store = image::Store::open().map_err(|e| e.to_string())?;
            let imgs = image::list_summaries(&store).map_err(|e| e.to_string())?;
            println!(
                "{:<44} {:<14} {:>10}  CREATED",
                "REFERENCE", "IMAGE ID", "SIZE"
            );
            for im in imgs {
                let id = im
                    .config_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&im.config_digest);
                let id = &id[..id.len().min(12)];
                println!(
                    "{:<44} {:<14} {:>10}  {}",
                    im.reference,
                    id,
                    human_size(im.size),
                    im.created_ts
                );
            }
            Ok(0)
        }
        "rmi" => {
            let reference = one(args)?;
            let store = image::Store::open().map_err(|e| e.to_string())?;
            image::remove_image(&store, reference).map_err(|e| e.to_string())?;
            println!("removed {reference}");
            Ok(0)
        }
        "volumes" => {
            let vols = image::volume::list().map_err(|e| e.to_string())?;
            println!("{:<28} MOUNTPOINT", "NAME");
            for v in vols {
                println!("{:<28} {}", v.name, v.path.display());
            }
            Ok(0)
        }
        "net" => match args.get(1).map(String::as_str) {
            Some("gc") => {
                let n = net::NetworkManager::new().gc().map_err(|e| e.to_string())?;
                println!("reclaimed {n} leaked container network(s)");
                Ok(0)
            }
            _ => Err("usage: net gc".into()),
        },
        "" => Err(
            "missing command (run|create|start|stop|restart|kill|delete|list|logs|\
            exec|exec-pty|stats|pull|images|rmi|volumes|save|load|commit|run-image|\
            create-image|net)"
                .into(),
        ),
        other => Err(format!("unknown command: {other}")),
    }
}

fn one(args: &[String]) -> Result<&str, String> {
    args.get(1)
        .map(String::as_str)
        .ok_or_else(|| format!("{} needs <id>", args[0]))
}

fn two(args: &[String]) -> Result<(&str, &str), String> {
    let id = args.get(1).map(String::as_str);
    let bundle = args.get(2).map(String::as_str);
    match (id, bundle) {
        (Some(i), Some(b)) => Ok((i, b)),
        _ => Err(format!("{} needs <id> <bundle>", args[0])),
    }
}

/// The value following `flag` (e.g. `--net bridge` → `Some("bridge")`).
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Every value following each occurrence of `flag` (e.g. repeated `-p`).
fn flag_values(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Accept `9`, `KILL`, or `SIGKILL`.
fn parse_signal(s: &str) -> Result<Signal, String> {
    if let Ok(n) = s.parse::<i32>() {
        return Signal::try_from(n).map_err(|_| format!("invalid signal number: {n}"));
    }
    let name = if s.starts_with("SIG") {
        s.to_string()
    } else {
        format!("SIG{}", s.to_uppercase())
    };
    Signal::from_str(&name).map_err(|_| format!("invalid signal: {s}"))
}

/// Human-readable byte size (e.g. `4.0MB`).
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut b = bytes as f64;
    let mut i = 0;
    while b >= 1024.0 && i < UNITS.len() - 1 {
        b /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}B")
    } else {
        format!("{b:.1}{}", UNITS[i])
    }
}
