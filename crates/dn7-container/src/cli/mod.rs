//! The runtime's command dispatch — a runc-style CLI over the container runtime,
//! shared by the `dn7crun` test binary and the unified `dn7 container` CLI.
//!
//! [`run`] takes the argv tail (`[verb, ...]`) and returns a process exit code.
//! Linux-only (it drives namespaces/cgroups/overlayfs/nftables directly).
#![cfg(target_os = "linux")]

use std::path::Path;

use nix::sys::signal::Signal;

use crate::{container, image, net};

mod args;
mod term;

use args::*;
use term::exec_tty;

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
            let (pre, cmd) = split_at_dashdash(args);
            let spec = image_spec_from_flags(id, reference, pre, cmd)?;
            container::run_image(&spec).map_err(|e| e.to_string())
        }
        "create-image" => {
            let (id, reference) = two(args)?;
            let (pre, cmd) = split_at_dashdash(args);
            let spec = image_spec_from_flags(id, reference, pre, cmd)?;
            let meta = container::state::StateMeta {
                image: Some(reference.to_string()),
                name: Some(id.to_string()),
                mem_limit: spec.mem_limit,
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
            let full = one_resolved(args)?;
            let id = full.as_str();
            container::start_or_rerun(id).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "state" => {
            let full = one_resolved(args)?;
            let id = full.as_str();
            let st = container::state(id).map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?;
            println!("{json}");
            Ok(0)
        }
        "kill" => {
            // Signal as a flag (`--signal KILL`, docker style) or positional.
            let full = one_resolved(args)?;
            let id = full.as_str();
            let sig = flag_value(args, "--signal")
                .or_else(|| flag_value(args, "-s"))
                .or_else(|| {
                    args.get(2)
                        .map(String::as_str)
                        .filter(|s| !s.starts_with('-'))
                })
                .map(parse_signal)
                .transpose()?
                .unwrap_or(Signal::SIGTERM);
            container::kill(id, sig).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "stop" => {
            // Grace period: `-t <secs>` override, else the container's stored
            // stop_timeout (docker --stop-timeout), else 10s.
            let full = one_resolved(args)?;
            let id = full.as_str();
            let grace = match flag_value(args, "-t").or_else(|| flag_value(args, "--time")) {
                Some(s) => std::time::Duration::from_secs(
                    s.parse::<u64>().map_err(|_| format!("bad -t value: {s}"))?,
                ),
                None => container::state(id)
                    .map(|s| container::stop_grace_period(&s))
                    .unwrap_or(std::time::Duration::from_secs(10)),
            };
            container::stop(id, grace).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "restart" => {
            let full = one_resolved(args)?;
            let id = full.as_str();
            container::restart(id).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "pause" => {
            let full = one_resolved(args)?;
            let id = full.as_str();
            container::pause(id).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "unpause" => {
            let full = one_resolved(args)?;
            let id = full.as_str();
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
            let full = container::resolve(id).map_err(|e| e.to_string())?;
            container::delete(&full, force).map_err(|e| e.to_string())?;
            Ok(0)
        }
        "list" | "ls" => {
            let items = container::list().map_err(|e| e.to_string())?;
            if args.iter().any(|a| a == "--json") {
                let v: Vec<serde_json::Value> = items
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "name": s.meta.name,
                            "image": s.meta.image,
                            "status": s.status.as_str(),
                            "pid": s.pid,
                            "created": s.created,
                            "exit_code": s.meta.exit_code,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
                );
                return Ok(0);
            }
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
            // `logs [-n N] [-f] <id>` — tail the last N lines, then optionally
            // follow appended output (offset-polling `logs_from`, docker -f).
            use std::io::Write;
            let mut follow = false;
            let mut tail: Option<usize> = None;
            let mut id: Option<&str> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-f" | "--follow" => follow = true,
                    "-n" | "--tail" => {
                        let v = args.get(i + 1).ok_or("-n needs a line count")?;
                        tail = Some(v.parse().map_err(|_| format!("bad -n value: {v}"))?);
                        i += 1;
                    }
                    a if a.starts_with('-') => return Err(format!("unknown flag: {a}")),
                    a => id = Some(a),
                }
                i += 1;
            }
            let full =
                container::resolve(id.ok_or("logs needs <id>")?).map_err(|e| e.to_string())?;
            let id = full.as_str();
            let bytes = container::logs(id).map_err(|e| e.to_string())?;
            let out = match tail {
                Some(n) => tail_lines(&bytes, n),
                None => bytes,
            };
            std::io::stdout()
                .write_all(&out)
                .map_err(|e| e.to_string())?;
            let _ = std::io::stdout().flush();
            if follow {
                // Poll from the current end of the live log file (1s cadence);
                // Ctrl-C ends the process like `docker logs -f`.
                let mut offset = std::fs::metadata(container::state::State::log_path(id))
                    .map(|m| m.len())
                    .unwrap_or(0);
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let (chunk, next) =
                        container::logs_from(id, offset).map_err(|e| e.to_string())?;
                    offset = next;
                    if !chunk.is_empty() {
                        std::io::stdout()
                            .write_all(&chunk)
                            .map_err(|e| e.to_string())?;
                        let _ = std::io::stdout().flush();
                    }
                }
            }
            Ok(0)
        }
        "exec-cap" => {
            use std::io::Write;
            let full = one_resolved(args)?;
            let id = full.as_str();
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
            // Docker-style: `exec [-i] [-t|-it|-ti] <id> <cmd> [args…]`. A tty
            // request routes to the interactive PTY bridge (what `exec-pty`
            // does); the flags used to be swallowed into the command line.
            let mut tty = false;
            let mut rest: Vec<String> = Vec::new();
            for (i, a) in args.iter().enumerate().skip(1) {
                if a == "--" {
                    rest.extend(args[i + 1..].iter().cloned());
                    break;
                }
                if rest.is_empty() {
                    match a.as_str() {
                        "-t" | "--tty" | "-it" | "-ti" => {
                            tty = true;
                            continue;
                        }
                        "-i" | "--interactive" => continue, // stdin is always bridged
                        f if f.starts_with('-') => return Err(format!("unknown flag: {f}")),
                        _ => {}
                    }
                }
                rest.push(a.clone());
            }
            let (id, cmd) = rest
                .split_first()
                .ok_or("exec needs <id> <cmd> [args...]")?;
            let full = container::resolve(id).map_err(|e| e.to_string())?;
            let id = full.as_str();
            if tty {
                return exec_tty(id, cmd);
            }
            if cmd.is_empty() {
                return Err("exec needs <id> <cmd> [args...]".into());
            }
            container::exec(id, cmd).map_err(|e| e.to_string())
        }
        "exec-pty" => {
            let full = one_resolved(args)?;
            let id = full.as_str();
            let sep = args.iter().position(|a| a == "--");
            let cmd: Vec<String> = match sep {
                Some(i) => args[i + 1..].to_vec(),
                None => vec!["/bin/sh".to_string()],
            };
            exec_tty(id, &cmd)
        }
        "stats" => {
            let full = one_resolved(args)?;
            let id = full.as_str();
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
            if args.iter().any(|a| a == "--json") {
                let v: Vec<serde_json::Value> = imgs
                    .iter()
                    .map(|im| {
                        serde_json::json!({
                            "reference": im.reference,
                            "id": im.config_digest,
                            "size": im.size,
                            "created": im.created_ts,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
                );
                return Ok(0);
            }
            // Fit the REFERENCE column to the longest name instead of cutting
            // long registry paths at a fixed 44 chars.
            let w = imgs.iter().map(|im| im.reference.len()).max().unwrap_or(0);
            let w = w.clamp(44, 100);
            println!(
                "{:<w$} {:<14} {:>10}  CREATED",
                "REFERENCE", "IMAGE ID", "SIZE"
            );
            for im in imgs {
                let id = im
                    .config_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&im.config_digest);
                let id = &id[..id.len().min(12)];
                println!(
                    "{:<w$} {:<14} {:>10}  {}",
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
            if args.iter().any(|a| a == "--json") {
                let v: Vec<serde_json::Value> = vols
                    .iter()
                    .map(|v| serde_json::json!({ "name": v.name, "mountpoint": v.path }))
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
                );
                return Ok(0);
            }
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
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            Ok(0)
        }
        "" => Err(format!("missing command\n{HELP}")),
        other => Err(format!("unknown command: {other}\n{HELP}")),
    }
}

const HELP: &str = "\
usage: dn7 container <command> [options]

containers:
  run <id> <bundle>                 run an OCI bundle (create + start)
  run-image <id> <ref> [opts] [-- cmd…]     pull/run an image
  create-image <id> <ref> [opts] [-- cmd…]  create without starting
      opts: -p [ip:]hp:cp[/proto]  -v src:dst[:ro]  -e K=V  --net bridge|host|none
            --ip a.b.c.d  --mac-address MAC  --hostname H  --dns IP
            --mem BYTES  --cpus N  --cpu-shares N  --pids-limit N  -t|--tty
  create <id> <bundle>              create from a bundle (parked until start)
  start|restart|pause|unpause <id>
  stop [-t secs] <id>               graceful stop (stored stop-timeout, else 10s)
  kill [--signal SIG] <id>          send a signal (default SIGTERM)
  rm|delete [-f] <id>               remove (force kills first)
  ls|list [--json]                  list containers
  state <id>                        full state record (JSON)
  stats <id>                        cgroup resource counters (JSON)
  logs [-n N] [-f] <id>             show logs; -f follows like docker logs -f
  exec [-it] <id> <cmd> [args…]     run a command inside (-t: interactive PTY)
  exec-pty <id> [-- cmd…]           interactive PTY shell (default /bin/sh)
  exec-cap [-e K=V] <id> -- cmd…    run + capture combined output

images & volumes:
  pull <ref>                        pull an image (arch auto-selected)
  images [--json]                   list stored images
  rmi <ref>                         remove an image (keeps shared layers)
  save <ref> <out.tar>              export OCI image tar
  load <in.tar> <ref>               import an image tar (OCI or docker save)
  commit <id> <new-ref>             snapshot a container into an image
  volumes [--json]                  list named volumes

network:
  net gc                            reclaim leaked container networks";
