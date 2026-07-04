//! Argv parsing for the container CLI: positional/flag helpers, the
//! `run-image`/`create-image` spec builder, and small formatting utilities.
//! Unknown flags are hard errors — a typo must never be silently skipped as if
//! the option had been applied.

use std::str::FromStr;

use nix::sys::signal::Signal;

use crate::{container, image};

/// `(flags-before---, command-after---)` split for `run-image`/`create-image`.
pub(super) fn split_at_dashdash(args: &[String]) -> (&[String], Vec<String>) {
    match args.iter().position(|a| a == "--") {
        Some(i) => (&args[..i], args[i + 1..].to_vec()),
        None => (args, Vec::new()),
    }
}

/// Build an [`container::ImageRunSpec`] from `run-image`/`create-image` flags.
/// Every flag the spec supports is parsed (dns/hostname/limits used to be
/// silently hardcoded empty), and an unknown flag is an ERROR — a typo like
/// `--cpuz` must not be skipped as if the option were applied.
pub(super) fn image_spec_from_flags(
    id: &str,
    reference: &str,
    pre: &[String],
    cmd: Vec<String>,
) -> Result<container::ImageRunSpec, String> {
    const VALUED: &[&str] = &[
        "-v",
        "-p",
        "-e",
        "--net",
        "--ip",
        "--mac-address",
        "--mem",
        "--cpus",
        "--cpu-shares",
        "--pids-limit",
        "--dns",
        "--hostname",
    ];
    const BOOLS: &[&str] = &["-t", "--tty"];
    check_flags(&pre[1..], VALUED, BOOLS)?;
    let mut volumes = Vec::new();
    for vs in flag_values(pre, "-v") {
        volumes.push(image::volume::resolve(&vs).map_err(|e| e.to_string())?);
    }
    let parse_i64 = |flag: &str| -> Result<Option<i64>, String> {
        match flag_value(pre, flag) {
            Some(s) => s
                .parse::<i64>()
                .map(Some)
                .map_err(|_| format!("bad {flag} value: {s}")),
            None => Ok(None),
        }
    };
    let mem_limit = parse_i64("--mem")?;
    let cpu_shares = match flag_value(pre, "--cpu-shares") {
        Some(s) => Some(
            s.parse::<u64>()
                .map_err(|_| format!("bad --cpu-shares value: {s}"))?,
        ),
        None => None,
    };
    let pids_limit = parse_i64("--pids-limit")?;
    let cpu_quota = match flag_value(pre, "--cpus") {
        Some(s) => {
            let c: f64 = s.parse().map_err(|_| format!("bad --cpus value: {s}"))?;
            Some(((c * 100_000.0) as i64, 100_000u64))
        }
        None => None,
    };
    Ok(container::ImageRunSpec {
        id: id.to_string(),
        reference: reference.to_string(),
        cmd,
        net_mode: flag_value(pre, "--net").unwrap_or("bridge").to_string(),
        ports: flag_values(pre, "-p").join(","),
        volumes,
        env_extra: flag_values(pre, "-e"),
        dns: flag_values(pre, "--dns"),
        hostname: flag_value(pre, "--hostname").map(str::to_string),
        mem_limit,
        cpu_quota,
        cpu_shares,
        pids_limit,
        tty: pre.iter().any(|a| a == "-t" || a == "--tty"),
        static_ip: flag_value(pre, "--ip").map(str::to_string),
        static_mac: flag_value(pre, "--mac-address").map(str::to_string),
    })
}

/// Reject any `-`-prefixed arg that isn't a known flag. Positionals (no `-`)
/// pass through; a valued flag also skips its argument.
pub(super) fn check_flags(args: &[String], valued: &[&str], bools: &[&str]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a.starts_with('-') {
            if valued.contains(&a) {
                i += 2;
                continue;
            }
            if bools.contains(&a) {
                i += 1;
                continue;
            }
            return Err(format!("unknown flag: {a} (see `dn7 container help`)"));
        }
        i += 1;
    }
    Ok(())
}

/// The last `n` lines of `bytes` (whole buffer when it has fewer).
pub(super) fn tail_lines(bytes: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let mut seen = 0usize;
    for (i, b) in bytes.iter().enumerate().rev() {
        if *b == b'\n' {
            // The trailing newline (last byte) doesn't start a line.
            if i == bytes.len() - 1 {
                continue;
            }
            seen += 1;
            if seen == n {
                return bytes[i + 1..].to_vec();
            }
        }
    }
    bytes.to_vec()
}

pub(super) fn one(args: &[String]) -> Result<&str, String> {
    args.get(1)
        .map(String::as_str)
        .ok_or_else(|| format!("{} needs <id>", args[0]))
}

/// Like [`one`] but resolves the reference (name / id-prefix → full id), so every
/// CLI verb accepts a container name or short id the way the web console does.
pub(super) fn one_resolved(args: &[String]) -> Result<String, String> {
    crate::container::resolve(one(args)?).map_err(|e| e.to_string())
}

pub(super) fn two(args: &[String]) -> Result<(&str, &str), String> {
    let id = args.get(1).map(String::as_str);
    let bundle = args.get(2).map(String::as_str);
    match (id, bundle) {
        (Some(i), Some(b)) => Ok((i, b)),
        _ => Err(format!("{} needs <id> <bundle>", args[0])),
    }
}

/// The value following `flag` (e.g. `--net bridge` → `Some("bridge")`).
pub(super) fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Every value following each occurrence of `flag` (e.g. repeated `-p`).
pub(super) fn flag_values(args: &[String], flag: &str) -> Vec<String> {
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
pub(super) fn parse_signal(s: &str) -> Result<Signal, String> {
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
pub(super) fn human_size(bytes: u64) -> String {
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
