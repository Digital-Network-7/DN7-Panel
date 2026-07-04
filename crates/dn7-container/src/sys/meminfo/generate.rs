//! cgroup v2 → `/proc/meminfo` text, following LXCFS `proc_meminfo_read`. The
//! goal: `free`/`top` inside a container show the container's memory *limit* as
//! total and a sensible used/available, instead of the host's RAM. Everything is
//! best-effort — any read failure falls back to the real host `/proc/meminfo`.

use std::path::Path;

use super::resolve;

/// Full `/proc/meminfo` text for the process `pid` (host pidns). Non-container
/// callers (and any failure) get the host meminfo verbatim.
pub fn meminfo_for_pid(pid: u32) -> String {
    match resolve::container_cgroup_of(pid) {
        Some(cg) => synth(&cg).unwrap_or_else(host_meminfo),
        None => host_meminfo(),
    }
}

fn host_meminfo() -> String {
    std::fs::read_to_string("/proc/meminfo").unwrap_or_default()
}

/// Host memory/swap totals (kB) that cap the synthesized values.
struct HostMem {
    mem_total: u64,
    swap_total: u64,
    swap_free: u64,
}

impl HostMem {
    fn scan() -> HostMem {
        let mut m = HostMem {
            mem_total: 0,
            swap_total: 0,
            swap_free: 0,
        };
        if let Ok(txt) = std::fs::read_to_string("/proc/meminfo") {
            for line in txt.lines() {
                if let Some(v) = kb_line(line, "MemTotal:") {
                    m.mem_total = v;
                } else if let Some(v) = kb_line(line, "SwapTotal:") {
                    m.swap_total = v;
                } else if let Some(v) = kb_line(line, "SwapFree:") {
                    m.swap_free = v;
                }
            }
        }
        m
    }
}

/// Parse a `<label>   <number> kB` meminfo line into its kB value.
fn kb_line(line: &str, label: &str) -> Option<u64> {
    line.strip_prefix(label)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Synthesize meminfo from the container cgroup at `cg` (`…/dn7/<id>`).
fn synth(cg: &Path) -> Option<String> {
    let host = HostMem::scan();
    if host.mem_total == 0 {
        return None; // no host baseline → let the caller fall back
    }

    // Total = the memory limit (kB), capped to host; "max"/unset → host total.
    let mut mem_total = read_max_bytes(&cg.join("memory.max"))
        .map(|b| b / 1024)
        .unwrap_or(host.mem_total);
    if mem_total == 0 || mem_total > host.mem_total {
        mem_total = host.mem_total;
    }

    let mut usage = read_u64(&cg.join("memory.current")).unwrap_or(0) / 1024;
    if usage > mem_total {
        usage = mem_total; // guard against a transient over-limit reading
    }

    // memory.stat keys (bytes).
    let stat = |k: &str| read_keyed(&cg.join("memory.stat"), k).unwrap_or(0);
    let cache = stat("file") / 1024;
    let shmem = stat("shmem") / 1024;
    let reclaimable =
        (stat("active_file") + stat("inactive_file") + stat("slab_reclaimable")) / 1024;
    let sreclaimable = stat("slab_reclaimable") / 1024;

    let mem_free = mem_total - usage;
    let mut mem_avail = mem_free + reclaimable;
    if mem_avail > mem_total {
        mem_avail = mem_free; // clamp (LXCFS §6)
    }

    // Swap: cgroup v2 `memory.swap.max` is swap-only; cap to the host's free swap.
    let mut swap_total = read_max_bytes(&cg.join("memory.swap.max"))
        .map(|b| b / 1024)
        .unwrap_or(host.swap_total);
    if swap_total > host.swap_total {
        swap_total = host.swap_total;
    }
    let swap_usage = read_u64(&cg.join("memory.swap.current")).unwrap_or(0) / 1024;
    let mut swap_free = swap_total.saturating_sub(swap_usage);
    if swap_free > host.swap_free {
        swap_free = host.swap_free;
    }

    Some(format_meminfo(&Fields {
        mem_total,
        mem_free,
        mem_avail,
        cached: cache,
        shmem,
        sreclaimable,
        swap_total,
        swap_free,
    }))
}

/// The subset of `/proc/meminfo` fields `free`/`top` (procps-ng) actually read;
/// the rest are emitted as 0 so those tools don't fall back to host values.
struct Fields {
    mem_total: u64,
    mem_free: u64,
    mem_avail: u64,
    cached: u64,
    shmem: u64,
    sreclaimable: u64,
    swap_total: u64,
    swap_free: u64,
}

/// Emit the kernel's `<label>   <value> kB` column layout. procps parses by
/// label→number, so the exact spacing isn't load-bearing, but we match the
/// kernel's right-aligned style. `free`'s used = MemTotal − MemAvailable, and
/// buff/cache = Buffers + Cached + SReclaimable.
fn format_meminfo(f: &Fields) -> String {
    let mut s = String::with_capacity(512);
    let mut row = |label: &str, kb: u64| {
        // "MemTotal:" left in a 16-wide field, value right-aligned in 8, then kB.
        s.push_str(&format!("{:<16}{:>8} kB\n", format!("{label}:"), kb));
    };
    row("MemTotal", f.mem_total);
    row("MemFree", f.mem_free);
    row("MemAvailable", f.mem_avail);
    row("Buffers", 0);
    row("Cached", f.cached);
    row("SwapCached", 0);
    row("Active", 0);
    row("Inactive", 0);
    row("Shmem", f.shmem);
    row("SReclaimable", f.sreclaimable);
    row("SUnreclaim", 0);
    row("Slab", f.sreclaimable);
    row("SwapTotal", f.swap_total);
    row("SwapFree", f.swap_free);
    s
}

// ---- CPU: /proc/cpuinfo, /proc/stat, /sys/.../cpu/online so top/lscpu/sysconf
//      see the cgroup CPU limit instead of the host's core count -------------

/// CPUs to present for the container: the cgroup v2 quota (`cpu.max`
/// quota/period, rounded up) and/or `cpuset.cpus.effective`, capped to the host
/// count, min 1. Unlimited → host count. Mirrors LXCFS.
fn cpu_count(cg: &Path, host_cpus: usize) -> usize {
    let mut n = host_cpus.max(1);
    if let Ok(s) = std::fs::read_to_string(cg.join("cpu.max")) {
        let mut it = s.split_whitespace();
        if let (Some(q), Some(p)) = (it.next(), it.next()) {
            if q != "max" {
                if let (Ok(q), Ok(p)) = (q.parse::<u64>(), p.parse::<u64>()) {
                    if p > 0 {
                        n = n.min(q.div_ceil(p).max(1) as usize);
                    }
                }
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string(cg.join("cpuset.cpus.effective")) {
        let c = count_cpu_list(s.trim());
        if c > 0 {
            n = n.min(c);
        }
    }
    n.max(1)
}

/// Count CPUs in a cpuset list like "0-3,7" → 5.
fn count_cpu_list(s: &str) -> usize {
    let mut total = 0;
    for part in s.split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
                    total += b.saturating_sub(a) + 1;
                }
            }
            None => total += usize::from(part.parse::<usize>().is_ok()),
        }
    }
    total
}

/// A `/proc/stat` line for a specific CPU (`cpu0`, `cpu12`), not the aggregate.
fn is_percpu(l: &str) -> bool {
    l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit)
}

/// Host online-CPU count from `/proc/stat` `cpuN` lines.
fn host_cpu_count() -> usize {
    std::fs::read_to_string("/proc/stat")
        .map(|s| s.lines().filter(|l| is_percpu(l)).count())
        .unwrap_or(1)
        .max(1)
}

/// `/proc/cpuinfo` trimmed to the first N `processor` blocks (blocks 0..N-1).
pub fn cpuinfo_for_pid(pid: u32) -> String {
    let host = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    match resolve::container_cgroup_of(pid) {
        Some(cg) => {
            let blocks: Vec<&str> = host
                .split("\n\n")
                .filter(|b| !b.trim().is_empty())
                .collect();
            let n = cpu_count(&cg, blocks.len().max(1)).min(blocks.len().max(1));
            let mut out = blocks.into_iter().take(n).collect::<Vec<_>>().join("\n\n");
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out
        }
        None => host,
    }
}

/// `/proc/stat` with the `cpuN` lines trimmed to N (aggregate recomputed as
/// their sum); all non-cpu lines (intr/ctxt/btime/procs_*/softirq) pass through.
pub fn stat_for_pid(pid: u32) -> String {
    let host = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    match resolve::container_cgroup_of(pid) {
        Some(cg) => {
            let host_n = host.lines().filter(|l| is_percpu(l)).count().max(1);
            filter_stat(&host, cpu_count(&cg, host_n))
        }
        None => host,
    }
}

fn filter_stat(host: &str, n: usize) -> String {
    let mut agg = [0u64; 10];
    let mut kept: Vec<&str> = Vec::new();
    for l in host.lines().filter(|l| is_percpu(l)) {
        let idx: usize = l[3..]
            .split_whitespace()
            .next()
            .and_then(|x| x.parse().ok())
            .unwrap_or(usize::MAX);
        if idx < n {
            for (i, f) in l.split_whitespace().skip(1).take(10).enumerate() {
                agg[i] += f.parse::<u64>().unwrap_or(0);
            }
            kept.push(l);
        }
    }
    let mut out = String::with_capacity(host.len());
    out.push_str("cpu ");
    out.push_str(&agg.map(|v| v.to_string()).join(" "));
    out.push('\n');
    for l in &kept {
        out.push_str(l);
        out.push('\n');
    }
    for l in host.lines().filter(|l| !l.starts_with("cpu")) {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// `/sys/devices/system/cpu/{online,possible,present}` = `0-(N-1)` (or `0`) for
/// the container (helps `lscpu`/`nproc --all`/sysconf); host value for non-
/// container callers. `host_file` is the real file to fall back to.
fn cpu_range(pid: u32, host_file: &str) -> String {
    match resolve::container_cgroup_of(pid) {
        Some(cg) => match cpu_count(&cg, host_cpu_count()) {
            0 | 1 => "0\n".into(),
            n => format!("0-{}\n", n - 1),
        },
        None => std::fs::read_to_string(host_file).unwrap_or_else(|_| "0\n".into()),
    }
}

pub fn online_for_pid(pid: u32) -> String {
    cpu_range(pid, "/sys/devices/system/cpu/online")
}
pub fn possible_for_pid(pid: u32) -> String {
    cpu_range(pid, "/sys/devices/system/cpu/possible")
}
pub fn present_for_pid(pid: u32) -> String {
    cpu_range(pid, "/sys/devices/system/cpu/present")
}

// ---- small cgroup readers (mirrors sys/cgroup.rs; kept local to avoid widening
//      that module's public surface) ----------------------------------------

/// Read a single-`u64` interface file (e.g. `memory.current`).
fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Read a `<u64>`-or-`max` interface file (e.g. `memory.max`). `max` → `None`.
fn read_max_bytes(path: &Path) -> Option<u64> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    if s == "max" {
        None
    } else {
        s.parse().ok()
    }
}

/// Read `key`'s value from a `key value`-per-line file (e.g. `memory.stat`).
fn read_keyed(path: &Path, key: &str) -> Option<u64> {
    let txt = std::fs::read_to_string(path).ok()?;
    for line in txt.lines() {
        let mut it = line.split_ascii_whitespace();
        if it.next() == Some(key) {
            return it.next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_parseable_and_capped() {
        let out = format_meminfo(&Fields {
            mem_total: 65536,
            mem_free: 55000,
            mem_avail: 60000,
            cached: 4096,
            shmem: 128,
            sreclaimable: 512,
            swap_total: 0,
            swap_free: 0,
        });
        // procps parses "<label>: <num> kB"; check the key lines are present.
        assert!(out.contains("MemTotal:"));
        assert!(kb_line(out.lines().next().unwrap(), "MemTotal:") == Some(65536));
        let avail = out
            .lines()
            .find_map(|l| kb_line(l, "MemAvailable:"))
            .unwrap();
        assert_eq!(avail, 60000);
        // MemAvailable must never exceed MemTotal.
        assert!(avail <= 65536);
    }

    #[test]
    fn kb_line_parses_padded() {
        assert_eq!(
            kb_line("MemTotal:       65536 kB", "MemTotal:"),
            Some(65536)
        );
        assert_eq!(kb_line("MemFree:            0 kB", "MemFree:"), Some(0));
        assert_eq!(kb_line("SwapTotal: 12 kB", "MemTotal:"), None);
    }
}
