use std::time::Instant;

use serde::Serialize;
use sysinfo::{Disks, Networks, System};

/// One mounted filesystem's capacity (bytes), reported for the disk breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct DiskMount {
    /// Mount point, e.g. "/" or "/data".
    pub mount: String,
    pub total: u64,
    pub used: u64,
}

/// A single metrics snapshot collected from the local machine.
#[derive(Debug, Clone, Serialize)]
pub struct Metrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    /// Network throughput since the previous sample, in bytes/sec.
    pub net_rx: f64,
    pub net_tx: f64,
    pub uptime: i64,
    pub hostname: String,
    pub os_version: String,
    pub ip: String,
    /// Whether this agent is running inside a Docker/container environment.
    pub is_container: bool,
    /// Logical CPU core count.
    pub cpu_cores: i64,
    /// Total / used physical memory, in bytes.
    pub mem_total: u64,
    pub mem_used: u64,
    /// Aggregate total / used disk space across mounts, in bytes.
    pub disk_total: u64,
    pub disk_used: u64,
    /// Per-mount disk breakdown (deduped by device).
    pub disk_mounts: Vec<DiskMount>,
    /// Self-update phase ("idle"|"checking"|"downloading"|"installing"|"error")
    /// and download progress percent (0..100), so the UI can show live update
    /// status instead of the agent appearing to hang during a slow download.
    pub update_phase: String,
    pub update_progress: u64,
}

/// Collector that maintains a System handle across refreshes so CPU usage is
/// computed correctly (CPU usage needs two samples).
pub struct Collector {
    sys: System,
    networks: Networks,
    /// Reused across ticks; refreshed in place rather than re-enumerated each
    /// time (enumerating disks every second is needlessly expensive).
    disks: Disks,
    /// Timestamp of the previous collect, to convert byte deltas to per-second.
    last_sample: Option<Instant>,
    /// Cached identity fields that don't change at runtime, resolved once.
    hostname: String,
    os_version: String,
    /// Cached local IP, refreshed only periodically (it rarely changes, and
    /// opening a UDP socket every tick is wasteful).
    ip: String,
    ip_checked_at: Option<Instant>,
    /// Whether we're inside a container — detected once at startup.
    is_container: bool,
}

impl Collector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let networks = Networks::new_with_refreshed_list();
        let disks = Disks::new_with_refreshed_list();
        Collector {
            sys,
            networks,
            disks,
            last_sample: None,
            hostname: System::host_name().unwrap_or_default(),
            os_version: os_label(),
            ip: local_ip().unwrap_or_default(),
            ip_checked_at: Some(Instant::now()),
            is_container: detect_container(),
        }
    }

    /// Refresh and produce a metrics snapshot.
    pub fn collect(&mut self) -> Metrics {
        // CPU needs to be refreshed; usage is relative to the previous refresh.
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();

        let cpu_usage = {
            let cpus = self.sys.cpus();
            if cpus.is_empty() {
                0.0
            } else {
                let total: f32 = cpus.iter().map(|c| c.cpu_usage()).sum();
                (total / cpus.len() as f32) as f64
            }
        };
        let cpu_cores = self.sys.cpus().len() as i64;

        let total_mem = self.sys.total_memory();
        let used_mem = self.sys.used_memory();
        let memory_usage = if total_mem == 0 {
            0.0
        } else {
            (used_mem as f64 / total_mem as f64) * 100.0
        };

        // Refresh disks in place (cheap) and aggregate used/total + per-mount.
        self.disks.refresh();
        let (disk_total, disk_used, disk_mounts) = aggregate_disks(&self.disks);
        let disk_usage = if disk_total == 0 {
            0.0
        } else {
            (disk_used as f64 / disk_total as f64) * 100.0
        };

        // Network throughput: sum per-interface received/transmitted bytes since
        // the last refresh, divided by the elapsed wall-clock seconds.
        self.networks.refresh();
        let mut rx_bytes: u64 = 0;
        let mut tx_bytes: u64 = 0;
        for (_iface, data) in self.networks.iter() {
            rx_bytes += data.received();
            tx_bytes += data.transmitted();
        }
        let now = Instant::now();
        let elapsed = self
            .last_sample
            .map(|t| now.duration_since(t).as_secs_f64())
            .filter(|s| *s > 0.0)
            .unwrap_or(0.0);
        self.last_sample = Some(now);
        let (net_rx, net_tx) = if elapsed > 0.0 {
            (rx_bytes as f64 / elapsed, tx_bytes as f64 / elapsed)
        } else {
            // First sample has no baseline; report 0 to avoid a huge spike.
            (0.0, 0.0)
        };

        let uptime = System::uptime() as i64;

        // Re-resolve the local IP at most once a minute (it almost never moves).
        let refresh_ip = self
            .ip_checked_at
            .map(|t| now.duration_since(t).as_secs() >= 60)
            .unwrap_or(true);
        if refresh_ip {
            if let Some(ip) = local_ip() {
                self.ip = ip;
            }
            self.ip_checked_at = Some(now);
        }

        Metrics {
            cpu_usage: clamp_pct(cpu_usage),
            memory_usage: clamp_pct(memory_usage),
            disk_usage: clamp_pct(disk_usage),
            net_rx: net_rx.max(0.0),
            net_tx: net_tx.max(0.0),
            uptime,
            hostname: self.hostname.clone(),
            os_version: self.os_version.clone(),
            ip: self.ip.clone(),
            is_container: self.is_container,
            cpu_cores,
            mem_total: total_mem,
            mem_used: used_mem,
            disk_total,
            disk_used,
            disk_mounts,
            update_phase: crate::update::phase_str().to_string(),
            update_progress: crate::update::progress(),
        }
    }
}

fn clamp_pct(v: f64) -> f64 {
    if v.is_nan() {
        0.0
    } else {
        (v.clamp(0.0, 100.0) * 100.0).round() / 100.0
    }
}

/// Aggregate disk usage across mounted disks, de-duplicating by underlying
/// device so the same physical disk mounted twice (bind mounts, etc.) isn't
/// double-counted. Returns (total_bytes, used_bytes, per-mount breakdown).
fn aggregate_disks(disks: &Disks) -> (u64, u64, Vec<DiskMount>) {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut total: u64 = 0;
    let mut used: u64 = 0;
    let mut mounts: Vec<DiskMount> = Vec::new();
    for disk in disks.list() {
        let key = disk.name().to_string_lossy().to_string();
        if !key.is_empty() && !seen.insert(key) {
            continue; // already counted this device
        }
        let dt = disk.total_space();
        if dt == 0 {
            continue; // skip pseudo/zero-sized filesystems
        }
        let avail = disk.available_space();
        let du = dt.saturating_sub(avail);
        total += dt;
        used += du;
        mounts.push(DiskMount {
            mount: disk.mount_point().to_string_lossy().to_string(),
            total: dt,
            used: du,
        });
    }
    // Largest filesystems first so the UI shows the most relevant mounts on top.
    mounts.sort_by(|a, b| b.total.cmp(&a.total));
    (total, used, mounts)
}

fn os_label() -> String {
    let name = System::name().unwrap_or_else(|| "Unknown".to_string());
    let version = System::os_version().unwrap_or_default();
    if version.is_empty() {
        name
    } else {
        format!("{name} {version}")
    }
}

/// Best-effort local IP discovery by opening a UDP socket to a public address.
/// No packets are actually sent; this just resolves the chosen source address.
fn local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

/// Detect whether we're running inside a Docker/container environment. Uses the
/// common signals: the `/.dockerenv` marker file, a `container` env var, or
/// container/docker/kubepods references in `/proc/1/cgroup`. Best-effort and
/// Linux-focused; returns false on non-Linux or when nothing matches.
fn detect_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }
    if std::env::var("container").map(|v| !v.is_empty()).unwrap_or(false) {
        return true;
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        let c = cgroup.to_ascii_lowercase();
        if c.contains("docker") || c.contains("kubepods") || c.contains("containerd") || c.contains("/lxc/") {
            return true;
        }
    }
    false
}
