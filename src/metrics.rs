use serde::Serialize;
use sysinfo::{Disks, System};

/// A single metrics snapshot collected from the local machine.
#[derive(Debug, Clone, Serialize)]
pub struct Metrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub uptime: i64,
    pub hostname: String,
    pub os_version: String,
    pub ip: String,
}

/// Collector that maintains a System handle across refreshes so CPU usage is
/// computed correctly (CPU usage needs two samples).
pub struct Collector {
    sys: System,
}

impl Collector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Collector { sys }
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

        let total_mem = self.sys.total_memory();
        let used_mem = self.sys.used_memory();
        let memory_usage = if total_mem == 0 {
            0.0
        } else {
            (used_mem as f64 / total_mem as f64) * 100.0
        };

        let disk_usage = compute_disk_usage();

        let uptime = System::uptime() as i64;
        let hostname = System::host_name().unwrap_or_default();
        let os_version = os_label();
        let ip = local_ip().unwrap_or_default();

        Metrics {
            cpu_usage: clamp_pct(cpu_usage),
            memory_usage: clamp_pct(memory_usage),
            disk_usage: clamp_pct(disk_usage),
            uptime,
            hostname,
            os_version,
            ip,
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

/// Aggregate disk usage across all mounted disks (used / total).
fn compute_disk_usage() -> f64 {
    let disks = Disks::new_with_refreshed_list();
    let mut total: u64 = 0;
    let mut available: u64 = 0;
    for disk in disks.list() {
        total += disk.total_space();
        available += disk.available_space();
    }
    if total == 0 {
        return 0.0;
    }
    let used = total.saturating_sub(available);
    (used as f64 / total as f64) * 100.0
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
