//! Host metrics snapshot: the collected DTOs (DiskMount/Metrics) + the
//! Collector that maintains sampling state across ticks.
use super::*;

/// One mounted filesystem's capacity (bytes), reported for the disk breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct DiskMount {
    /// Mount point, e.g. "/" or "/data".
    pub mount: String,
    pub total: u64,
    pub used: u64,
    /// Storage category for grouping in the UI: "ssd" | "hdd" | "other".
    /// Derived from the backing block device's rotational flag.
    #[serde(default)]
    pub kind: String,
    /// Parent block device this mount lives on, e.g. "/dev/vda". Lets the UI
    /// group mounts under their physical disk. Empty if undeterminable.
    #[serde(default)]
    pub device: String,
    /// Whole-disk capacity of `device` in bytes (the physical disk size, not
    /// the partition/filesystem size). 0 if undeterminable.
    #[serde(default)]
    pub device_size: u64,
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
    /// Whether this panel is running inside a Docker/container environment.
    pub is_container: bool,
    /// Logical CPU core count (threads).
    pub cpu_cores: i64,
    /// Physical CPU core count (0/unknown falls back to logical on display).
    pub cpu_physical_cores: i64,
    /// Whether the CPU is virtualized (running under a hypervisor / cloud VM or
    /// in a container) — i.e. the cores are vCPUs, not dedicated physical cores.
    pub cpu_virtual: bool,
    /// CPU model/brand string (e.g. "Intel(R) Xeon(R) ... @ 2.50GHz"), resolved
    /// once at startup. Empty if unavailable.
    pub cpu_model: String,
    /// Best-effort memory hardware description (e.g. "Samsung DDR5 4800 MT/s"),
    /// from dmidecode when available (root). Empty otherwise.
    pub mem_model: String,
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
    /// status instead of the panel appearing to hang during a slow download.
    pub update_phase: String,
    pub update_progress: u64,
    /// Bytes downloaded so far / total bytes for the in-flight self-update, so
    /// the UI can show "current MB / total MB" (0 when not downloading).
    pub update_done_bytes: u64,
    pub update_total_bytes: u64,
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
    /// CPU model/brand, resolved once at startup.
    cpu_model: String,
    /// Physical core count, resolved once at startup (0 = unknown).
    cpu_physical_cores: i64,
    /// Whether the CPU is virtualized (vCPU), detected once at startup.
    cpu_virtual: bool,
    /// Memory hardware description (dmidecode, best-effort), resolved once.
    mem_model: String,
    /// Cache of per-device static disk facts (kind / device path / whole-disk
    /// size) keyed by sysinfo's device name. These come from `/sys/block/*`
    /// which never changes at runtime, so we read them once per device instead
    /// of on every 1s tick.
    disk_static: std::collections::HashMap<String, DiskStatic>,
}

/// Static (runtime-invariant) facts about a backing block device, cached so the
/// per-tick disk aggregation doesn't re-read `/sys/block/*` every second.
#[derive(Clone)]
pub(crate) struct DiskStatic {
    pub(crate) kind: String,
    pub(crate) device: String,
    pub(crate) device_size: u64,
}

impl Collector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let networks = Networks::new_with_refreshed_list();
        let disks = Disks::new_with_refreshed_list();
        let cpu_model = sys
            .cpus()
            .first()
            .map(|c| c.brand().trim().to_string())
            .unwrap_or_default();
        let cpu_physical_cores = sys.physical_core_count().unwrap_or(0) as i64;
        let is_container = detect_container();
        let cpu_virtual = detect_virtual_cpu(is_container);
        let mem_model = detect_mem_model();
        Collector {
            sys,
            networks,
            disks,
            last_sample: None,
            hostname: System::host_name().unwrap_or_default(),
            os_version: os_label(),
            ip: local_ip().unwrap_or_default(),
            ip_checked_at: Some(Instant::now()),
            is_container,
            cpu_model,
            cpu_physical_cores,
            cpu_virtual,
            mem_model,
            disk_static: std::collections::HashMap::new(),
        }
    }

    /// Refresh and produce a metrics snapshot.
    pub fn collect(&mut self) -> Metrics {
        // CPU needs to be refreshed; usage is relative to the previous refresh.
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();

        let cpu_usage = self.cpu_usage_pct();
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
        let (disk_total, disk_used, disk_mounts) =
            aggregate_disks(&self.disks, &mut self.disk_static);
        let disk_usage = if disk_total == 0 {
            0.0
        } else {
            (disk_used as f64 / disk_total as f64) * 100.0
        };

        let now = Instant::now();
        let (net_rx, net_tx) = self.net_throughput(now);
        let uptime = System::uptime() as i64;
        self.refresh_ip_if_stale(now);

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
            cpu_physical_cores: self.cpu_physical_cores,
            cpu_virtual: self.cpu_virtual,
            cpu_model: self.cpu_model.clone(),
            mem_model: self.mem_model.clone(),
            mem_total: total_mem,
            mem_used: used_mem,
            disk_total,
            disk_used,
            disk_mounts,
            update_phase: crate::platform::update::phase_str().to_string(),
            update_progress: crate::platform::update::progress(),
            update_done_bytes: crate::platform::update::done_bytes(),
            update_total_bytes: crate::platform::update::total_bytes(),
        }
    }

    /// Average CPU usage percent across all logical CPUs (since last refresh).
    fn cpu_usage_pct(&self) -> f64 {
        let cpus = self.sys.cpus();
        if cpus.is_empty() {
            return 0.0;
        }
        let total: f32 = cpus.iter().map(|c| c.cpu_usage()).sum();
        (total / cpus.len() as f32) as f64
    }

    /// Network throughput (rx, tx) in bytes/sec: sum per-interface bytes since
    /// the last refresh, divided by the elapsed wall-clock seconds. Updates the
    /// sampling baseline. The first sample has no baseline, so it reports 0 to
    /// avoid a huge spike.
    fn net_throughput(&mut self, now: Instant) -> (f64, f64) {
        self.networks.refresh();
        let mut rx_bytes: u64 = 0;
        let mut tx_bytes: u64 = 0;
        for (_iface, data) in self.networks.iter() {
            rx_bytes += data.received();
            tx_bytes += data.transmitted();
        }
        let elapsed = self
            .last_sample
            .map(|t| now.duration_since(t).as_secs_f64())
            .filter(|s| *s > 0.0)
            .unwrap_or(0.0);
        self.last_sample = Some(now);
        if elapsed > 0.0 {
            (rx_bytes as f64 / elapsed, tx_bytes as f64 / elapsed)
        } else {
            (0.0, 0.0)
        }
    }

    /// Re-resolve the local IP at most once a minute (it almost never moves).
    fn refresh_ip_if_stale(&mut self, now: Instant) {
        let stale = self
            .ip_checked_at
            .map(|t| now.duration_since(t).as_secs() >= 60)
            .unwrap_or(true);
        if stale {
            if let Some(ip) = local_ip() {
                self.ip = ip;
            }
            self.ip_checked_at = Some(now);
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
