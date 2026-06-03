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
    /// Storage category for grouping in the UI: "ssd" | "hdd" | "other".
    /// Derived from the backing block device's rotational flag.
    #[serde(default)]
    pub kind: String,
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
    /// Logical CPU core count (threads).
    pub cpu_cores: i64,
    /// Physical CPU core count (0/unknown falls back to logical on display).
    pub cpu_physical_cores: i64,
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
    /// status instead of the agent appearing to hang during a slow download.
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
    /// Memory hardware description (dmidecode, best-effort), resolved once.
    mem_model: String,
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
            is_container: detect_container(),
            cpu_model,
            cpu_physical_cores,
            mem_model,
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
            cpu_physical_cores: self.cpu_physical_cores,
            cpu_model: self.cpu_model.clone(),
            mem_model: self.mem_model.clone(),
            mem_total: total_mem,
            mem_used: used_mem,
            disk_total,
            disk_used,
            disk_mounts,
            update_phase: crate::update::phase_str().to_string(),
            update_progress: crate::update::progress(),
            update_done_bytes: crate::update::done_bytes(),
            update_total_bytes: crate::update::total_bytes(),
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
        // Only count real physical disks: skip pseudo / virtual filesystems
        // (tmpfs, overlay, squashfs, proc, ...) which otherwise show up as
        // spurious or zero-sized entries (and a blank row in the UI).
        let fs = disk.file_system().to_string_lossy().to_ascii_lowercase();
        if !is_physical_fs(&fs) {
            continue;
        }
        let mount = disk.mount_point().to_string_lossy().to_string();
        if is_virtual_mount(&mount) {
            continue;
        }
        let key = disk.name().to_string_lossy().to_string();
        if !key.is_empty() && !seen.insert(key) {
            continue; // already counted this device
        }
        let dt = disk.total_space();
        if dt == 0 {
            continue; // skip pseudo/zero-sized filesystems
        }
        // Sanity guard: reject absurd capacities (e.g. an FTP/network mount that
        // reports a bogus multi-petabyte total) so one bad row can't blow up the
        // aggregate percentage. 1 PiB is far above any realistic single mount.
        const MAX_SANE_BYTES: u64 = 1 << 50; // 1 PiB
        if dt > MAX_SANE_BYTES {
            continue;
        }
        let avail = disk.available_space();
        let du = dt.saturating_sub(avail);
        total += dt;
        used += du;
        mounts.push(DiskMount {
            mount,
            total: dt,
            used: du,
            kind: disk_kind(&disk.name().to_string_lossy()),
        });
    }
    // Largest filesystems first so the UI shows the most relevant mounts on top.
    mounts.sort_by(|a, b| b.total.cmp(&a.total));
    (total, used, mounts)
}

/// True for real, local, persistent disk filesystems we want to count.
///
/// Uses an **allowlist** of known physical/local filesystem types rather than a
/// denylist: network and FUSE mounts (NFS, CIFS/SMB, sshfs, curlftpfs/FTP, …)
/// must NOT be counted — they aren't local storage and often report bogus
/// capacities (e.g. an FTP mount showing "0 / 1024 TB" which wrecks the
/// percentage). Anything not explicitly recognized as a local disk FS is
/// excluded.
fn is_physical_fs(fs: &str) -> bool {
    const PHYSICAL: &[&str] = &[
        // Linux native.
        "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "reiser4", "nilfs2",
        "bcachefs", "zfs", "ufs",
        // Windows / removable, mounted as real block devices.
        "ntfs", "ntfs3", "fuseblk", // fuseblk = ntfs-3g on a real disk
        "vfat", "exfat", "msdos", "fat", "fat32", "udf",
        // macOS-style (rare on servers, but local disks).
        "hfs", "hfsplus", "apfs",
    ];
    if fs.is_empty() {
        return false;
    }
    // Defensively reject any FUSE userspace filesystem except ntfs-3g's
    // `fuseblk` (handled in the allowlist): sshfs, curlftpfs, rclone, gvfs, etc.
    if fs.starts_with("fuse.") || fs == "fuse" {
        return false;
    }
    PHYSICAL.contains(&fs)
}

/// Classify a block device as "ssd" | "hdd" | "other" by reading the kernel's
/// rotational flag for the backing device. `dev_name` is sysinfo's device name
/// (e.g. "/dev/sda1", "/dev/nvme0n1p2"). NVMe is always SSD. Non-Linux or an
/// unreadable flag yields "other".
fn disk_kind(dev_name: &str) -> String {
    let base = match block_base_name(dev_name) {
        Some(b) => b,
        None => return "other".to_string(),
    };
    // NVMe is solid-state by definition.
    if base.starts_with("nvme") {
        return "ssd".to_string();
    }
    let path = format!("/sys/block/{base}/queue/rotational");
    match std::fs::read_to_string(&path) {
        Ok(s) => match s.trim() {
            "0" => "ssd".to_string(),
            "1" => "hdd".to_string(),
            _ => "other".to_string(),
        },
        Err(_) => "other".to_string(),
    }
}

/// Reduce a device path to its parent block-device name under `/sys/block`:
/// "/dev/sda1" -> "sda", "/dev/nvme0n1p2" -> "nvme0n1", "/dev/vdb" -> "vdb".
fn block_base_name(dev_name: &str) -> Option<String> {
    let name = dev_name.rsplit('/').next().unwrap_or(dev_name);
    if name.is_empty() {
        return None;
    }
    // NVMe: strip a trailing "pN" partition suffix (nvme0n1p2 -> nvme0n1).
    if name.starts_with("nvme") {
        if let Some(idx) = name.rfind('p') {
            // Only strip if what's after 'p' is all digits (partition number).
            if name[idx + 1..].chars().all(|c| c.is_ascii_digit()) && idx > 0 {
                return Some(name[..idx].to_string());
            }
        }
        return Some(name.to_string());
    }
    // sd*/vd*/xvd*/hd*: strip trailing partition digits (sda1 -> sda).
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.is_empty() {
        Some(name.to_string())
    } else {
        Some(trimmed.to_string())
    }
}

/// True for mount points that are virtual/system paths rather than real,
/// user-relevant storage. Excludes kernel/pseudo paths, boot/firmware
/// partitions, and container/runtime internal mounts that just add noise.
fn is_virtual_mount(mount: &str) -> bool {
    // Kernel / pseudo filesystems.
    if mount.starts_with("/proc")
        || mount.starts_with("/sys")
        || mount.starts_with("/dev")
        || mount.starts_with("/run")
    {
        return true;
    }
    // Snap loop mounts.
    if mount == "/snap" || mount.starts_with("/snap/") {
        return true;
    }
    // Boot / EFI / firmware partitions (tiny, not user storage; were the source
    // of the odd "/boot/efi" SSD tag).
    if mount == "/boot" || mount.starts_with("/boot/") || mount.starts_with("/efi") {
        return true;
    }
    // Container/runtime internal mounts (docker/k8s/containerd overlays, etc.).
    if mount.starts_with("/var/lib/docker")
        || mount.starts_with("/var/lib/kubelet")
        || mount.starts_with("/var/lib/containers")
        || mount.starts_with("/var/lib/containerd")
        || mount.starts_with("/var/snap")
    {
        return true;
    }
    false
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

/// Best-effort memory hardware description via `dmidecode -t memory`. Reads the
/// first populated DIMM's manufacturer + type + speed (e.g. "Samsung DDR5
/// 4800 MT/s"). Requires root + dmidecode; returns "" when unavailable (most
/// containers/cloud VMs), which the UI treats as "unknown" and simply omits.
fn detect_mem_model() -> String {
    // Only meaningful on Linux with dmidecode present; cheap to attempt.
    let out = match std::process::Command::new("dmidecode")
        .args(["-t", "memory"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return String::new(),
    };
    let text = String::from_utf8_lossy(&out);
    // dmidecode prints one block per "Memory Device". Pick the first populated
    // one (Size not "No Module Installed").
    let mut manufacturer = String::new();
    let mut ram_type = String::new();
    let mut speed = String::new();
    let mut installed = false;
    let mut in_device = false;
    for line in text.lines() {
        let l = line.trim();
        if l == "Memory Device" {
            // Starting a new device block: if the previous one was populated and
            // had enough info, stop here.
            if installed && (!ram_type.is_empty() || !manufacturer.is_empty()) {
                break;
            }
            in_device = true;
            installed = false;
            manufacturer.clear();
            ram_type.clear();
            speed.clear();
            continue;
        }
        if !in_device {
            continue;
        }
        if let Some(v) = l.strip_prefix("Size:") {
            let v = v.trim();
            installed = !v.is_empty() && v != "No Module Installed" && v != "0";
        } else if let Some(v) = l.strip_prefix("Type:") {
            let v = v.trim();
            if v != "Unknown" && v != "Other" {
                ram_type = v.to_string();
            }
        } else if let Some(v) = l.strip_prefix("Manufacturer:") {
            let v = v.trim();
            if !v.is_empty() && v != "Unknown" && !v.starts_with("Not ") {
                manufacturer = v.to_string();
            }
        } else if let Some(v) = l.strip_prefix("Configured Memory Speed:") {
            let v = v.trim();
            if v != "Unknown" && !v.is_empty() {
                speed = v.to_string();
            }
        } else if let Some(v) = l.strip_prefix("Speed:") {
            // Fallback to rated Speed when Configured isn't reported.
            let v = v.trim();
            if speed.is_empty() && v != "Unknown" && !v.is_empty() {
                speed = v.to_string();
            }
        }
    }
    let parts: Vec<&str> = [manufacturer.as_str(), ram_type.as_str(), speed.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    parts.join(" ")
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
    if std::env::var("container")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        let c = cgroup.to_ascii_lowercase();
        if c.contains("docker")
            || c.contains("kubepods")
            || c.contains("containerd")
            || c.contains("/lxc/")
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{is_physical_fs, is_virtual_mount};

    #[test]
    fn physical_fs_filter() {
        // Local disk filesystems are counted.
        assert!(is_physical_fs("ext4"));
        assert!(is_physical_fs("xfs"));
        assert!(is_physical_fs("btrfs"));
        assert!(is_physical_fs("ntfs"));
        assert!(is_physical_fs("vfat"));
        assert!(is_physical_fs("fuseblk")); // ntfs-3g on a real disk
                                            // Pseudo / in-memory / image filesystems are excluded.
        assert!(!is_physical_fs("tmpfs"));
        assert!(!is_physical_fs("overlay"));
        assert!(!is_physical_fs("squashfs"));
        assert!(!is_physical_fs(""));
        // Network / FUSE mounts (the FTP/sshfs/NFS bug) are excluded.
        assert!(!is_physical_fs("nfs"));
        assert!(!is_physical_fs("nfs4"));
        assert!(!is_physical_fs("cifs"));
        assert!(!is_physical_fs("smbfs"));
        assert!(!is_physical_fs("fuse.sshfs"));
        assert!(!is_physical_fs("fuse.curlftpfs"));
        assert!(!is_physical_fs("fuse.rclone"));
        assert!(!is_physical_fs("fuse"));
    }

    #[test]
    fn virtual_mount_filter() {
        assert!(is_virtual_mount("/proc"));
        assert!(is_virtual_mount("/sys/fs/cgroup"));
        assert!(is_virtual_mount("/run/lock"));
        assert!(is_virtual_mount("/snap/core/1234"));
        // Boot / EFI / firmware partitions are excluded (the /boot/efi tag bug).
        assert!(is_virtual_mount("/boot"));
        assert!(is_virtual_mount("/boot/efi"));
        assert!(is_virtual_mount("/efi"));
        // Container/runtime internal mounts are excluded.
        assert!(is_virtual_mount("/var/lib/docker/overlay2/abc"));
        assert!(is_virtual_mount("/var/lib/kubelet/pods/x"));
        // Real user storage is kept.
        assert!(!is_virtual_mount("/"));
        assert!(!is_virtual_mount("/data"));
        assert!(!is_virtual_mount("/home"));
    }
}
