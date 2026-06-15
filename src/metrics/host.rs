//! Host facts: OS/mem/cpu detection, local IP, container detection (split from metrics.rs).
use super::*;

pub(crate) fn os_label() -> String {
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
pub(crate) fn detect_mem_model() -> String {
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
pub(crate) fn local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

/// Detect whether we're running inside a Docker/container environment. Uses the
/// common signals: the `/.dockerenv` marker file, a `container` env var, or
/// container/docker/kubepods references in `/proc/1/cgroup`. Best-effort and
/// Linux-focused; returns false on non-Linux or when nothing matches.
pub(crate) fn detect_container() -> bool {
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

/// Detect whether the CPU is virtualized (vCPU) rather than dedicated physical
/// cores. True for cloud VMs / hypervisor guests and for containers (whose
/// "cores" are the host's, scheduled by the hypervisor/host). Best-effort,
/// Linux-focused; conservative — returns false when nothing indicates a VM.
///
/// Signals, in order:
///   1. containers are always vCPU;
///   2. `systemd-detect-virt -q` exits 0 when virtualized;
///   3. the `hypervisor` flag in `/proc/cpuinfo` (set by most hypervisors);
///   4. `/sys/hypervisor/type` (Xen) or DMI product/vendor naming a hypervisor.
pub(crate) fn detect_virtual_cpu(is_container: bool) -> bool {
    if is_container {
        return true;
    }
    // systemd-detect-virt is the most reliable when present.
    if let Ok(status) = std::process::Command::new("systemd-detect-virt")
        .arg("-q")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        // Exit 0 => some virtualization detected; non-zero => bare metal/none.
        if status.success() {
            return true;
        }
        // A definitive "none" answer — trust it.
        return false;
    }
    // Fallback: the hypervisor CPU flag (KVM/VMware/Hyper-V/Xen HVM all set it).
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("flags") && line.contains(" hypervisor") {
                return true;
            }
        }
    }
    // Xen paravirtual guests expose this.
    if std::path::Path::new("/sys/hypervisor/type").exists() {
        return true;
    }
    // DMI naming as a last resort (cloud/hypervisor product or vendor strings).
    let dmi = |p: &str| {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    let hay = format!(
        "{} {} {}",
        dmi("/sys/class/dmi/id/product_name"),
        dmi("/sys/class/dmi/id/sys_vendor"),
        dmi("/sys/class/dmi/id/board_vendor"),
    );
    const VM_HINTS: &[&str] = &[
        "kvm",
        "qemu",
        "vmware",
        "virtualbox",
        "vbox",
        "xen",
        "hyper-v",
        "microsoft corporation",
        "bochs",
        "openstack",
        "amazon ec2",
        "google compute",
        "alibaba cloud",
        "tencent cloud",
        "huawei cloud",
        "droplet", // DigitalOcean
    ];
    VM_HINTS.iter().any(|h| hay.contains(h))
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
