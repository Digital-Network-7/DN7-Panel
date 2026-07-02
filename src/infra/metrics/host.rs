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

/// Best-effort memory hardware description (e.g. "Samsung DDR5 4800 MT/s") by
/// parsing the SMBIOS DMI tables directly from `/sys/firmware/dmi/tables/DMI` —
/// PURE RUST, no `dmidecode` shell-out. Returns "" when the tables are absent or
/// unreadable (most containers/cloud VMs; needs root), which the UI omits.
pub(crate) fn detect_mem_model() -> String {
    std::fs::read("/sys/firmware/dmi/tables/DMI")
        .map(|d| parse_smbios_mem(&d))
        .unwrap_or_default()
}

/// Parse raw SMBIOS table bytes for the first populated DIMM's description
/// (manufacturer + DDR type + speed). Factored out so it's unit-testable without
/// the root-only `/sys/firmware/dmi/tables/DMI`.
fn parse_smbios_mem(data: &[u8]) -> String {
    // Walk SMBIOS structures: header [type:u8, length:u8, handle:u16], a formatted
    // area of `length` bytes, then a double-NUL-terminated set of strings (string
    // refs in the formatted area are 1-based indices into that set).
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let typ = data[i];
        let len = data[i + 1] as usize;
        if len < 4 || i + len > data.len() {
            break;
        }
        let formatted = &data[i..i + len];
        // The string set runs from the end of the formatted area to the first
        // double-NUL (`\0\0`); each string is NUL-separated within it.
        let sset_start = i + len;
        let mut j = sset_start;
        while j + 1 < data.len() && !(data[j] == 0 && data[j + 1] == 0) {
            j += 1;
        }
        let strings: Vec<&[u8]> = data[sset_start..j.min(data.len())]
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .collect();
        let str_at = |idx: usize| -> String {
            idx.checked_sub(1)
                .and_then(|k| strings.get(k))
                .map(|b| String::from_utf8_lossy(b).trim().to_string())
                .unwrap_or_default()
        };
        let word = |off: usize| -> u16 {
            if off + 1 < formatted.len() {
                u16::from_le_bytes([formatted[off], formatted[off + 1]])
            } else {
                0
            }
        };

        // Type 17 = Memory Device. Offsets per the SMBIOS spec.
        if typ == 17 && len > 0x17 {
            let size = word(0x0C);
            let installed = size != 0 && size != 0xFFFF;
            if installed {
                let manufacturer = str_at(formatted[0x17] as usize);
                let ram_type = mem_type_name(formatted.get(0x12).copied().unwrap_or(0));
                // Configured Memory Speed (0x20, SMBIOS 2.7+) preferred, else rated.
                let cfg = if len > 0x21 { word(0x20) } else { 0 };
                let rated = word(0x15);
                let mts = if cfg != 0 && cfg != 0xFFFF {
                    cfg
                } else {
                    rated
                };
                let speed = if mts != 0 && mts != 0xFFFF {
                    format!("{mts} MT/s")
                } else {
                    String::new()
                };
                let parts: Vec<String> = [manufacturer, ram_type, speed]
                    .into_iter()
                    .filter(|s| !s.is_empty() && s != "Unknown" && !s.starts_with("Not "))
                    .collect();
                if !parts.is_empty() {
                    return parts.join(" ");
                }
            }
        }
        if typ == 127 {
            break; // end-of-table marker
        }
        i = j + 2; // skip the terminating double-NUL to the next structure
    }
    String::new()
}

/// SMBIOS Memory Device "Type" byte → a human name (the common DDR variants);
/// "" for unknown/other.
fn mem_type_name(b: u8) -> String {
    match b {
        0x12 => "DDR",
        0x13 => "DDR2",
        0x14 => "DDR2 FB-DIMM",
        0x18 => "DDR3",
        0x1A => "DDR4",
        0x1B => "LPDDR",
        0x1C => "LPDDR2",
        0x1D => "LPDDR3",
        0x1E => "LPDDR4",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        _ => "",
    }
    .to_string()
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
/// Signals, in order (all pure-Rust — no `systemd-detect-virt` shell-out):
///   1. containers are always vCPU;
///   2. the `hypervisor` flag in `/proc/cpuinfo` (set by most hypervisors);
///   3. `/sys/hypervisor/type` (Xen) or DMI product/vendor naming a hypervisor.
pub(crate) fn detect_virtual_cpu(is_container: bool) -> bool {
    if is_container {
        return true;
    }
    // Pure-Rust detection only (no `systemd-detect-virt` shell-out).
    // The hypervisor CPU flag (KVM/VMware/Hyper-V/Xen HVM all set it).
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
    use super::{is_physical_fs, is_virtual_mount, parse_smbios_mem};

    #[test]
    fn smbios_parses_populated_dimm() {
        // A synthetic SMBIOS type-17 (Memory Device) structure: DDR4, 3200 MT/s,
        // manufacturer string #1 = "Samsung", followed by the end-of-table marker.
        let mut s = vec![0u8; 0x22]; // 34-byte formatted area
        s[0] = 17; // type = Memory Device
        s[1] = 0x22; // length
        s[2] = 0x01; // handle lo
        s[0x0C] = 0x00;
        s[0x0D] = 0x20; // Size = 0x2000 (populated, != 0 / 0xFFFF)
        s[0x12] = 0x1A; // Memory Type = DDR4
        s[0x15] = 0x80;
        s[0x16] = 0x0C; // Speed = 3200 (0x0C80)
        s[0x17] = 0x01; // Manufacturer = string #1
        s[0x20] = 0x80;
        s[0x21] = 0x0C; // Configured Speed = 3200
        let mut blob = s;
        blob.extend_from_slice(b"Samsung\0\0"); // string set (#1) + terminator
        blob.extend_from_slice(&[127, 4, 0, 0, 0, 0]); // type 127 end-of-table

        assert_eq!(parse_smbios_mem(&blob), "Samsung DDR4 3200 MT/s");
        // Empty / garbage input is safe and yields "".
        assert_eq!(parse_smbios_mem(&[]), "");
        assert_eq!(parse_smbios_mem(&[17, 2, 0]), "");
    }

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
