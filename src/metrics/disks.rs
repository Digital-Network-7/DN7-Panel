//! Disk usage aggregation + device facts (split from metrics.rs).
use super::*;

/// Aggregate disk usage across mounted disks, de-duplicating by underlying
/// device so the same physical disk mounted twice (bind mounts, etc.) isn't
/// double-counted. Returns (total_bytes, used_bytes, per-mount breakdown).
pub(crate) fn aggregate_disks(
    disks: &Disks,
    cache: &mut std::collections::HashMap<String, DiskStatic>,
) -> (u64, u64, Vec<DiskMount>) {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut total: u64 = 0;
    let mut used: u64 = 0;
    let mut mounts: Vec<DiskMount> = Vec::new();
    for disk in disks.list() {
        if !is_countable_disk(disk) {
            continue;
        }
        let key = disk.name().to_string_lossy().to_string();
        if !key.is_empty() && !seen.insert(key) {
            continue; // already counted this device
        }
        let dt = disk.total_space();
        let du = dt.saturating_sub(disk.available_space());
        total += dt;
        used += du;
        let dev_name = disk.name().to_string_lossy().to_string();
        let st = disk_static_facts(cache, &dev_name);
        mounts.push(DiskMount {
            mount: disk.mount_point().to_string_lossy().to_string(),
            total: dt,
            used: du,
            kind: st.kind.clone(),
            device: st.device.clone(),
            device_size: st.device_size,
        });
    }
    // Largest filesystems first so the UI shows the most relevant mounts on top.
    mounts.sort_by_key(|m| std::cmp::Reverse(m.total));
    (total, used, mounts)
}

/// Whether a disk represents a real, countable physical filesystem: skip
/// pseudo/virtual filesystems (tmpfs, overlay, squashfs, proc, ...), virtual
/// mount points, zero-sized entries, and absurd capacities (e.g. a network
/// mount reporting bogus multi-petabyte totals) that would skew the aggregate.
pub(crate) fn is_countable_disk(disk: &sysinfo::Disk) -> bool {
    const MAX_SANE_BYTES: u64 = 1 << 50; // 1 PiB — far above any real single mount
    let fs = disk.file_system().to_string_lossy().to_ascii_lowercase();
    if !is_physical_fs(&fs) {
        return false;
    }
    if is_virtual_mount(&disk.mount_point().to_string_lossy()) {
        return false;
    }
    let dt = disk.total_space();
    dt != 0 && dt <= MAX_SANE_BYTES
}

/// Static device facts (kind / device path / whole-disk size) for `dev_name`.
/// These come from `/sys/block/*` and never change at runtime, so they're read
/// once per device and cached — a 1s metrics tick won't keep hitting the FS.
pub(crate) fn disk_static_facts(
    cache: &mut std::collections::HashMap<String, DiskStatic>,
    dev_name: &str,
) -> DiskStatic {
    cache
        .entry(dev_name.to_string())
        .or_insert_with(|| {
            let base = block_base_name(dev_name);
            let device = base
                .as_ref()
                .map(|b| format!("/dev/{b}"))
                .unwrap_or_default();
            let device_size = base.as_deref().map(whole_disk_size).unwrap_or(0);
            DiskStatic {
                kind: disk_kind(dev_name),
                device,
                device_size,
            }
        })
        .clone()
}

/// True for real, local, persistent disk filesystems we want to count.
///
/// Uses an **allowlist** of known physical/local filesystem types rather than a
/// denylist: network and FUSE mounts (NFS, CIFS/SMB, sshfs, curlftpfs/FTP, …)
/// must NOT be counted — they aren't local storage and often report bogus
/// capacities (e.g. an FTP mount showing "0 / 1024 TB" which wrecks the
/// percentage). Anything not explicitly recognized as a local disk FS is
/// excluded.
pub(crate) fn is_physical_fs(fs: &str) -> bool {
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
pub(crate) fn disk_kind(dev_name: &str) -> String {
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

/// Whole-disk capacity in bytes for a block-device base name (e.g. "vda",
/// "nvme0n1"), read from `/sys/block/<base>/size` (count of 512-byte sectors).
/// 0 when unavailable (non-Linux, missing node, parse error).
pub(crate) fn whole_disk_size(base: &str) -> u64 {
    let path = format!("/sys/block/{base}/size");
    match std::fs::read_to_string(&path) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map(|sectors| sectors * 512)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Reduce a device path to its parent block-device name under `/sys/block`:
/// "/dev/sda1" -> "sda", "/dev/nvme0n1p2" -> "nvme0n1", "/dev/vdb" -> "vdb".
pub(crate) fn block_base_name(dev_name: &str) -> Option<String> {
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
pub(crate) fn is_virtual_mount(mount: &str) -> bool {
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
