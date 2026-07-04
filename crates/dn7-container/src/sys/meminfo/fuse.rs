//! The pure-Rust `/dev/fuse` server: mount via `mount(2)` (no libfuse, no
//! `fusermount`), then a single-threaded read→handle→write loop. It exposes a
//! two-node tree — a root dir (nodeid 1) containing one file `meminfo`
//! (nodeid 2) — whose content is regenerated per READ from the *caller's*
//! cgroup. Every request path either writes exactly one reply or is one of the
//! three no-reply ops, so a reader can never hang; every parse is bounds-checked
//! and every cgroup read fails open, so the serve thread cannot panic (which
//! would leave the mount live but unanswered).

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use nix::mount::{mount, umount2, MntFlags, MsFlags};

use super::abi::*;
use super::generate;

const HDR: usize = std::mem::size_of::<FuseInHeader>();

/// Mount the FUSE fs at `dir` and start its serve thread. Returns `Err` on any
/// setup failure (no `/dev/fuse`, `mount(2)` denied, …) so the caller can fall
/// back to the host `/proc/meminfo`. On success the mount + thread persist for
/// the process's life.
pub fn spawn(dir: &Path) -> std::io::Result<()> {
    // Clear a stale/dead FUSE mount left by a killed predecessor FIRST: it
    // reports ENOTCONN on any access, which would make create_dir_all below fail
    // before we ever reached the cleanup. MNT_DETACH removes it from the tree.
    let _ = umount2(dir, MntFlags::MNT_DETACH);
    std::fs::create_dir_all(dir)?;

    let devpath = CString::new("/dev/fuse").expect("no NUL");
    // SAFETY: opening a fixed device path; we own the returned fd.
    let devfd = unsafe { libc::open(devpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if devfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `devfd` is a fresh fd we just opened and don't otherwise use.
    let owned = unsafe { OwnedFd::from_raw_fd(devfd) };

    // SAFETY: geteuid/getegid are always-succeeding syscalls.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // rootmode is the octal dir mode (S_IFDIR|0555). allow_other: container
    // processes run as arbitrary uids. default_permissions: let the kernel do
    // permission checks from the 0444 mode we report in GETATTR.
    let data = format!(
        "fd={devfd},rootmode=40555,user_id={uid},group_id={gid},allow_other,default_permissions"
    );
    mount(
        Some("dn7fuse"),
        dir,
        Some("fuse"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOATIME | MsFlags::MS_RDONLY,
        Some(data.as_str()),
    )
    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

    std::thread::Builder::new()
        .name("dn7-meminfo-fuse".into())
        .spawn(move || serve_loop(owned))?;
    Ok(())
}

/// The blocking request loop. Exits (thread ends) only when the mount goes away
/// (`read` returns 0/ENODEV) or on an unexpected fd error.
fn serve_loop(fd: OwnedFd) {
    let raw = fd.as_raw_fd();
    let mut buf = vec![0u8; 132 * 1024];
    loop {
        // SAFETY: reading one FUSE request into an owned buffer.
        let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            match errno() {
                libc::EINTR | libc::EAGAIN => continue,
                _ => break, // ENODEV (unmounted) or unexpected → stop serving
            }
        }
        if n == 0 {
            break;
        }
        if let Some(reply) = handle(&buf[..n as usize]) {
            write_reply(raw, &reply);
        }
    }
}

/// Dispatch one request. Returns the reply bytes, or `None` for the reply-less
/// ops (FORGET / BATCH_FORGET / INTERRUPT).
fn handle(req: &[u8]) -> Option<Vec<u8>> {
    let hdr: FuseInHeader = read_struct(req)?;
    let body = req.get(HDR..).unwrap_or(&[]);
    let u = hdr.unique;
    Some(match hdr.opcode {
        FUSE_INIT => handle_init(&hdr, body),
        FUSE_GETATTR => handle_getattr(&hdr),
        FUSE_LOOKUP => handle_lookup(&hdr, body),
        FUSE_OPEN => reply_struct(u, &open_out(FOPEN_DIRECT_IO)),
        FUSE_OPENDIR => reply_struct(u, &open_out(0)),
        FUSE_READ => handle_read(&hdr, body),
        FUSE_READDIR => handle_readdir(&hdr, body),
        FUSE_STATFS => reply_struct(
            u,
            &FuseKstatfs {
                namelen: 255,
                bsize: 4096,
                ..zeroed()
            },
        ),
        FUSE_FLUSH | FUSE_RELEASE | FUSE_RELEASEDIR | FUSE_DESTROY => reply_status(u, 0),
        FUSE_FORGET | FUSE_BATCH_FORGET | FUSE_INTERRUPT => return None,
        _ => reply_status(u, ENOSYS),
    })
}

/// Content of a virtual file for `nodeid`, generated for the caller `pid`.
fn content_for(nodeid: u64, pid: u32) -> Option<String> {
    Some(match nodeid {
        NODE_MEMINFO => generate::meminfo_for_pid(pid),
        NODE_CPUINFO => generate::cpuinfo_for_pid(pid),
        NODE_STAT => generate::stat_for_pid(pid),
        NODE_ONLINE => generate::online_for_pid(pid),
        NODE_POSSIBLE => generate::possible_for_pid(pid),
        NODE_PRESENT => generate::present_for_pid(pid),
        _ => return None,
    })
}

/// Resolve a directory-entry name to its file nodeid.
fn file_node(name: &[u8]) -> Option<u64> {
    Some(match name {
        b"meminfo" => NODE_MEMINFO,
        b"cpuinfo" => NODE_CPUINFO,
        b"stat" => NODE_STAT,
        b"online" => NODE_ONLINE,
        b"possible" => NODE_POSSIBLE,
        b"present" => NODE_PRESENT,
        _ => return None,
    })
}

/// The virtual files (name, nodeid) served under the root dir.
const FILES: &[(&[u8], u64)] = &[
    (b"meminfo", NODE_MEMINFO),
    (b"cpuinfo", NODE_CPUINFO),
    (b"stat", NODE_STAT),
    (b"online", NODE_ONLINE),
    (b"possible", NODE_POSSIBLE),
    (b"present", NODE_PRESENT),
];

fn handle_init(hdr: &FuseInHeader, body: &[u8]) -> Vec<u8> {
    if body.len() < 8 {
        return reply_status(hdr.unique, EIO);
    }
    let their_minor = le_u32(&body[4..8]);
    let max_readahead = if body.len() >= 12 {
        le_u32(&body[8..12])
    } else {
        0
    };
    let out = FuseInitOut {
        major: PROTO_MAJOR,
        minor: their_minor.min(PROTO_MINOR),
        max_readahead,
        flags: 0, // negotiate no optional features — simplest correct baseline
        max_background: 0,
        congestion_threshold: 0,
        max_write: MAX_WRITE,
        time_gran: 1,
        max_pages: 0,
        map_alignment: 0,
        flags2: 0,
        unused: [0; 7],
    };
    reply_struct(hdr.unique, &out)
}

fn handle_getattr(hdr: &FuseInHeader) -> Vec<u8> {
    let attr = if hdr.nodeid == NODE_ROOT {
        dir_attr()
    } else if let Some(content) = content_for(hdr.nodeid, hdr.pid) {
        // Report the real content length for THIS caller's cgroup. Readers that
        // trust the file size (GNU `cat` via copy_file_range/sendfile) then read
        // the right amount instead of treating a size-0 file as empty; read()-
        // based tools (free/top/grep) work either way.
        file_attr(hdr.nodeid, content.len() as u64)
    } else {
        return reply_status(hdr.unique, ENOENT);
    };
    reply_struct(
        hdr.unique,
        &FuseAttrOut {
            attr_valid: 0,
            attr_valid_nsec: 0,
            dummy: 0,
            attr,
        },
    )
}

fn handle_lookup(hdr: &FuseInHeader, body: &[u8]) -> Vec<u8> {
    let node = match (hdr.nodeid == NODE_ROOT)
        .then(|| file_node(cstr(body)))
        .flatten()
    {
        Some(n) => n,
        None => return reply_status(hdr.unique, ENOENT),
    };
    reply_struct(
        hdr.unique,
        &FuseEntryOut {
            nodeid: node,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            // Real size comes from the GETATTR the kernel issues next (attr_valid=0).
            attr: file_attr(node, 0),
        },
    )
}

fn handle_read(hdr: &FuseInHeader, body: &[u8]) -> Vec<u8> {
    let ri: FuseReadIn = match read_struct(body) {
        Some(r) => r,
        None => return reply_status(hdr.unique, EIO),
    };
    // Regenerate per read from the CALLER's cgroup — this is the whole trick.
    let content = match content_for(hdr.nodeid, hdr.pid) {
        Some(c) => c,
        None => return reply_status(hdr.unique, ENOENT),
    };
    let bytes = content.as_bytes();
    let off = ri.offset as usize;
    if off >= bytes.len() {
        return reply_ok(hdr.unique, &[]); // EOF
    }
    let end = off.saturating_add(ri.size as usize).min(bytes.len());
    reply_ok(hdr.unique, &bytes[off..end])
}

fn handle_readdir(hdr: &FuseInHeader, body: &[u8]) -> Vec<u8> {
    let ri: FuseReadIn = match read_struct(body) {
        Some(r) => r,
        None => return reply_status(hdr.unique, EIO),
    };
    reply_ok(hdr.unique, &pack_readdir(ri.offset, ri.size))
}

/// Pack the root dir's entries (`.`, `..`, then the virtual files) as
/// `fuse_dirent`s, each padded to an 8-byte boundary, resuming after cookie
/// `offset` and stopping at the `size` budget. An empty result = end-of-dir.
fn pack_readdir(offset: u64, size: u32) -> Vec<u8> {
    // (name, ino, cookie, d_type). Cookies are 1-based and monotonic.
    let mut entries: Vec<(&[u8], u64, u64, u32)> =
        vec![(b".", NODE_ROOT, 1, DT_DIR), (b"..", NODE_ROOT, 2, DT_DIR)];
    for (i, (name, ino)) in FILES.iter().enumerate() {
        entries.push((name, *ino, 3 + i as u64, DT_REG));
    }
    let mut out = Vec::new();
    for (name, ino, cookie, typ) in entries {
        if cookie <= offset {
            continue;
        }
        let entlen = 24 + name.len();
        let padded = (entlen + 7) & !7;
        if out.len() + padded > size as usize {
            break;
        }
        let dh = FuseDirentHeader {
            ino,
            off: cookie,
            namelen: name.len() as u32,
            typ,
        };
        out.extend_from_slice(as_bytes(&dh));
        out.extend_from_slice(name);
        out.resize(out.len() + (padded - entlen), 0); // 8-byte alignment padding
    }
    out
}

// ---- attrs + reply helpers -------------------------------------------------

fn file_attr(ino: u64, size: u64) -> FuseAttr {
    FuseAttr {
        ino,
        size,
        mode: S_IFREG | 0o444,
        nlink: 1,
        blksize: 4096,
        ..zeroed()
    }
}

fn dir_attr() -> FuseAttr {
    FuseAttr {
        ino: NODE_ROOT,
        mode: S_IFDIR | 0o555,
        nlink: 2,
        blksize: 4096,
        ..zeroed()
    }
}

fn open_out(open_flags: u32) -> FuseOpenOut {
    FuseOpenOut {
        fh: 0,
        open_flags,
        padding: 0,
    }
}

fn zeroed<T: Default>() -> T {
    T::default()
}

/// Header-only reply carrying a status (0 = ok, negative = errno).
fn reply_status(unique: u64, error: i32) -> Vec<u8> {
    as_bytes(&FuseOutHeader {
        len: std::mem::size_of::<FuseOutHeader>() as u32, // 16
        error,
        unique,
    })
    .to_vec()
}

/// Reply header + raw payload bytes.
fn reply_ok(unique: u64, payload: &[u8]) -> Vec<u8> {
    let h = FuseOutHeader {
        len: (16 + payload.len()) as u32,
        error: 0,
        unique,
    };
    let mut v = Vec::with_capacity(16 + payload.len());
    v.extend_from_slice(as_bytes(&h));
    v.extend_from_slice(payload);
    v
}

/// Reply header + a `repr(C)` struct payload.
fn reply_struct<T: Copy>(unique: u64, s: &T) -> Vec<u8> {
    reply_ok(unique, as_bytes(s))
}

/// Write one reply in a single `write` (FUSE = one message per write), retrying
/// only on EINTR. A lost reply (e.g. the op was interrupted) is dropped.
fn write_reply(fd: RawFd, buf: &[u8]) {
    loop {
        // SAFETY: writing an owned buffer to the fuse fd.
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 && errno() == libc::EINTR {
            continue;
        }
        break;
    }
}

fn cstr(body: &[u8]) -> &[u8] {
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    &body[..end]
}

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readdir_packs_and_resumes() {
        // From offset 0 with a big budget: `.`, `..`, and every virtual file.
        let all = pack_readdir(0, 4096);
        assert!(!all.is_empty());
        assert_eq!(all.len() % 8, 0); // each entry is 8-byte aligned
                                      // Past the last cookie (2 dot entries + FILES): end-of-directory (empty).
        let last = 2 + FILES.len() as u64;
        assert!(pack_readdir(last, 4096).is_empty());
        // A zero budget yields nothing.
        assert!(pack_readdir(0, 0).is_empty());
    }

    #[test]
    fn status_reply_is_16_bytes() {
        assert_eq!(reply_status(7, ENOENT).len(), 16);
    }

    #[test]
    fn cstr_stops_at_nul() {
        assert_eq!(cstr(b"meminfo\0garbage"), b"meminfo");
        assert_eq!(cstr(b"noterm"), b"noterm");
    }
}
