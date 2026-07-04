//! FUSE kernel ABI (protocol 7.39, Linux 6.8) — the exact `#[repr(C)]` wire
//! structs, opcode constants, and bounded encode/decode helpers for a minimal
//! read-only pseudo-filesystem talking directly to `/dev/fuse`. Every struct
//! size is asserted at compile time, so a layout mistake is a build error rather
//! than a runtime `EIO`. All integers are native-endian (LE on our targets).

use std::mem::size_of;

// ---- opcodes we handle (from include/uapi/linux/fuse.h) ----
pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_INTERRUPT: u32 = 36;
pub const FUSE_DESTROY: u32 = 38;
pub const FUSE_BATCH_FORGET: u32 = 42;

/// `open_flags`: bypass the page cache — each read hits us at the exact
/// offset/size, so content always reflects live cgroup state (`/proc` semantics).
pub const FOPEN_DIRECT_IO: u32 = 1 << 0;

/// Negotiated protocol version we implement.
pub const PROTO_MAJOR: u32 = 7;
pub const PROTO_MINOR: u32 = 39;
/// Matches the no-`FUSE_MAX_PAGES` default request cap (32 pages * 4 KiB).
pub const MAX_WRITE: u32 = 128 * 1024;

// ---- negative errnos (Linux) ----
pub const ENOENT: i32 = -2;
pub const EIO: i32 = -5;
pub const EROFS: i32 = -30;
pub const ENOSYS: i32 = -38;

// ---- st_mode bits ----
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;

// ---- readdir d_type ----
pub const DT_DIR: u32 = 4;
pub const DT_REG: u32 = 8;

// ---- fixed inode numbers: a flat root dir + one node per virtual file ----
pub const NODE_ROOT: u64 = 1;
pub const NODE_MEMINFO: u64 = 2;
pub const NODE_CPUINFO: u64 = 3;
pub const NODE_STAT: u64 = 4;
pub const NODE_ONLINE: u64 = 5;
pub const NODE_POSSIBLE: u64 = 6;
pub const NODE_PRESENT: u64 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub total_extlen: u16,
    pub padding: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub flags2: u32,
    pub unused: [u32; 11],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub unused: [u32; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

/// READDIR dirent header; the (unpadded) name follows, then the whole entry is
/// padded up to an 8-byte boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuseDirentHeader {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub typ: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FuseKstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}

// ---- compile-time layout guards: a wrong field is a build error, not an EIO ----
const _: () = assert!(size_of::<FuseInHeader>() == 40);
const _: () = assert!(size_of::<FuseOutHeader>() == 16);
const _: () = assert!(size_of::<FuseInitIn>() == 64);
const _: () = assert!(size_of::<FuseInitOut>() == 64);
const _: () = assert!(size_of::<FuseAttr>() == 88);
const _: () = assert!(size_of::<FuseEntryOut>() == 128);
const _: () = assert!(size_of::<FuseAttrOut>() == 104);
const _: () = assert!(size_of::<FuseOpenOut>() == 16);
const _: () = assert!(size_of::<FuseReadIn>() == 40);
const _: () = assert!(size_of::<FuseDirentHeader>() == 24);
const _: () = assert!(size_of::<FuseKstatfs>() == 80);

/// View any `repr(C)` POD as its wire bytes (for building replies). Safe: our
/// reply structs are `Copy`, have no implicit padding, and every field is set
/// before this is called, so no uninitialized bytes are exposed.
pub fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: `T` is `#[repr(C)] Copy` POD with no padding; we read `size_of::<T>`
    // bytes from a live reference we hold for the duration of the borrow.
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, size_of::<T>()) }
}

/// Decode a struct from the head of a request buffer; `None` if too short. Uses
/// an unaligned read because FUSE request payloads are packed and the buffer is
/// not guaranteed to be `T`-aligned.
pub fn read_struct<T: Copy>(buf: &[u8]) -> Option<T> {
    if buf.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: bounds checked above; `read_unaligned` tolerates any alignment and
    // `T` is a plain POD, so any bit pattern is a valid value.
    Some(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) })
}
