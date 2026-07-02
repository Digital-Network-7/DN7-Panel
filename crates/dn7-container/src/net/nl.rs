//! Minimal **synchronous** rtnetlink (`NETLINK_ROUTE`) over raw libc sockets —
//! the pure-Rust, in-process replacement for shelling out to `ip` (iproute2).
//! No C library, no async runtime: just the handful of fire-and-forget messages
//! the runtime needs (create bridge/veth, set up/master/addr/mac/name/route, move
//! a link into a netns, delete a link), plus a `with_netns` helper that runs a
//! closure with a netlink socket bound inside a container's network namespace.
//!
//! Message layout is built by hand per the rtnetlink ABI (nlmsghdr + ifinfomsg/
//! ifaddrmsg/rtmsg + 4-byte-aligned rtattr TLVs). Every mutating request carries
//! `NLM_F_ACK`, so the kernel always replies with one `NLMSG_ERROR` whose errno
//! we surface (0 = success).

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::{Error, Result};

// rtnetlink message types.
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;

// nlmsg flags.
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// IFLA_* link attributes.
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

// IFA_* / RTA_* attributes.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_GATEWAY: u16 = 5;

const IFF_UP: u32 = 1;
const AF_INET: u8 = 2;
const AF_UNSPEC: u8 = 0;

// Route msg fields.
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

/// errno for "object already exists" — tolerated on idempotent setup.
pub const EEXIST: i32 = 17;
/// errno for "no such device" — tolerated on idempotent teardown.
pub const ENODEV: i32 = 19;

#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A growable rtnetlink request buffer (header filled in on [`finish`]).
struct MsgBuf {
    buf: Vec<u8>,
}

impl MsgBuf {
    fn new(nlmsg_type: u16, flags: u16, seq: u32) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (patched in finish)
        buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel = 0)
        Self { buf }
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// `ifinfomsg { family, pad, type, index, flags, change }`.
    fn ifinfo(&mut self, family: u8, index: i32, flags: u32, change: u32) {
        self.buf.push(family);
        self.buf.push(0);
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
        self.buf.extend_from_slice(&index.to_ne_bytes());
        self.buf.extend_from_slice(&flags.to_ne_bytes());
        self.buf.extend_from_slice(&change.to_ne_bytes());
    }

    /// `ifaddrmsg { family, prefixlen, flags, scope, index }`.
    fn ifaddr(&mut self, family: u8, prefixlen: u8, index: u32) {
        self.buf.push(family);
        self.buf.push(prefixlen);
        self.buf.push(0); // flags
        self.buf.push(0); // scope
        self.buf.extend_from_slice(&index.to_ne_bytes());
    }

    /// `rtmsg { family, dst_len, src_len, tos, table, protocol, scope, type, flags }`.
    fn rtmsg_default(&mut self) {
        self.buf.push(AF_INET); // family
        self.buf.push(0); // dst_len (0 = default route)
        self.buf.push(0); // src_len
        self.buf.push(0); // tos
        self.buf.push(RT_TABLE_MAIN);
        self.buf.push(RTPROT_BOOT);
        self.buf.push(RT_SCOPE_UNIVERSE);
        self.buf.push(RTN_UNICAST);
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // flags
    }

    fn attr(&mut self, typ: u16, data: &[u8]) {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&typ.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
    }

    /// Open a nested attribute; returns the byte offset to patch in [`nest_end`].
    fn nest_start(&mut self, typ: u16) -> usize {
        let at = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // len placeholder
        self.buf.extend_from_slice(&typ.to_ne_bytes());
        at
    }

    fn nest_end(&mut self, at: usize) {
        let len = (self.buf.len() - at) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
        self.pad();
    }

    fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// A bound `NETLINK_ROUTE` socket. Created in whatever network namespace the
/// calling thread is in (see [`with_netns`]).
pub struct NlSock {
    fd: OwnedFd,
    seq: u32,
}

impl NlSock {
    pub fn open() -> Result<Self> {
        // SAFETY: socket(2) with constant args; we own the returned fd.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(Error::Other(format!(
                "netlink socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: bind a zeroed sockaddr_nl (kernel assigns the port id).
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            return Err(Error::Other(format!(
                "netlink bind: {}",
                std::io::Error::last_os_error()
            )));
        }
        // A receive timeout so a dropped/never-acked request errors out instead of
        // blocking the (synchronous) runtime forever.
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: setsockopt SO_RCVTIMEO with a valid timeval pointer + length.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
        Ok(Self { fd, seq: 0 })
    }

    /// Send one request and consume its `NLMSG_ERROR` ack. `Ok(())` on success,
    /// `Err(errno)` (positive) on a kernel error so callers can tolerate
    /// [`EEXIST`]/[`ENODEV`].
    fn talk(&mut self, build: impl FnOnce(u32) -> Vec<u8>) -> std::result::Result<(), i32> {
        self.seq += 1;
        let msg = build(self.seq);
        // SAFETY: send the built buffer; pointer + len are valid.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr() as *const _, msg.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(5));
        }
        let mut buf = [0u8; 8192];
        // SAFETY: recv into a stack buffer.
        let r = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(5));
        }
        let r = r as usize;
        let mut off = 0;
        while off + 16 <= r {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let mtype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < 16 || off + len > r {
                break;
            }
            if mtype == NLMSG_ERROR {
                // nlmsgerr: i32 error (negative errno; 0 = ack) then the orig header.
                let errno = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                return if errno == 0 { Ok(()) } else { Err(-errno) };
            }
            if mtype == NLMSG_DONE {
                return Ok(());
            }
            off += align4(len);
        }
        Ok(())
    }

    /// Tolerate specific errnos (idempotent ops) while propagating real failures.
    fn talk_ok(
        &mut self,
        what: &str,
        tolerate: &[i32],
        build: impl FnOnce(u32) -> Vec<u8>,
    ) -> Result<()> {
        match self.talk(build) {
            Ok(()) => Ok(()),
            Err(e) if tolerate.contains(&e) => Ok(()),
            Err(e) => Err(Error::Other(format!("netlink {what} failed: errno {e}"))),
        }
    }

    /// Create a bridge named `name` (idempotent — tolerates EEXIST).
    pub fn add_bridge(&mut self, name: &str) -> Result<()> {
        self.talk_ok("add bridge", &[EEXIST], |seq| {
            let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, 0, 0, 0);
            m.attr(IFLA_IFNAME, name.as_bytes());
            let li = m.nest_start(IFLA_LINKINFO);
            m.attr(IFLA_INFO_KIND, b"bridge");
            m.nest_end(li);
            m.finish()
        })
    }

    /// Create a veth pair `host` <-> `peer` (idempotent — tolerates EEXIST).
    pub fn add_veth(&mut self, host: &str, peer: &str) -> Result<()> {
        self.talk_ok("add veth", &[EEXIST], |seq| {
            let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, 0, 0, 0);
            m.attr(IFLA_IFNAME, host.as_bytes());
            let li = m.nest_start(IFLA_LINKINFO);
            m.attr(IFLA_INFO_KIND, b"veth");
            let data = m.nest_start(IFLA_INFO_DATA);
            let peer_nest = m.nest_start(VETH_INFO_PEER);
            m.ifinfo(AF_UNSPEC, 0, 0, 0); // peer ifinfomsg
            m.attr(IFLA_IFNAME, peer.as_bytes());
            m.nest_end(peer_nest);
            m.nest_end(data);
            m.nest_end(li);
            m.finish()
        })
    }

    /// Bring link `index` up.
    pub fn set_up(&mut self, index: i32) -> Result<()> {
        self.talk_ok("set up", &[], |seq| {
            let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, index, IFF_UP, IFF_UP);
            m.finish()
        })
    }

    /// Set link `index`'s master to bridge `master_index`.
    pub fn set_master(&mut self, index: i32, master_index: i32) -> Result<()> {
        self.talk_ok("set master", &[], |seq| {
            let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, index, 0, 0);
            m.attr(IFLA_MASTER, &(master_index as u32).to_ne_bytes());
            m.finish()
        })
    }

    /// Rename link `index` to `new_name`.
    pub fn set_name(&mut self, index: i32, new_name: &str) -> Result<()> {
        self.talk_ok("set name", &[], |seq| {
            let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, index, 0, 0);
            m.attr(IFLA_IFNAME, new_name.as_bytes());
            m.finish()
        })
    }

    /// Set link `index`'s MAC (`mac` = 6 bytes).
    pub fn set_mac(&mut self, index: i32, mac: &[u8; 6]) -> Result<()> {
        self.talk_ok("set mac", &[], |seq| {
            let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, index, 0, 0);
            m.attr(IFLA_ADDRESS, mac);
            m.finish()
        })
    }

    /// Move link `index` into the network namespace owned by `pid`.
    pub fn move_to_netns_pid(&mut self, index: i32, pid: i32) -> Result<()> {
        self.talk_ok("move to netns", &[], |seq| {
            let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, index, 0, 0);
            m.attr(IFLA_NET_NS_PID, &(pid as u32).to_ne_bytes());
            m.finish()
        })
    }

    /// Add `addr/prefix` to link `index` (idempotent — tolerates EEXIST).
    pub fn add_addr(&mut self, index: i32, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        self.talk_ok("add addr", &[EEXIST], |seq| {
            let mut m = MsgBuf::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_ACK, seq);
            m.ifaddr(AF_INET, prefix, index as u32);
            m.attr(IFA_LOCAL, &addr.octets());
            m.attr(IFA_ADDRESS, &addr.octets());
            m.finish()
        })
    }

    /// Add a default route via `gateway`.
    pub fn add_default_route(&mut self, gateway: Ipv4Addr) -> Result<()> {
        self.talk_ok("add default route", &[EEXIST], |seq| {
            let mut m = MsgBuf::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_ACK, seq);
            m.rtmsg_default();
            m.attr(RTA_GATEWAY, &gateway.octets());
            m.finish()
        })
    }

    /// Delete link `index` (idempotent — tolerates ENODEV).
    pub fn del_link(&mut self, index: i32) -> Result<()> {
        self.talk_ok("del link", &[ENODEV], |seq| {
            let mut m = MsgBuf::new(RTM_DELLINK, NLM_F_ACK, seq);
            m.ifinfo(AF_UNSPEC, index, 0, 0);
            m.finish()
        })
    }
}

/// Resolve an interface name → index in the CURRENT network namespace (0 = none).
pub fn if_index(name: &str) -> Result<i32> {
    let c = CString::new(name).map_err(|_| Error::Other("bad ifname".into()))?;
    // SAFETY: if_nametoindex reads the name in the caller's netns.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(Error::Other(format!("interface {name} not found")));
    }
    Ok(idx as i32)
}

/// Run `f` with a netlink socket bound inside `pid`'s network namespace, then
/// restore the caller's netns. Synchronous: the thread does not yield between
/// `setns` and restore, so it cannot leak the swapped namespace to other work.
pub fn with_netns<T>(pid: i32, f: impl FnOnce(&mut NlSock) -> Result<T>) -> Result<T> {
    let self_ns =
        std::fs::File::open("/proc/self/ns/net").map_err(Error::io("/proc/self/ns/net"))?;
    let target_path = format!("/proc/{pid}/ns/net");
    let target = std::fs::File::open(&target_path).map_err(Error::io(&target_path))?;
    // Enter the container netns.
    // SAFETY: setns on an owned netns fd; CLONE_NEWNET affects only this thread.
    if unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(Error::Other(format!(
            "setns netns: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Guard restores the caller's netns no matter how `f` returns.
    let _restore = NetnsRestore(self_ns);
    let mut sock = NlSock::open()?;
    f(&mut sock)
}

/// On drop, return the thread to its original network namespace.
struct NetnsRestore(std::fs::File);
impl Drop for NetnsRestore {
    fn drop(&mut self) {
        // SAFETY: restore the saved netns; best-effort (nothing to do on failure).
        unsafe { libc::setns(self.0.as_raw_fd(), libc::CLONE_NEWNET) };
    }
}

#[cfg(test)]
mod tests {
    //! Golden-byte tests for the hand-built rtnetlink wire layout. No socket, no
    //! root, no kernel — they pin the exact framing (header length/type/flags,
    //! rtattr TLV length + 4-byte alignment, nested-attr length patching) so a
    //! refactor of `MsgBuf` can't silently corrupt the messages.
    use super::*;

    #[test]
    fn align4_rounds_up_to_4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(7), 8);
        assert_eq!(align4(8), 8);
    }

    #[test]
    fn header_is_16_bytes_with_request_flag_and_patched_len() {
        let m = MsgBuf::new(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE, 7).finish();
        assert_eq!(m.len(), 16, "nlmsghdr is 16 bytes");
        assert_eq!(
            &m[0..4],
            &16u32.to_ne_bytes(),
            "nlmsg_len patched in finish"
        );
        assert_eq!(&m[4..6], &RTM_NEWADDR.to_ne_bytes(), "nlmsg_type");
        assert_eq!(
            &m[6..8],
            &(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE).to_ne_bytes(),
            "NLM_F_REQUEST is always OR'd in"
        );
        assert_eq!(&m[8..12], &7u32.to_ne_bytes(), "nlmsg_seq");
        assert_eq!(&m[12..16], &0u32.to_ne_bytes(), "nlmsg_pid = 0 (kernel)");
    }

    #[test]
    fn attr_tlv_length_and_4byte_padding() {
        let mut m = MsgBuf::new(RTM_NEWLINK, 0, 1);
        m.attr(IFLA_IFNAME, b"abc"); // 3-byte payload
        let a = &m.buf[16..]; // skip the 16-byte header
        assert_eq!(&a[0..2], &7u16.to_ne_bytes(), "rtattr len = 4 + payload");
        assert_eq!(&a[2..4], &IFLA_IFNAME.to_ne_bytes(), "rtattr type");
        assert_eq!(&a[4..7], b"abc", "payload");
        assert_eq!(a.len(), 8, "padded up to align4(7) = 8");
        assert_eq!(a[7], 0, "pad byte is zero");
    }

    #[test]
    fn ifaddrmsg_with_local_addr_has_exact_layout() {
        let mut m = MsgBuf::new(RTM_NEWADDR, NLM_F_ACK, 1);
        m.ifaddr(AF_INET, 24, 5);
        m.attr(IFA_LOCAL, &Ipv4Addr::new(172, 18, 0, 2).octets());
        let bytes = m.finish();
        // 16 (nlmsghdr) + 8 (ifaddrmsg) + 8 (4 rtattr hdr + 4 addr) = 32.
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[0..4], &32u32.to_ne_bytes());
        assert_eq!(bytes[16], AF_INET, "ifa_family");
        assert_eq!(bytes[17], 24, "ifa_prefixlen");
        assert_eq!(bytes[18], 0, "ifa_flags");
        assert_eq!(bytes[19], 0, "ifa_scope");
        assert_eq!(&bytes[20..24], &5u32.to_ne_bytes(), "ifa_index");
        assert_eq!(&bytes[24..26], &8u16.to_ne_bytes(), "IFA_LOCAL rtattr len");
        assert_eq!(&bytes[26..28], &IFA_LOCAL.to_ne_bytes());
        assert_eq!(&bytes[28..32], &[172, 18, 0, 2]);
    }

    #[test]
    fn nested_linkinfo_length_is_patched() {
        let mut m = MsgBuf::new(RTM_NEWLINK, NLM_F_CREATE, 1);
        let at = m.nest_start(IFLA_LINKINFO);
        m.attr(IFLA_INFO_KIND, b"veth"); // 4 + 4 = 8, already aligned
        m.nest_end(at);
        let nested = &m.buf[at..];
        // nest header (4) + inner rtattr (4 + 4) = 12.
        assert_eq!(
            u16::from_ne_bytes([nested[0], nested[1]]) as usize,
            12,
            "nested attr length patched by nest_end"
        );
        assert_eq!(&nested[2..4], &IFLA_LINKINFO.to_ne_bytes());
        assert_eq!(&nested[4..6], &8u16.to_ne_bytes(), "inner INFO_KIND len");
        assert_eq!(&nested[6..8], &IFLA_INFO_KIND.to_ne_bytes());
        assert_eq!(&nested[8..12], b"veth");
    }
}
