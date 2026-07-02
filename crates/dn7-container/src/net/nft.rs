//! Minimal **synchronous nftables over raw `NETLINK_NETFILTER`** — the pure-Rust,
//! permissive, in-process replacement for the GPL/bindgen `rustables` crate (and
//! for shelling out to the `nft` binary). No C library, no build-time bindgen.
//!
//! Wire format (all constants are the kernel's `linux/netfilter/nf_tables.h`):
//! - A message is `nlmsghdr` (native byte order) + `nfgenmsg { family:u8,
//!   version:u8, res_id:be16 }` + 4-byte-aligned nlattr TLVs.
//! - `nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_*`.
//! - **Numeric attribute *values* are big-endian** (registers, ops, keys, hook
//!   nums, priorities, verdict codes, handles) — the key difference from the
//!   rtnetlink helper in [`super::nl`], whose values are native-endian. nlattr
//!   *headers* (len/type) stay native-endian. Nested attrs carry `NLA_F_NESTED`.
//! - A transaction is `NFNL_MSG_BATCH_BEGIN` + the messages + `NFNL_MSG_BATCH_END`
//!   in a single `send`. Each *content* message carries `NLM_F_ACK` (the kernel
//!   acks the messages, not the END marker). nftables validates the whole
//!   transaction, then on success acks each message (errno 0) and on failure
//!   sends one `NLMSG_ERROR` (errno<0) for the offending message and rolls back —
//!   so the first reply decides the batch.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::{Error, Result};

// nfnetlink / nftables subsystem + batch framing.
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

// nlmsg flags / types.
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLA_F_NESTED: u16 = 0x8000;

// nft message types (OR'd with the subsystem above).
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DELRULE: u16 = 8;

// Object attributes.
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_LIST_ELEM: u16 = 1;

// Expression attributes.
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFTA_NAT_REG_PROTO_MIN: u16 = 5;

// Value enums.
pub(crate) const NFT_CMP_EQ: u32 = 0;
pub(crate) const NFT_CMP_NEQ: u32 = 1;
pub(crate) const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
pub(crate) const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
pub(crate) const NFT_META_IIFNAME: u32 = 6;
pub(crate) const NFT_META_OIFNAME: u32 = 7;
pub(crate) const NFT_META_NFPROTO: u32 = 15;
pub(crate) const NFT_META_L4PROTO: u32 = 16;
const NFT_NAT_DNAT: u32 = 1;
const NFT_REG_VERDICT: u32 = 0;
pub(crate) const NFT_REG_1: u32 = 1;
pub(crate) const NFT_REG_2: u32 = 2;

// Families / hooks / verdicts.
const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
pub(crate) const NFPROTO_IPV4: u32 = 2;
pub(crate) const NF_INET_PRE_ROUTING: u32 = 0;
pub(crate) const NF_INET_FORWARD: u32 = 2;
pub(crate) const NF_INET_LOCAL_OUT: u32 = 3;
pub(crate) const NF_INET_POST_ROUTING: u32 = 4;
pub(crate) const NF_ACCEPT: u32 = 1;

/// errno for "object already exists" — tolerated on idempotent adds.
const EEXIST: i32 = 17;
/// errno for "no such file/object" — how the kernel reports an absent table.
const ENOENT: i32 = 2;

const fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ---------------------------------------------------------------------------
// Attribute TLV builder (values big-endian; headers native-endian).
// ---------------------------------------------------------------------------

/// A flat sequence of 4-byte-aligned nlattr TLVs. Used both for the attribute
/// section of a message and, recursively, for nested attributes / expressions.
#[derive(Default)]
pub(crate) struct Attrs {
    buf: Vec<u8>,
}

impl Attrs {
    fn new() -> Self {
        Attrs { buf: Vec::new() }
    }

    /// Raw payload TLV (addresses, ports, masks, strings — already in the desired
    /// byte order by the caller).
    fn raw(&mut self, typ: u16, data: &[u8]) {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&typ.to_ne_bytes());
        self.buf.extend_from_slice(data);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// A big-endian u32 value (register, op, key, hook num, priority, …).
    fn be32(&mut self, typ: u16, v: u32) {
        self.raw(typ, &v.to_be_bytes());
    }

    /// A NUL-terminated string (chain/table name, chain type, expr name).
    fn str0(&mut self, typ: u16, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.raw(typ, &v);
    }

    /// A nested attribute carrying `inner`'s TLVs, flagged `NLA_F_NESTED`.
    fn nested(&mut self, typ: u16, inner: &Attrs) {
        self.raw(typ | NLA_F_NESTED, &inner.buf);
    }
}

/// Wrap `data` as one expression: `{ NFTA_EXPR_NAME=name, NFTA_EXPR_DATA=data }`.
fn expr(name: &str, data: Attrs) -> Vec<u8> {
    let mut e = Attrs::new();
    e.str0(NFTA_EXPR_NAME, name);
    e.nested(NFTA_EXPR_DATA, &data);
    e.buf
}

/// The expression encoders. Each returns the bytes of ONE expression
/// (`NFTA_EXPR_NAME` + `NFTA_EXPR_DATA`); [`Batch::add_rule`] wraps each in an
/// `NFTA_LIST_ELEM`. `firewall.rs` composes rules out of these.
pub(crate) mod exprs {
    use super::*;

    /// `meta load <key> => reg <dreg>`.
    pub(crate) fn meta_load(key: u32, dreg: u32) -> Vec<u8> {
        let mut d = Attrs::new();
        d.be32(NFTA_META_KEY, key);
        d.be32(NFTA_META_DREG, dreg);
        expr("meta", d)
    }

    /// `cmp <op> reg <sreg> <value>` (value already in wire byte order).
    pub(crate) fn cmp(sreg: u32, op: u32, value: &[u8]) -> Vec<u8> {
        let mut dv = Attrs::new();
        dv.raw(NFTA_DATA_VALUE, value);
        let mut d = Attrs::new();
        d.be32(NFTA_CMP_SREG, sreg);
        d.be32(NFTA_CMP_OP, op);
        d.nested(NFTA_CMP_DATA, &dv);
        expr("cmp", d)
    }

    /// `payload load <len>b @ base <base> + <offset> => reg <dreg>`.
    pub(crate) fn payload_load(base: u32, offset: u32, len: u32, dreg: u32) -> Vec<u8> {
        let mut d = Attrs::new();
        d.be32(NFTA_PAYLOAD_DREG, dreg);
        d.be32(NFTA_PAYLOAD_BASE, base);
        d.be32(NFTA_PAYLOAD_OFFSET, offset);
        d.be32(NFTA_PAYLOAD_LEN, len);
        expr("payload", d)
    }

    /// `bitwise reg <dreg> = (reg <sreg> & mask) ^ xor` (len bytes).
    pub(crate) fn bitwise(sreg: u32, dreg: u32, len: u32, mask: &[u8], xor: &[u8]) -> Vec<u8> {
        let mut m = Attrs::new();
        m.raw(NFTA_DATA_VALUE, mask);
        let mut x = Attrs::new();
        x.raw(NFTA_DATA_VALUE, xor);
        let mut d = Attrs::new();
        d.be32(NFTA_BITWISE_SREG, sreg);
        d.be32(NFTA_BITWISE_DREG, dreg);
        d.be32(NFTA_BITWISE_LEN, len);
        d.nested(NFTA_BITWISE_MASK, &m);
        d.nested(NFTA_BITWISE_XOR, &x);
        expr("bitwise", d)
    }

    /// `immediate reg <dreg> <value>` — load a constant into a data register.
    pub(crate) fn immediate_data(dreg: u32, value: &[u8]) -> Vec<u8> {
        let mut dv = Attrs::new();
        dv.raw(NFTA_DATA_VALUE, value);
        let mut d = Attrs::new();
        d.be32(NFTA_IMMEDIATE_DREG, dreg);
        d.nested(NFTA_IMMEDIATE_DATA, &dv);
        expr("immediate", d)
    }

    /// `immediate reg 0 <verdict>` — a terminal verdict (e.g. `NF_ACCEPT`).
    pub(crate) fn immediate_verdict(code: u32) -> Vec<u8> {
        let mut v = Attrs::new();
        v.be32(NFTA_VERDICT_CODE, code);
        let mut dv = Attrs::new();
        dv.nested(NFTA_DATA_VERDICT, &v);
        let mut d = Attrs::new();
        d.be32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        d.nested(NFTA_IMMEDIATE_DATA, &dv);
        expr("immediate", d)
    }

    /// `nat dnat <family> addr reg <addr_reg> proto reg <proto_reg>`.
    pub(crate) fn nat_dnat(family: u32, addr_reg: u32, proto_reg: u32) -> Vec<u8> {
        let mut d = Attrs::new();
        d.be32(NFTA_NAT_TYPE, NFT_NAT_DNAT);
        d.be32(NFTA_NAT_FAMILY, family);
        d.be32(NFTA_NAT_REG_ADDR_MIN, addr_reg);
        d.be32(NFTA_NAT_REG_PROTO_MIN, proto_reg);
        expr("nat", d)
    }

    /// `masquerade` (no flags / port range).
    pub(crate) fn masquerade() -> Vec<u8> {
        expr("masq", Attrs::new())
    }
}

// ---------------------------------------------------------------------------
// Message framing.
// ---------------------------------------------------------------------------

/// Build one `nlmsghdr` + `nfgenmsg` + attribute-section message.
fn message(
    nlmsg_type: u16,
    flags: u16,
    seq: u32,
    family: u8,
    res_id: u16,
    attrs: &Attrs,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + attrs.buf.len());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (patched below)
    buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel = 0)
                                                // nfgenmsg: family, version (NFNETLINK_V0), res_id (big-endian).
    buf.push(family);
    buf.push(0);
    buf.extend_from_slice(&res_id.to_be_bytes());
    buf.extend_from_slice(&attrs.buf);
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
    buf
}

// ---------------------------------------------------------------------------
// Transaction batch.
// ---------------------------------------------------------------------------

/// A pending nftables transaction: a list of encoded messages sent atomically.
#[derive(Default)]
pub(crate) struct Batch {
    msgs: Vec<(u16, u16, Attrs)>, // (nft msg type, extra flags, attrs)
}

impl Batch {
    pub(crate) fn new() -> Self {
        Batch { msgs: Vec::new() }
    }

    /// `add table inet <name>`.
    pub(crate) fn add_table(&mut self, name: &str) {
        let mut a = Attrs::new();
        a.str0(NFTA_TABLE_NAME, name);
        self.msgs.push((NFT_MSG_NEWTABLE, NLM_F_CREATE, a));
    }

    /// `delete table inet <name>`.
    pub(crate) fn del_table(&mut self, name: &str) {
        let mut a = Attrs::new();
        a.str0(NFTA_TABLE_NAME, name);
        self.msgs.push((NFT_MSG_DELTABLE, 0, a));
    }

    /// `add chain inet <table> <name> { type <ty> hook <hooknum> priority <prio>; policy <pol>; }`.
    pub(crate) fn add_chain(
        &mut self,
        table: &str,
        name: &str,
        hooknum: u32,
        priority: i32,
        chain_type: &str,
        policy: u32,
    ) {
        let mut hook = Attrs::new();
        hook.be32(NFTA_HOOK_HOOKNUM, hooknum);
        hook.be32(NFTA_HOOK_PRIORITY, priority as u32);
        let mut a = Attrs::new();
        a.str0(NFTA_CHAIN_TABLE, table);
        a.str0(NFTA_CHAIN_NAME, name);
        a.nested(NFTA_CHAIN_HOOK, &hook);
        a.be32(NFTA_CHAIN_POLICY, policy);
        a.str0(NFTA_CHAIN_TYPE, chain_type);
        self.msgs.push((NFT_MSG_NEWCHAIN, NLM_F_CREATE, a));
    }

    /// `add rule inet <table> <chain> <exprs...>` (appended), optionally tagged
    /// with `userdata` (the `comment` TLV) for later teardown.
    pub(crate) fn add_rule(
        &mut self,
        table: &str,
        chain: &str,
        exprs: &[Vec<u8>],
        userdata: Option<&[u8]>,
    ) {
        let mut list = Attrs::new();
        for e in exprs {
            // Each expression is one NFTA_LIST_ELEM (nested) in the rule's
            // expression list.
            list.raw(NFTA_LIST_ELEM | NLA_F_NESTED, e);
        }
        let mut a = Attrs::new();
        a.str0(NFTA_RULE_TABLE, table);
        a.str0(NFTA_RULE_CHAIN, chain);
        a.nested(NFTA_RULE_EXPRESSIONS, &list);
        if let Some(u) = userdata {
            a.raw(NFTA_RULE_USERDATA, u);
        }
        self.msgs
            .push((NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, a));
    }

    /// `delete rule inet <table> <chain> handle <handle>`.
    pub(crate) fn del_rule(&mut self, table: &str, chain: &str, handle: u64) {
        let mut a = Attrs::new();
        a.str0(NFTA_RULE_TABLE, table);
        a.str0(NFTA_RULE_CHAIN, chain);
        a.raw(NFTA_RULE_HANDLE, &handle.to_be_bytes());
        self.msgs.push((NFT_MSG_DELRULE, 0, a));
    }

    fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    /// Serialize the whole transaction (BATCH_BEGIN + messages + BATCH_END) into
    /// one buffer starting at `seq0`. Returns the buffer + the BATCH_END seq.
    fn serialize(&self, seq0: u32) -> (Vec<u8>, u32) {
        let mut out = Vec::new();
        let mut seq = seq0;
        out.extend_from_slice(&message(
            NFNL_MSG_BATCH_BEGIN,
            0,
            seq,
            NFPROTO_UNSPEC,
            NFNL_SUBSYS_NFTABLES,
            &Attrs::new(),
        ));
        for (msg, flags, attrs) in &self.msgs {
            seq += 1;
            // ACK every content message: nftables validates the whole transaction
            // then, on success, acks each message (errno 0); on failure it sends
            // one NLMSG_ERROR for the offending message and aborts (no acks). So
            // the first reply decides the batch — see `recv_ack`.
            out.extend_from_slice(&message(
                nft_type(*msg),
                *flags | NLM_F_ACK,
                seq,
                NFPROTO_INET,
                0,
                attrs,
            ));
        }
        seq += 1;
        let end_seq = seq;
        out.extend_from_slice(&message(
            NFNL_MSG_BATCH_END,
            0,
            end_seq,
            NFPROTO_UNSPEC,
            NFNL_SUBSYS_NFTABLES,
            &Attrs::new(),
        ));
        (out, end_seq)
    }

    /// Send the transaction and consume its single ack. Idempotent-safe: tolerates
    /// `EEXIST`. A no-op batch is a no-op.
    pub(crate) fn send(self) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let mut sock = NftSock::open()?;
        let (buf, _end_seq) = self.serialize(sock.next_seq_block(self.msgs.len() as u32 + 2));
        sock.send_raw(&buf)?;
        match sock.recv_ack() {
            Ok(()) => Ok(()),
            Err(EEXIST) => Ok(()),
            Err(e) => Err(nft_err("transaction", e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Socket.
// ---------------------------------------------------------------------------

struct NftSock {
    fd: OwnedFd,
    seq: u32,
}

impl NftSock {
    fn open() -> Result<Self> {
        // SAFETY: socket(2) with constant args; we own the returned fd.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(sock_err("socket"));
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
            return Err(sock_err("bind"));
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

    /// Reserve `n` sequence numbers, returning the first.
    fn next_seq_block(&mut self, n: u32) -> u32 {
        let start = self.seq + 1;
        self.seq += n;
        start
    }

    fn send_raw(&self, buf: &[u8]) -> Result<()> {
        // SAFETY: send the built buffer; pointer + len are valid.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), buf.as_ptr() as *const _, buf.len(), 0) };
        if n < 0 {
            return Err(sock_err("send"));
        }
        Ok(())
    }

    fn recv_into(&self, buf: &mut [u8]) -> Result<usize> {
        // SAFETY: recv into a caller-owned buffer.
        let r = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
            )
        };
        if r < 0 {
            return Err(sock_err("recv"));
        }
        Ok(r as usize)
    }

    /// Read until the first `NLMSG_ERROR`: nftables validates the whole batch
    /// before replying, so errno 0 = the batch committed and errno<0 = the
    /// offending message failed (and the batch was rolled back). Returns
    /// `Err(positive errno)`.
    fn recv_ack(&mut self) -> std::result::Result<(), i32> {
        let mut buf = [0u8; 16384];
        loop {
            let r = self.recv_into(&mut buf).map_err(|_| libc::EIO)?;
            let mut off = 0;
            while off + 16 <= r {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let mtype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                if len < 16 || off + len > r {
                    return Err(libc::EIO);
                }
                if mtype == NLMSG_ERROR {
                    let errno = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                    return if errno == 0 { Ok(()) } else { Err(-errno) };
                }
                off += align4(len);
            }
        }
    }

    /// Dump all rules of `chain` in `table` (family inet); returns each rule's
    /// `(handle, userdata)`. Used to find and delete a container's tagged rules.
    fn dump_rules(&mut self, table: &str, chain: &str) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut a = Attrs::new();
        a.str0(NFTA_RULE_TABLE, table);
        a.str0(NFTA_RULE_CHAIN, chain);
        let seq = self.next_seq_block(1);
        let msg = message(
            nft_type(NFT_MSG_GETRULE),
            NLM_F_DUMP,
            seq,
            NFPROTO_INET,
            0,
            &a,
        );
        self.send_raw(&msg)?;

        let mut out = Vec::new();
        let mut buf = [0u8; 32768];
        'outer: loop {
            let r = self.recv_into(&mut buf)?;
            let mut off = 0;
            while off + 16 <= r {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let mtype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                if len < 16 || off + len > r {
                    break 'outer;
                }
                if mtype == NLMSG_DONE {
                    break 'outer;
                }
                if mtype == NLMSG_ERROR {
                    let errno = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                    if errno != 0 {
                        return Err(nft_err("dump rules", -errno));
                    }
                    break 'outer;
                }
                if mtype == nft_type(NFT_MSG_NEWRULE) {
                    // body = nfgenmsg (4 bytes) then attributes.
                    if let Some(item) = parse_rule(&buf[off + 20..off + len]) {
                        out.push(item);
                    }
                }
                off += align4(len);
            }
        }
        Ok(out)
    }

    /// Is `table inet <name>` present? A targeted GETTABLE: a `NEWTABLE` reply =
    /// present, `ENOENT` = absent.
    fn table_present(&mut self, name: &str) -> Result<bool> {
        let mut a = Attrs::new();
        a.str0(NFTA_TABLE_NAME, name);
        let seq = self.next_seq_block(1);
        let msg = message(
            nft_type(NFT_MSG_GETTABLE),
            NLM_F_ACK,
            seq,
            NFPROTO_INET,
            0,
            &a,
        );
        self.send_raw(&msg)?;
        let mut buf = [0u8; 8192];
        let r = self.recv_into(&mut buf)?;
        let mut off = 0;
        while off + 16 <= r {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let mtype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < 16 || off + len > r {
                break;
            }
            if mtype == nft_type(NFT_MSG_NEWTABLE) {
                return Ok(true);
            }
            if mtype == NLMSG_ERROR {
                let errno = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                return match -errno {
                    0 => Ok(true),
                    ENOENT => Ok(false),
                    e => Err(nft_err("get table", e)),
                };
            }
            off += align4(len);
        }
        Ok(false)
    }
}

/// Walk a NEWRULE message body's attributes for `(NFTA_RULE_HANDLE, NFTA_RULE_USERDATA)`.
fn parse_rule(body: &[u8]) -> Option<(u64, Vec<u8>)> {
    let mut handle: Option<u64> = None;
    let mut udata: Vec<u8> = Vec::new();
    let mut off = 0;
    while off + 4 <= body.len() {
        let alen = u16::from_ne_bytes(body[off..off + 2].try_into().ok()?) as usize;
        let atype = u16::from_ne_bytes(body[off + 2..off + 4].try_into().ok()?) & 0x3fff;
        if alen < 4 || off + alen > body.len() {
            break;
        }
        let val = &body[off + 4..off + alen];
        if atype == NFTA_RULE_HANDLE && val.len() >= 8 {
            handle = Some(u64::from_be_bytes(val[..8].try_into().ok()?));
        } else if atype == NFTA_RULE_USERDATA {
            udata = val.to_vec();
        }
        off += align4(alen);
    }
    handle.map(|h| (h, udata))
}

fn sock_err(what: &str) -> Error {
    Error::Other(format!(
        "nftables {what}: {}",
        std::io::Error::last_os_error()
    ))
}

fn nft_err(what: &str, errno: i32) -> Error {
    Error::Other(format!("nftables {what} failed: errno {errno}"))
}

// ---------------------------------------------------------------------------
// Public helpers used by `firewall.rs`.
// ---------------------------------------------------------------------------

/// Whether the nftables netlink subsystem is usable (kernel support + perms).
pub(crate) fn have_nft() -> bool {
    NftSock::open()
        .and_then(|mut s| s.table_present("dn7"))
        .is_ok()
}

/// Is `table inet <name>` present?
pub(crate) fn table_present(name: &str) -> bool {
    NftSock::open()
        .and_then(|mut s| s.table_present(name))
        .unwrap_or(false)
}

/// Every rule `(handle, userdata)` in `table inet <table>`'s `chain`.
pub(crate) fn list_rules(table: &str, chain: &str) -> Result<Vec<(u64, Vec<u8>)>> {
    NftSock::open()?.dump_rules(table, chain)
}

#[cfg(test)]
mod tests {
    //! Golden-byte tests for the hand-built nftables wire layout — no socket, no
    //! root, no kernel. They pin the framing (message header + nfgenmsg, nlattr
    //! TLV length + 4-byte alignment, NLA_F_NESTED, big-endian numeric values) so
    //! a refactor can't silently corrupt the messages the kernel parses.
    use super::*;

    #[test]
    fn align4_rounds_up() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }

    #[test]
    fn nft_type_ors_in_the_subsystem() {
        assert_eq!(nft_type(NFT_MSG_NEWRULE), 0x0a06);
        assert_eq!(nft_type(NFT_MSG_NEWTABLE), 0x0a00);
    }

    #[test]
    fn attr_be32_is_big_endian_and_padded() {
        let mut a = Attrs::new();
        a.be32(NFTA_CMP_OP, 1);
        // 4-byte header + 4-byte value, already aligned.
        assert_eq!(a.buf.len(), 8);
        assert_eq!(&a.buf[0..2], &8u16.to_ne_bytes(), "nlattr len = 4 + 4");
        assert_eq!(&a.buf[2..4], &NFTA_CMP_OP.to_ne_bytes(), "nlattr type");
        assert_eq!(&a.buf[4..8], &1u32.to_be_bytes(), "VALUE is big-endian");
    }

    #[test]
    fn attr_str0_nul_terminates_and_pads() {
        let mut a = Attrs::new();
        a.str0(NFTA_TABLE_NAME, "dn7");
        // 4 header + "dn7\0" = 8, aligned.
        assert_eq!(a.buf.len(), 8);
        assert_eq!(&a.buf[0..2], &8u16.to_ne_bytes());
        assert_eq!(&a.buf[4..8], b"dn7\0");
    }

    #[test]
    fn nested_attr_sets_the_nested_flag() {
        let mut inner = Attrs::new();
        inner.be32(NFTA_HOOK_HOOKNUM, NF_INET_POST_ROUTING);
        let mut a = Attrs::new();
        a.nested(NFTA_CHAIN_HOOK, &inner);
        let atype = u16::from_ne_bytes(a.buf[2..4].try_into().unwrap());
        assert_eq!(atype & NLA_F_NESTED, NLA_F_NESTED, "NLA_F_NESTED set");
        assert_eq!(
            atype & 0x3fff,
            NFTA_CHAIN_HOOK,
            "type preserved under the flag"
        );
    }

    #[test]
    fn message_header_and_nfgenmsg_layout() {
        let m = message(
            nft_type(NFT_MSG_NEWTABLE),
            NLM_F_CREATE,
            7,
            NFPROTO_INET,
            0,
            &Attrs::new(),
        );
        assert_eq!(m.len(), 20, "16 nlmsghdr + 4 nfgenmsg, no attrs");
        assert_eq!(&m[0..4], &20u32.to_ne_bytes(), "nlmsg_len patched");
        assert_eq!(&m[4..6], &nft_type(NFT_MSG_NEWTABLE).to_ne_bytes());
        assert_eq!(
            &m[6..8],
            &(NLM_F_REQUEST | NLM_F_CREATE).to_ne_bytes(),
            "REQUEST always OR'd"
        );
        assert_eq!(&m[8..12], &7u32.to_ne_bytes(), "seq");
        assert_eq!(m[16], NFPROTO_INET, "nfgen_family");
        assert_eq!(m[17], 0, "nfnetlink version 0");
        assert_eq!(&m[18..20], &0u16.to_be_bytes(), "res_id (be16)");
    }

    #[test]
    fn batch_wraps_messages_in_begin_end_and_acks_content() {
        let mut b = Batch::new();
        b.add_table("dn7");
        let (buf, end_seq) = b.serialize(1);
        // BATCH_BEGIN (seq 1), NEWTABLE (seq 2), BATCH_END (seq 3).
        assert_eq!(end_seq, 3);
        // First message is BATCH_BEGIN with res_id = NFTABLES subsystem, no ACK.
        assert_eq!(&buf[4..6], &NFNL_MSG_BATCH_BEGIN.to_ne_bytes());
        assert_eq!(&buf[18..20], &NFNL_SUBSYS_NFTABLES.to_be_bytes());
        let begin_flags = u16::from_ne_bytes(buf[6..8].try_into().unwrap());
        assert_eq!(begin_flags & NLM_F_ACK, 0, "BEGIN carries no ACK");
        // Walk to the content (NEWTABLE) and END messages.
        let begin_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let mid_off = begin_len;
        let mid_len = u32::from_ne_bytes(buf[mid_off..mid_off + 4].try_into().unwrap()) as usize;
        // The kernel acks the CONTENT message (not the END marker), so the ACK sits
        // on NEWTABLE — this is what makes a successful batch reply.
        let mid_flags = u16::from_ne_bytes(buf[mid_off + 6..mid_off + 8].try_into().unwrap());
        assert_eq!(
            mid_flags & NLM_F_ACK,
            NLM_F_ACK,
            "content message requests the ack"
        );
        let end_off = mid_off + align4(mid_len);
        assert_eq!(
            &buf[end_off + 4..end_off + 6],
            &NFNL_MSG_BATCH_END.to_ne_bytes(),
            "third message is BATCH_END"
        );
        let end_flags = u16::from_ne_bytes(buf[end_off + 6..end_off + 8].try_into().unwrap());
        assert_eq!(end_flags & NLM_F_ACK, 0, "END carries no ACK");
    }

    #[test]
    fn immediate_verdict_nests_data_then_verdict_then_code() {
        // immediate reg 0 accept — the deepest nesting we build.
        let e = exprs::immediate_verdict(NF_ACCEPT);
        // expr = { NFTA_EXPR_NAME="immediate", NFTA_EXPR_DATA={...} }.
        assert_eq!(&e[4..14], b"immediate\0");
        // The accept code (1) appears big-endian somewhere in the nested data.
        assert!(
            e.windows(4).any(|w| w == NF_ACCEPT.to_be_bytes()),
            "verdict code NF_ACCEPT present big-endian"
        );
    }

    #[test]
    fn parse_rule_extracts_handle_and_userdata() {
        // Craft a minimal NEWRULE body: nfgenmsg is stripped by the caller, so we
        // pass just the attribute section.
        let mut a = Attrs::new();
        a.raw(NFTA_RULE_HANDLE, &42u64.to_be_bytes());
        a.raw(NFTA_RULE_USERDATA, b"dn7:abc");
        let (h, u) = parse_rule(&a.buf).expect("handle present");
        assert_eq!(h, 42);
        assert_eq!(u, b"dn7:abc");
    }
}
