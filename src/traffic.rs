//! Per-process network traffic accounting.
//!
//! Reports, per process *name*, how many bytes were sent/received over a recent
//! interval so the backend can keep windowed Top-N rankings. The data source is
//! abstracted behind [`TrafficCollector`] so the implementation can evolve
//! (e.g. an eBPF-backed collector) without touching the report path:
//!
//!   - [`ProcNetCollector`] (Linux): enumerates TCP sockets via the SOCK_DIAG
//!     netlink API to read each socket's cumulative byte counters, and maps
//!     sockets to processes through `/proc/<pid>/fd` (socket inode -> pid ->
//!     process name). Pure Rust, no extra privileges beyond what the agent
//!     already runs with, and works inside containers. Limitations: TCP only
//!     (UDP/raw aren't counted) and very short-lived connections that open and
//!     close entirely within one sample gap may be missed — the numbers are a
//!     close approximation, not exact accounting.
//!   - [`NoopCollector`] (non-Linux / unsupported): returns nothing.
//!
//! A future eBPF collector would implement the same trait and be selected at
//! startup by [`detect_collector`] when the kernel/permissions allow it.

use std::collections::HashMap;

/// Cumulative byte counters for a single process (by name), as last observed.
#[derive(Debug, Clone, Default)]
pub struct ProcCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// A per-process traffic delta over the most recent interval: the bytes
/// sent/received attributed to one process name since the previous sample.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcTrafficDelta {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// A source of cumulative per-process byte counters.
///
/// Implementations return *cumulative* counters keyed by process name; the
/// [`TrafficMonitor`] turns successive snapshots into per-interval deltas.
pub trait TrafficCollector: Send {
    /// A short label identifying the backing mechanism (for diagnostics).
    fn kind(&self) -> &'static str;
    /// Snapshot the current cumulative counters per process name. Aggregates
    /// all of a process's sockets/threads under its name. Best-effort: returns
    /// whatever could be read.
    fn snapshot(&mut self) -> HashMap<String, ProcCounters>;
}

/// Wraps a [`TrafficCollector`] and converts successive cumulative snapshots
/// into per-interval deltas, robust to counter resets (process restart, socket
/// table churn): a counter that goes *backwards* for a name contributes 0 for
/// that tick rather than a huge bogus delta.
pub struct TrafficMonitor {
    collector: Box<dyn TrafficCollector>,
    prev: HashMap<String, ProcCounters>,
}

impl TrafficMonitor {
    /// Build the monitor with the best available collector for this host.
    pub fn new() -> Self {
        TrafficMonitor {
            collector: detect_collector(),
            prev: HashMap::new(),
        }
    }

    /// The active collector's mechanism label (for diagnostics/UI hints).
    pub fn kind(&self) -> &'static str {
        self.collector.kind()
    }

    /// Produce per-process deltas since the previous call. The first call
    /// establishes a baseline and returns an empty list (no prior counters).
    pub fn sample(&mut self) -> Vec<ProcTrafficDelta> {
        let cur = self.collector.snapshot();
        let mut out: Vec<ProcTrafficDelta> = Vec::new();
        if !self.prev.is_empty() {
            for (name, c) in &cur {
                let (drx, dtx) = match self.prev.get(name) {
                    Some(p) => (
                        c.rx_bytes.saturating_sub(p.rx_bytes),
                        c.tx_bytes.saturating_sub(p.tx_bytes),
                    ),
                    // Newly-seen process this tick: its cumulative counter is
                    // its delta (it accrued since we last sampled).
                    None => (c.rx_bytes, c.tx_bytes),
                };
                if drx > 0 || dtx > 0 {
                    out.push(ProcTrafficDelta {
                        name: name.clone(),
                        rx_bytes: drx,
                        tx_bytes: dtx,
                    });
                }
            }
        }
        self.prev = cur;
        out
    }
}

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// A collector that reports nothing — used on non-Linux or when no supported
/// mechanism is available.
pub struct NoopCollector;

impl TrafficCollector for NoopCollector {
    fn kind(&self) -> &'static str {
        "none"
    }
    fn snapshot(&mut self) -> HashMap<String, ProcCounters> {
        HashMap::new()
    }
}

/// Pick the best traffic collector for this host. On Linux this is the
/// proc+netlink collector; elsewhere it's the no-op. A future eBPF collector
/// would be chosen here when supported (and fall back to proc/netlink, then
/// no-op), giving the "B if available, else A" behavior.
pub fn detect_collector() -> Box<dyn TrafficCollector> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::ProcNetCollector::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(NoopCollector)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{ProcCounters, TrafficCollector};
    use std::collections::HashMap;

    /// Linux collector: SOCK_DIAG (TCP) for per-socket byte counters + `/proc`
    /// to map socket inodes to process names.
    pub struct ProcNetCollector;

    impl ProcNetCollector {
        pub fn new() -> Self {
            ProcNetCollector
        }
    }

    impl TrafficCollector for ProcNetCollector {
        fn kind(&self) -> &'static str {
            "proc-netlink"
        }

        fn snapshot(&mut self) -> HashMap<String, ProcCounters> {
            // 1) socket inode -> (rx, tx) cumulative bytes, for IPv4 + IPv6 TCP.
            let mut per_inode: HashMap<u32, (u64, u64)> = HashMap::new();
            for family in [
                netlink_packet_sock_diag::constants::AF_INET,
                netlink_packet_sock_diag::constants::AF_INET6,
            ] {
                if let Err(e) = collect_tcp_bytes(family, &mut per_inode) {
                    tracing::debug!(family, "sock_diag dump failed: {e}");
                }
            }
            if per_inode.is_empty() {
                return HashMap::new();
            }

            // 2) Map socket inodes to pids by scanning /proc/<pid>/fd, then sum
            //    per process name.
            inode_bytes_to_proc_names(&per_inode)
        }
    }

    /// Dump all TCP sockets for `family` via SOCK_DIAG and accumulate each
    /// socket's cumulative (received, acked) byte counters keyed by inode.
    fn collect_tcp_bytes(family: u8, out: &mut HashMap<u32, (u64, u64)>) -> std::io::Result<()> {
        use netlink_packet_core::{
            NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
        };
        use netlink_packet_sock_diag::{
            constants::*,
            inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
            SockDiagMessage,
        };
        use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

        let socket = Socket::new(NETLINK_SOCK_DIAG)?;
        socket.connect(&SocketAddr::new(0, 0))?;

        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        let mut packet = NetlinkMessage::new(
            nl_hdr,
            SockDiagMessage::InetRequest(InetRequest {
                family,
                protocol: IPPROTO_TCP,
                // Request the extended INET_DIAG_INFO (tcp_info) so we get the
                // cumulative bytes_acked / bytes_received counters.
                extensions: ExtensionFlags::INFO,
                states: StateFlags::all(),
                socket_id: if family == AF_INET6 {
                    SocketId::new_v6()
                } else {
                    SocketId::new_v4()
                },
            })
            .into(),
        );
        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];
        packet.serialize(&mut buf[..]);
        socket.send(&buf[..], 0)?;

        let mut recv_buf = vec![0u8; 16 * 1024];
        let mut offset = 0;
        'outer: while let Ok(size) = socket.recv(&mut &mut recv_buf[..], 0) {
            if size == 0 {
                break;
            }
            loop {
                let bytes = &recv_buf[offset..];
                let rx = match <NetlinkMessage<SockDiagMessage>>::deserialize(bytes) {
                    Ok(m) => m,
                    Err(_) => break 'outer,
                };
                match rx.payload {
                    NetlinkPayload::Noop => {}
                    NetlinkPayload::Done(_) => break 'outer,
                    NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                        let inode = resp.header.inode;
                        if inode != 0 {
                            let (rxb, txb) = extract_bytes(&resp);
                            let e = out.entry(inode).or_insert((0, 0));
                            e.0 = e.0.saturating_add(rxb);
                            e.1 = e.1.saturating_add(txb);
                        }
                    }
                    _ => break 'outer,
                }

                let len = rx.header.length as usize;
                if len == 0 {
                    break 'outer;
                }
                offset += len;
                if offset >= size {
                    offset = 0;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Pull (received, acked) cumulative bytes out of a socket's tcp_info NLA.
    fn extract_bytes(resp: &netlink_packet_sock_diag::inet::InetResponse) -> (u64, u64) {
        use netlink_packet_sock_diag::inet::nlas::Nla;
        for nla in resp.nlas.iter() {
            if let Nla::TcpInfo(info) = nla {
                // rx = bytes_received, tx = bytes_acked (delivered outbound).
                return (info.bytes_received, info.bytes_acked);
            }
        }
        (0, 0)
    }

    /// Build a map of socket inode -> owning pid by scanning `/proc/<pid>/fd`
    /// symlinks of the form `socket:[<inode>]`, then fold the per-inode byte
    /// counters into per-process-name totals.
    fn inode_bytes_to_proc_names(
        per_inode: &HashMap<u32, (u64, u64)>,
    ) -> HashMap<String, ProcCounters> {
        let mut out: HashMap<String, ProcCounters> = HashMap::new();
        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return out,
        };
        for entry in proc_dir.flatten() {
            let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue, // not a pid directory
            };
            let fd_dir = entry.path().join("fd");
            let rd = match std::fs::read_dir(&fd_dir) {
                Ok(rd) => rd,
                Err(_) => continue, // process gone or not ours to inspect
            };
            // Collect this pid's matching inode byte totals first.
            let mut rx_sum = 0u64;
            let mut tx_sum = 0u64;
            let mut matched = false;
            for fd in rd.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    if let Some(inode) = parse_socket_inode(&target.to_string_lossy()) {
                        if let Some((rxb, txb)) = per_inode.get(&inode) {
                            rx_sum = rx_sum.saturating_add(*rxb);
                            tx_sum = tx_sum.saturating_add(*txb);
                            matched = true;
                        }
                    }
                }
            }
            if !matched {
                continue;
            }
            let name = process_name(pid);
            let e = out.entry(name).or_default();
            e.rx_bytes = e.rx_bytes.saturating_add(rx_sum);
            e.tx_bytes = e.tx_bytes.saturating_add(tx_sum);
        }
        out
    }

    /// Parse the inode out of a `socket:[12345]` symlink target.
    fn parse_socket_inode(link: &str) -> Option<u32> {
        let rest = link.strip_prefix("socket:[")?;
        let num = rest.strip_suffix(']')?;
        num.parse().ok()
    }

    /// Resolve a process's display name: prefer `/proc/<pid>/comm` (the thread
    /// name), falling back to the first arg of `cmdline`, then `pid <n>`.
    fn process_name(pid: u32) -> String {
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            let t = comm.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
        if let Ok(cmd) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            // cmdline is NUL-separated; take argv[0]'s basename.
            if let Some(first) = cmd.split(|b| *b == 0).find(|s| !s.is_empty()) {
                let s = String::from_utf8_lossy(first);
                let base = s.rsplit('/').next().unwrap_or(&s);
                if !base.is_empty() {
                    return base.to_string();
                }
            }
        }
        format!("pid {pid}")
    }

    #[cfg(test)]
    mod tests {
        use super::parse_socket_inode;

        #[test]
        fn parses_socket_inode_link() {
            assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
            assert_eq!(parse_socket_inode("socket:[0]"), Some(0));
            assert_eq!(parse_socket_inode("pipe:[999]"), None);
            assert_eq!(parse_socket_inode("/dev/null"), None);
            assert_eq!(parse_socket_inode("socket:[abc]"), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted collector returning preset cumulative snapshots, to test the
    /// monitor's delta logic without touching the OS.
    struct ScriptedCollector {
        snaps: Vec<HashMap<String, ProcCounters>>,
        idx: usize,
    }
    impl TrafficCollector for ScriptedCollector {
        fn kind(&self) -> &'static str {
            "scripted"
        }
        fn snapshot(&mut self) -> HashMap<String, ProcCounters> {
            let s = self.snaps.get(self.idx).cloned().unwrap_or_default();
            self.idx += 1;
            s
        }
    }

    fn counters(rx: u64, tx: u64) -> ProcCounters {
        ProcCounters {
            rx_bytes: rx,
            tx_bytes: tx,
        }
    }

    #[test]
    fn first_sample_is_baseline_then_deltas() {
        let snaps = vec![
            HashMap::from([("nginx".to_string(), counters(100, 50))]),
            HashMap::from([("nginx".to_string(), counters(300, 90))]),
        ];
        let mut mon = TrafficMonitor {
            collector: Box::new(ScriptedCollector { snaps, idx: 0 }),
            prev: HashMap::new(),
        };
        // First call: baseline, empty.
        assert!(mon.sample().is_empty());
        // Second call: delta = (200, 40).
        let d = mon.sample();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "nginx");
        assert_eq!(d[0].rx_bytes, 200);
        assert_eq!(d[0].tx_bytes, 40);
    }

    #[test]
    fn counter_reset_yields_zero_not_garbage() {
        // A process whose counter goes backwards (restart) contributes 0.
        let snaps = vec![
            HashMap::from([("api".to_string(), counters(1000, 1000))]),
            HashMap::from([("api".to_string(), counters(10, 10))]),
        ];
        let mut mon = TrafficMonitor {
            collector: Box::new(ScriptedCollector { snaps, idx: 0 }),
            prev: HashMap::new(),
        };
        assert!(mon.sample().is_empty()); // baseline
        let d = mon.sample();
        // saturating_sub => 0,0 => filtered out entirely.
        assert!(d.is_empty());
    }

    #[test]
    fn newly_seen_process_counts_full_counter() {
        let snaps = vec![
            HashMap::from([("a".to_string(), counters(5, 5))]),
            HashMap::from([
                ("a".to_string(), counters(5, 5)),
                ("b".to_string(), counters(70, 30)),
            ]),
        ];
        let mut mon = TrafficMonitor {
            collector: Box::new(ScriptedCollector { snaps, idx: 0 }),
            prev: HashMap::new(),
        };
        assert!(mon.sample().is_empty()); // baseline
        let d = mon.sample();
        // "a" unchanged => filtered; "b" new => full (70,30).
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "b");
        assert_eq!(d[0].rx_bytes, 70);
        assert_eq!(d[0].tx_bytes, 30);
    }
}
