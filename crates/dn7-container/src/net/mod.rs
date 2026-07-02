//! Container networking (P5). See `docs/P5-networking-plan.md`.
//!
//! Modes (from the bundle's `dn7.net` annotation): `bridge` (veth onto the shared
//! `dn7br0`, with an IPAM address + default route), `none` (isolated netns, `lo`
//! up only), `host` (recorded no-op for now). An absent annotation leaves the
//! netns unmanaged (the pre-P5 behavior).
//!
//! All wiring runs parent-side while the container init is parked on the
//! cgroup-sync pipe, so the container's first instruction sees a fully-wired
//! `eth0` and never touches host networking itself (no `CAP_NET_ADMIN`).

pub mod backend;
pub mod config;
pub mod dns;
pub mod firewall;
pub mod ipam;
mod nft;
pub mod nl;

pub use config::{NetState, PortMap, Proto};
pub use ipam::{Ipam, NetworkConfig};

use crate::error::{Error, Result};
use crate::oci::spec::Spec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Bridge,
    None,
    Host,
}

/// Is `pid` still a live process? (Local copy so `net` doesn't depend on the
/// Linux-gated `container` module.)
fn pid_alive(pid: i32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    !matches!(kill(Pid::from_raw(pid), None), Err(nix::Error::ESRCH))
}

/// Orchestrates per-container network setup and teardown.
#[derive(Default)]
pub struct NetworkManager;

impl NetworkManager {
    pub fn new() -> NetworkManager {
        NetworkManager
    }

    /// Read the requested mode from the spec's `dn7.net` annotation.
    fn mode_of(spec: &Spec) -> Result<Option<NetMode>> {
        match spec.annotations.get("dn7.net").map(String::as_str) {
            None => Ok(None),
            Some("bridge") => Ok(Some(NetMode::Bridge)),
            Some("none") => Ok(Some(NetMode::None)),
            Some("host") => Ok(Some(NetMode::Host)),
            Some(other) => Err(Error::Other(format!("unknown dn7.net mode: {other}"))),
        }
    }

    /// Wire networking for `pid`'s container (the netns must already exist).
    /// Returns the receipt to persist, or `None` if the bundle didn't request
    /// managed networking. Fail-closed: any error tears down partial state.
    pub fn apply(&self, id: &str, pid: i32, spec: &Spec) -> Result<Option<NetState>> {
        let Some(mode) = Self::mode_of(spec)? else {
            return Ok(None);
        };
        config::validate_id(id)?;
        let ports = match spec.annotations.get("dn7.ports") {
            Some(s) => config::parse_ports(s)?,
            None => Vec::new(),
        };
        let result = self.apply_mode(id, pid, mode, &ports);
        if result.is_err() {
            self.teardown_by_id(id);
        }
        result.map(Some)
    }

    fn apply_mode(&self, id: &str, pid: i32, mode: NetMode, ports: &[PortMap]) -> Result<NetState> {
        match mode {
            NetMode::Host => Ok(NetState {
                mode: "host".into(),
                network: String::new(),
                bridge: String::new(),
                veth_host: String::new(),
                ip: None,
                mac: None,
                ports: Vec::new(),
            }),
            NetMode::None => {
                backend::lo_up(pid)?;
                Ok(NetState {
                    mode: "none".into(),
                    network: String::new(),
                    bridge: String::new(),
                    veth_host: String::new(),
                    ip: None,
                    mac: None,
                    ports: Vec::new(),
                })
            }
            NetMode::Bridge => self.apply_bridge(id, pid, ports),
        }
    }

    fn apply_bridge(&self, id: &str, pid: i32, ports: &[PortMap]) -> Result<NetState> {
        let cfg = NetworkConfig::default_dn7();
        let ipam = Ipam::new();
        let lease = ipam.allocate(&cfg, id, pid)?;

        let host = config::veth_host_name(id);
        let peer = config::veth_peer_name(id);

        backend::ensure_bridge(&cfg)?;
        backend::make_veth(&host, &peer)?;
        backend::attach_to_bridge(&host, &cfg.bridge)?;
        backend::move_peer(&peer, pid)?;
        backend::config_inside(
            pid,
            &peer,
            lease.ip,
            cfg.subnet.prefix_len(),
            cfg.gateway,
            &lease.mac,
        )?;

        // Outbound NAT + published ports. Best-effort on NAT (a container without
        // `nft` still has bridge/gateway connectivity); published ports require
        // `nft`, so a port request without it is a hard error.
        let mut published = Vec::new();
        if firewall::have_nft() {
            firewall::ensure_base(&cfg)?;
            for p in ports {
                firewall::publish_port(id, p, lease.ip)?;
                published.push(p.clone());
            }
        } else if ports.is_empty() {
            eprintln!("dn7-container: nft not found — container has no outbound NAT (internet)");
        } else {
            return Err(Error::Other(
                "publishing ports needs `nft` (nftables)".into(),
            ));
        }

        Ok(NetState {
            mode: "bridge".into(),
            network: cfg.name,
            bridge: cfg.bridge,
            veth_host: host,
            ip: Some(lease.ip),
            mac: Some(lease.mac),
            ports: published,
        })
    }

    /// Tear down a container's networking from its receipt. Idempotent. Order:
    /// published-port DNAT first (stop inbound traffic), then the veth, then the
    /// IP lease. The shared bridge + base NAT table are left intact.
    pub fn teardown(&self, id: &str, state: &NetState) {
        if state.mode == "bridge" {
            let _ = firewall::teardown_container(id);
            let _ = backend::teardown_veth(&state.veth_host);
            let net = if state.network.is_empty() {
                ipam::DEFAULT_NETWORK
            } else {
                &state.network
            };
            let _ = Ipam::new().free(net, id);
        }
    }

    /// Reconcile leaked resources: free every lease whose pid is dead, removing
    /// its veth + DNAT rules. Returns the number reclaimed. (`dn7crun net gc`.)
    pub fn gc(&self) -> Result<usize> {
        let ipam = Ipam::new();
        let dead = ipam.reap(ipam::DEFAULT_NETWORK, pid_alive)?;
        for lease in &dead {
            let _ = firewall::teardown_container(&lease.container_id);
            let _ = backend::teardown_veth(&config::veth_host_name(&lease.container_id));
        }
        Ok(dead.len())
    }

    /// Best-effort teardown when we only know the id (apply-failure rollback):
    /// re-derive the names and release any lease + DNAT rules.
    fn teardown_by_id(&self, id: &str) {
        let _ = firewall::teardown_container(id);
        let _ = backend::teardown_veth(&config::veth_host_name(id));
        let _ = Ipam::new().free(ipam::DEFAULT_NETWORK, id);
    }
}
