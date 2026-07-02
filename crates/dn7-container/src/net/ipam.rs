//! IP address management. Each network has a flock'd JSON lease table — leases
//! are the source of truth; the free set is derived. Leases live on tmpfs
//! (`/run`) so a reboot clears them along with the netns + nft rules.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::net::config::mac_for;

pub const DEFAULT_NETWORK: &str = "dn7";
pub const DEFAULT_BRIDGE: &str = "dn7br0";

/// A managed network: its bridge, subnet, and gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub bridge: String,
    pub subnet: Ipv4Net,
    pub gateway: Ipv4Addr,
}

impl NetworkConfig {
    /// The built-in default network (`dn7`, `172.18.0.0/24`, gw `.1`) — `172.18`
    /// avoids Docker's default `172.17`.
    pub fn default_dn7() -> NetworkConfig {
        NetworkConfig {
            name: DEFAULT_NETWORK.to_string(),
            bridge: DEFAULT_BRIDGE.to_string(),
            subnet: "172.18.0.0/24".parse().expect("valid CIDR"),
            gateway: Ipv4Addr::new(172, 18, 0, 1),
        }
    }
}

/// All managed networks. Currently just the built-in default; user-defined
/// networks (persisted under the var root) plug in here later.
pub fn list_networks() -> Vec<NetworkConfig> {
    vec![NetworkConfig::default_dn7()]
}

/// One allocated address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub container_id: String,
    pub pid: i32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LeaseTable {
    leases: Vec<Lease>,
}

/// IP allocator over per-network lease tables. `run_root` holds the (tmpfs)
/// leases; `var_root` is reserved for persistent network configs (P5b+).
pub struct Ipam {
    run_root: PathBuf,
    #[allow(dead_code)] // used once persistent user-defined networks land (P5e)
    var_root: PathBuf,
}

impl Default for Ipam {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipam {
    pub fn new() -> Ipam {
        Ipam {
            run_root: PathBuf::from("/run/dn7-container/_ipam"),
            var_root: PathBuf::from("/var/lib/dn7-container/networks"),
        }
    }

    #[cfg(test)]
    pub fn with_roots(run_root: PathBuf, var_root: PathBuf) -> Ipam {
        Ipam { run_root, var_root }
    }

    /// Allocate an address for `container_id` in `cfg`'s subnet, skipping the
    /// network/broadcast (via `hosts()`) and the gateway. Idempotent: an existing
    /// lease for the id is returned unchanged.
    pub fn allocate(&self, cfg: &NetworkConfig, container_id: &str, pid: i32) -> Result<Lease> {
        let _guard = self.lock(&cfg.name)?;
        let mut table = self.load(&cfg.name)?;

        if let Some(existing) = table.leases.iter().find(|l| l.container_id == container_id) {
            return Ok(existing.clone());
        }

        let used: HashSet<Ipv4Addr> = table.leases.iter().map(|l| l.ip).collect();
        let ip = cfg
            .subnet
            .hosts()
            .find(|ip| *ip != cfg.gateway && !used.contains(ip))
            .ok_or_else(|| Error::Other(format!("network {} is exhausted", cfg.name)))?;

        let lease = Lease {
            ip,
            mac: mac_for(ip),
            container_id: container_id.to_string(),
            pid,
        };
        table.leases.push(lease.clone());
        self.save(&cfg.name, &table)?;
        Ok(lease)
    }

    /// Release `container_id`'s lease (no-op if absent).
    pub fn free(&self, net: &str, container_id: &str) -> Result<()> {
        let _guard = self.lock(net)?;
        let mut table = self.load(net)?;
        let before = table.leases.len();
        table.leases.retain(|l| l.container_id != container_id);
        if table.leases.len() != before {
            self.save(net, &table)?;
        }
        Ok(())
    }

    /// Drop leases whose pid is no longer live (crash/leak reconciliation).
    /// Returns the number reclaimed.
    pub fn reclaim_dead(&self, net: &str, is_live: impl Fn(i32) -> bool) -> Result<usize> {
        Ok(self.reap(net, is_live)?.len())
    }

    /// Like `reclaim_dead`, but returns the removed leases (so the caller can tear
    /// down their veth / firewall rules too).
    pub fn reap(&self, net: &str, is_live: impl Fn(i32) -> bool) -> Result<Vec<Lease>> {
        let _guard = self.lock(net)?;
        let mut table = self.load(net)?;
        let mut dead = Vec::new();
        table.leases.retain(|l| {
            if is_live(l.pid) {
                true
            } else {
                dead.push(l.clone());
                false
            }
        });
        if !dead.is_empty() {
            self.save(net, &table)?;
        }
        Ok(dead)
    }

    fn net_dir(&self, net: &str) -> PathBuf {
        self.run_root.join(net)
    }

    fn load(&self, net: &str) -> Result<LeaseTable> {
        let p = self.net_dir(net).join("leases.json");
        match fs::read(&p) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(Error::Json),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LeaseTable::default()),
            Err(e) => Err(Error::Io { path: p, source: e }),
        }
    }

    fn save(&self, net: &str, table: &LeaseTable) -> Result<()> {
        let dir = self.net_dir(net);
        let p = dir.join("leases.json");
        let tmp = dir.join("leases.json.tmp");
        let json = serde_json::to_vec_pretty(table)?;
        // Write-then-rename so a crash mid-write can't leave a truncated lease
        // table (which would leak or double-allocate container IPs).
        fs::write(&tmp, &json).map_err(Error::io(&tmp))?;
        if let Err(e) = fs::rename(&tmp, &p) {
            let _ = fs::remove_file(&tmp);
            return Err(Error::io(&p)(e));
        }
        Ok(())
    }

    /// Hold an exclusive advisory lock for `net` (auto-released when the returned
    /// guard's file is dropped). Serialises allocate/free across processes.
    fn lock(&self, net: &str) -> Result<FlockGuard> {
        let dir = self.net_dir(net);
        fs::create_dir_all(&dir).map_err(Error::io(&dir))?;
        let lp = dir.join(".lock");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lp)
            .map_err(Error::io(&lp))?;
        // SAFETY: flock on a valid, owned fd; blocks until the lock is acquired.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(Error::io(&lp)(std::io::Error::last_os_error()));
        }
        Ok(FlockGuard { _file: file })
    }
}

/// Releases the flock by closing the lock file on drop.
struct FlockGuard {
    _file: File,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn temp_ipam() -> (Ipam, PathBuf) {
        static N: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir().join(format!(
            "dn7ipam-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let run = base.join("run");
        let var = base.join("var");
        (Ipam::with_roots(run, var), base)
    }

    fn net30() -> NetworkConfig {
        NetworkConfig {
            name: "t30".into(),
            bridge: "dn7t0".into(),
            subnet: "10.9.0.0/30".parse().unwrap(), // hosts: .1 (gw), .2 — one usable
            gateway: Ipv4Addr::new(10, 9, 0, 1),
        }
    }

    #[test]
    fn allocates_from_dot2_skipping_gateway() {
        let (ipam, dir) = temp_ipam();
        let cfg = NetworkConfig::default_dn7();
        let a = ipam.allocate(&cfg, "c1", 100).unwrap();
        let b = ipam.allocate(&cfg, "c2", 101).unwrap();
        assert_eq!(a.ip, Ipv4Addr::new(172, 18, 0, 2));
        assert_eq!(b.ip, Ipv4Addr::new(172, 18, 0, 3));
        assert_ne!(a.ip, cfg.gateway);
        assert_eq!(a.mac, "02:42:ac:12:00:02");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn allocation_is_idempotent_per_container() {
        let (ipam, dir) = temp_ipam();
        let cfg = NetworkConfig::default_dn7();
        let a = ipam.allocate(&cfg, "c1", 1).unwrap();
        let again = ipam.allocate(&cfg, "c1", 1).unwrap();
        assert_eq!(a.ip, again.ip);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn free_then_realloc_reuses_address() {
        let (ipam, dir) = temp_ipam();
        let cfg = NetworkConfig::default_dn7();
        let a = ipam.allocate(&cfg, "c1", 1).unwrap();
        ipam.free(&cfg.name, "c1").unwrap();
        let b = ipam.allocate(&cfg, "c2", 2).unwrap();
        assert_eq!(a.ip, b.ip, "freed address should be reused");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn exhaustion_errors() {
        let (ipam, dir) = temp_ipam();
        let cfg = net30();
        let _ = ipam.allocate(&cfg, "c1", 1).unwrap(); // takes the one usable host (.2)
        assert!(ipam.allocate(&cfg, "c2", 2).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reclaim_drops_dead_pids() {
        let (ipam, dir) = temp_ipam();
        let cfg = NetworkConfig::default_dn7();
        ipam.allocate(&cfg, "live", 1).unwrap();
        ipam.allocate(&cfg, "dead", 2).unwrap();
        let removed = ipam.reclaim_dead(&cfg.name, |pid| pid == 1).unwrap();
        assert_eq!(removed, 1);
        // The dead one's address frees up for reuse.
        let realloc = ipam.allocate(&cfg, "new", 3).unwrap();
        assert_eq!(realloc.ip, Ipv4Addr::new(172, 18, 0, 3));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_allocations_are_unique() {
        let (ipam, dir) = temp_ipam();
        let ipam = Arc::new(ipam);
        let cfg = Arc::new(NetworkConfig::default_dn7());
        let mut handles = Vec::new();
        for i in 0..20 {
            let ipam = Arc::clone(&ipam);
            let cfg = Arc::clone(&cfg);
            handles.push(std::thread::spawn(move || {
                ipam.allocate(&cfg, &format!("c{i}"), i).unwrap().ip
            }));
        }
        let ips: HashSet<Ipv4Addr> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(ips.len(), 20, "flock must prevent duplicate allocations");
        let _ = fs::remove_dir_all(&*dir);
    }
}
