//! User-defined network registry: persistent bridge-network configs on the var
//! root, layered over the built-in `dn7` default. Each network is one JSON file
//! (`<var_root>/<name>.json`) holding its bridge/subnet/gateway. The built-in
//! `dn7` network is synthetic (never stored) and can't be removed or renamed.
//!
//! A network's host bridge name is derived from `sha256(name)` (not the raw name)
//! so it always fits Linux's 15-char IFNAMSIZ and can't inject into netlink.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ipnet::Ipv4Net;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::net::backend;
use crate::net::ipam::{Ipam, NetworkConfig, DEFAULT_BRIDGE, DEFAULT_NETWORK};

const VAR_ROOT: &str = "/var/lib/dn7-container/networks";

/// Names reserved for the built-in modes / default network.
const RESERVED: &[&str] = &[DEFAULT_NETWORK, "bridge", "host", "none", "default"];

fn root() -> PathBuf {
    PathBuf::from(VAR_ROOT)
}

fn config_path(name: &str) -> PathBuf {
    root().join(format!("{name}.json"))
}

/// Deterministic host bridge name for a user network: `dn7br` + 9 hex of
/// `sha256(name)` → 14 chars, within IFNAMSIZ. The default network keeps its
/// well-known `dn7br0`.
fn bridge_for(name: &str) -> String {
    let d = Sha256::digest(name.as_bytes());
    let hex: String = d.iter().take(5).map(|b| format!("{b:02x}")).collect();
    format!("dn7br{}", &hex[..9])
}

/// Validate a user network name: `[a-z0-9][a-z0-9_.-]{0,31}`, and not reserved.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = (1..=32).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        });
    if !ok {
        return Err(Error::Other(format!(
            "invalid network name {name:?} (use a-z 0-9 _ . -, ≤32 chars)"
        )));
    }
    if RESERVED.contains(&name) {
        return Err(Error::Other(format!("network name {name:?} is reserved")));
    }
    Ok(())
}

/// Resolve a network name to its config: the built-in default for
/// `dn7`/`bridge`/empty, otherwise a stored user network. Errors if unknown.
pub fn resolve(name: &str) -> Result<NetworkConfig> {
    if name.is_empty() || name == DEFAULT_NETWORK || name == "bridge" {
        return Ok(NetworkConfig::default_dn7());
    }
    load_user(name).ok_or_else(|| Error::Other(format!("no such network: {name}")))
}

fn load_user(name: &str) -> Option<NetworkConfig> {
    let bytes = std::fs::read(config_path(name)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Every known network (built-in default first, then user networks by name).
pub fn all() -> Vec<NetworkConfig> {
    let mut nets = vec![NetworkConfig::default_dn7()];
    if let Ok(rd) = std::fs::read_dir(root()) {
        let mut users: Vec<NetworkConfig> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| std::fs::read(e.path()).ok())
            .filter_map(|b| serde_json::from_slice::<NetworkConfig>(&b).ok())
            .collect();
        users.sort_by(|a, b| a.name.cmp(&b.name));
        nets.extend(users);
    }
    nets
}

/// Whether `name` is the immutable built-in network.
pub fn is_builtin(name: &str) -> bool {
    name == DEFAULT_NETWORK || name == "bridge" || name == DEFAULT_BRIDGE
}

/// Create a user-defined bridge network: validate, reject a name/subnet clash,
/// persist the config, and bring up the host bridge. `subnet` must be a private
/// IPv4 CIDR; `gateway` (if `None`) defaults to the subnet's first host.
pub fn create(name: &str, subnet: Ipv4Net, gateway: Option<Ipv4Addr>) -> Result<NetworkConfig> {
    validate_name(name)?;
    if config_path(name).exists() {
        return Err(Error::Other(format!("network {name} already exists")));
    }
    let subnet = subnet.trunc(); // normalize to the network address
    if subnet.prefix_len() > 30 || subnet.prefix_len() < 8 {
        return Err(Error::Other(
            "subnet prefix must be between /8 and /30".into(),
        ));
    }
    let gw = match gateway {
        Some(g) => {
            if !subnet.contains(&g) {
                return Err(Error::Other(format!(
                    "gateway {g} is not inside subnet {subnet}"
                )));
            }
            g
        }
        None => subnet
            .hosts()
            .next()
            .ok_or_else(|| Error::Other("subnet has no usable host address".into()))?,
    };
    // Reject overlap with an existing network's subnet.
    for other in all() {
        if other.subnet.trunc() == subnet
            || other.subnet.contains(&gw)
            || subnet.contains(&other.gateway)
        {
            return Err(Error::Other(format!(
                "subnet {subnet} overlaps existing network {}",
                other.name
            )));
        }
    }
    let cfg = NetworkConfig {
        name: name.to_string(),
        bridge: bridge_for(name),
        subnet,
        gateway: gw,
    };
    std::fs::create_dir_all(root()).map_err(Error::io(root()))?;
    write_config(&cfg)?;
    // Bring the bridge up now so it exists even before the first container.
    backend::ensure_bridge(&cfg)?;
    Ok(cfg)
}

/// Remove a user network: refuse the built-in, refuse if any container still
/// holds a lease on it, then delete the bridge + the config file.
pub fn remove(name: &str) -> Result<()> {
    if is_builtin(name) {
        return Err(Error::Other("the built-in network can't be removed".into()));
    }
    let cfg = load_user(name).ok_or_else(|| Error::Other(format!("no such network: {name}")))?;
    let in_use = Ipam::new().active_leases(name);
    if in_use > 0 {
        return Err(Error::Other(format!(
            "network {name} still has {in_use} attached container(s)"
        )));
    }
    let _ = backend::delete_bridge(&cfg.bridge);
    let _ = Ipam::new().drop_table(name);
    std::fs::remove_file(config_path(name)).map_err(Error::io(config_path(name)))?;
    Ok(())
}

/// Rename a user network: move its config + carry the lease table across. The
/// bridge is renamed in place (its interface name is derived from the network
/// name, so it changes). Refuses the built-in and a clash with an existing name.
pub fn rename(old: &str, new: &str) -> Result<()> {
    if is_builtin(old) {
        return Err(Error::Other("the built-in network can't be renamed".into()));
    }
    validate_name(new)?;
    let mut cfg = load_user(old).ok_or_else(|| Error::Other(format!("no such network: {old}")))?;
    if config_path(new).exists() {
        return Err(Error::Other(format!("network {new} already exists")));
    }
    let old_bridge = cfg.bridge.clone();
    cfg.name = new.to_string();
    cfg.bridge = bridge_for(new);
    // Rename the live bridge interface (best-effort — it may not exist yet).
    let _ = backend::rename_bridge(&old_bridge, &cfg.bridge);
    write_config(&cfg)?;
    let _ = std::fs::remove_file(config_path(old));
    let _ = Ipam::new().rename_table(old, new);
    Ok(())
}

fn write_config(cfg: &NetworkConfig) -> Result<()> {
    let p = config_path(&cfg.name);
    let tmp = p.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(cfg)
        .map_err(|e| Error::Other(format!("serialize network: {e}")))?;
    std::fs::write(&tmp, &json).map_err(Error::io(&tmp))?;
    std::fs::rename(&tmp, &p).map_err(Error::io(&p))?;
    Ok(())
}

/// Parse a `subnet`/`gateway` request into a validated CIDR + optional gateway.
pub fn parse_subnet(subnet: &str, gateway: &str) -> Result<(Ipv4Net, Option<Ipv4Addr>)> {
    let net: Ipv4Net = subnet
        .trim()
        .parse()
        .map_err(|_| Error::Other(format!("invalid subnet CIDR: {subnet:?}")))?;
    let gw = if gateway.trim().is_empty() {
        None
    } else {
        Some(
            gateway
                .trim()
                .parse()
                .map_err(|_| Error::Other(format!("invalid gateway IP: {gateway:?}")))?,
        )
    };
    Ok((net, gw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_name_fits_ifnamsiz_and_is_stable() {
        let b = bridge_for("my-net");
        assert!(b.len() <= 15, "{b} must fit IFNAMSIZ");
        assert!(b.starts_with("dn7br"));
        assert_eq!(b, bridge_for("my-net"));
        assert_ne!(b, bridge_for("my-net2"));
    }

    #[test]
    fn name_validation_and_reserved() {
        assert!(validate_name("mynet").is_ok());
        assert!(validate_name("app_net.1-2").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("-x").is_err());
        assert!(validate_name("Up").is_err());
        assert!(validate_name("dn7").is_err()); // reserved
        assert!(validate_name("host").is_err());
    }

    #[test]
    fn resolve_builtin() {
        assert_eq!(resolve("dn7").unwrap().name, "dn7");
        assert_eq!(resolve("bridge").unwrap().name, "dn7");
        assert_eq!(resolve("").unwrap().name, "dn7");
        assert!(resolve("nope").is_err());
    }

    #[test]
    fn parse_subnet_forms() {
        let (n, g) = parse_subnet("172.20.0.0/24", "").unwrap();
        assert_eq!(n.to_string(), "172.20.0.0/24");
        assert!(g.is_none());
        let (_, g) = parse_subnet("10.5.0.0/16", "10.5.0.1").unwrap();
        assert_eq!(g.unwrap().to_string(), "10.5.0.1");
        assert!(parse_subnet("notacidr", "").is_err());
    }
}
