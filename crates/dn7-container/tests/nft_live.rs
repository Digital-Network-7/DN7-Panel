//! Live nftables round-trip against a real kernel — proves the hand-rolled
//! `net::nft` wire format is not just self-consistent (the golden-byte unit
//! tests) but actually ACCEPTED and interpreted correctly by netfilter.
//!
//! Requires root (CAP_NET_ADMIN), so it is `#[ignore]`d in the normal suite; run
//! explicitly as root:
//!   sudo -E cargo test -p dn7-container --test nft_live -- --ignored --nocapture
//! It uses the `nft` binary ONLY to read back + assert the ruleset (test-only).

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use dn7_container::net::config::{PortMap, Proto};
use dn7_container::net::firewall;
use dn7_container::net::ipam::NetworkConfig;

fn nft_list() -> String {
    let out = Command::new("nft")
        .args(["list", "table", "inet", "dn7"])
        .output()
        .expect("run nft");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn table_exists() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", "dn7"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[ignore = "needs root + CAP_NET_ADMIN; run with --ignored as root"]
fn nft_live_roundtrip() {
    // Clean slate (ignore errors — table may not exist).
    let _ = firewall::nuke_table();

    assert!(
        firewall::have_nft(),
        "have_nft() must see a usable subsystem"
    );

    let cfg = NetworkConfig::default_dn7();
    firewall::ensure_base(&cfg).expect("ensure_base must build the table");
    assert!(
        table_exists(),
        "table inet dn7 must exist after ensure_base"
    );

    let base = nft_list();
    println!("---- base ruleset ----\n{base}");
    for needle in [
        "chain postrouting",
        "chain prerouting",
        "chain output",
        "chain forward",
        "masquerade",
    ] {
        assert!(base.contains(needle), "base ruleset missing {needle:?}");
    }

    // Publish a wildcard TCP port 8080 -> container 172.18.0.5:80.
    let ctr = Ipv4Addr::new(172, 18, 0, 5);
    let p = PortMap {
        host_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        host_port: 8080,
        container_port: 80,
        proto: Proto::Tcp,
    };
    firewall::publish_port("testctr", &p, ctr).expect("publish_port");

    let pub_dump = nft_list();
    println!("---- after publish ----\n{pub_dump}");
    for needle in ["dport 8080", "dnat", "172.18.0.5", "dn7:testctr"] {
        assert!(
            pub_dump.contains(needle),
            "published ruleset missing {needle:?}"
        );
    }

    // Teardown removes exactly the tagged rules; base chains remain.
    firewall::teardown_container("testctr").expect("teardown_container");
    let after = nft_list();
    println!("---- after teardown ----\n{after}");
    assert!(
        !after.contains("dn7:testctr"),
        "teardown must remove the tagged rules"
    );
    assert!(
        after.contains("masquerade"),
        "base masquerade must survive teardown"
    );

    // Nuke the whole table.
    firewall::nuke_table().expect("nuke_table");
    assert!(!table_exists(), "nuke_table must remove the table");
}
