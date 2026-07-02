use super::*;

#[test]
fn host_tokens_split_and_overlap_detect() {
    // Tokenized, lowercased, whitespace-split.
    let a = host_tokens("A.com  b.com");
    assert!(a.contains("a.com"));
    assert!(a.contains("b.com"));
    // Per-host overlap: two multi-host server_names sharing one host overlap.
    let b = host_tokens("b.com c.com");
    assert!(a.iter().any(|h| b.contains(h)), "b.com overlaps");
    // No overlap when fully disjoint.
    let c = host_tokens("x.com y.com");
    assert!(!a.iter().any(|h| c.contains(h)));
    // Empty input → no tokens.
    assert!(host_tokens("   ").is_empty());
}

#[test]
fn server_name_validation() {
    assert!(valid_server_name("example.com"));
    assert!(valid_server_name("a.example.com www.example.com"));
    assert!(valid_server_name("*.example.com"));
    assert!(valid_server_name("_"));
    assert!(!valid_server_name(""));
    assert!(!valid_server_name("bad;name"));
    assert!(!valid_server_name("a/b"));
}

#[test]
fn host_token_validation() {
    assert!(valid_host_token("10.0.0.5"));
    assert!(valid_host_token("backend:3000"));
    assert!(valid_host_token("svc.local"));
    assert!(!valid_host_token("http://x"));
    assert!(!valid_host_token("a b"));
    assert!(!valid_host_token("a;b"));
}

#[test]
fn container_and_root_validation() {
    assert!(valid_container_name("app"));
    assert!(!valid_container_name("-app"));
    assert!(!valid_container_name("a b"));
    assert!(valid_root_segment("site1"));
    assert!(!valid_root_segment(".."));
    assert!(!valid_root_segment("a/b"));
}

#[test]
fn local_static_root_denies_sensitive_trees() {
    assert!(local_root_denied(std::path::Path::new("/")));
    assert!(local_root_denied(std::path::Path::new("/etc")));
    assert!(local_root_denied(std::path::Path::new("/etc/nginx")));
    assert!(local_root_denied(std::path::Path::new("/root/.ssh")));
    assert!(local_root_denied(std::path::Path::new("/proc/self")));
    assert!(!local_root_denied(std::path::Path::new("/var/www")));
    assert!(!local_root_denied(std::path::Path::new(
        "/usr/share/nginx/html"
    )));
}

#[test]
fn cert_name_validation() {
    assert!(valid_cert_name("mysite-2026"));
    assert!(valid_cert_name("a.b_c"));
    assert!(!valid_cert_name(""));
    assert!(!valid_cert_name(".."));
    assert!(!valid_cert_name("a/b"));
    assert!(!valid_cert_name("a b"));
}

#[test]
fn location_path_validation() {
    assert!(valid_location_path("/api"));
    assert!(valid_location_path("/"));
    assert!(valid_location_path("/a/b-c_d"));
    assert!(!valid_location_path("api")); // must start with /
    assert!(!valid_location_path("/a b"));
    assert!(!valid_location_path("/a;b"));
}

#[test]
fn sanitize_rel_rejects_traversal() {
    assert!(sanitize_rel("a/b/c.html").is_some());
    assert!(sanitize_rel("../etc/passwd").is_none());
    assert!(sanitize_rel("a/../../b").is_none());
    assert!(sanitize_rel("").is_none());
    assert_eq!(
        sanitize_rel("./x/./y.js").unwrap(),
        std::path::PathBuf::from("x/y.js")
    );
}

#[test]
fn zip_entry_copy_enforces_unpacked_limit() {
    let mut src = std::io::Cursor::new(vec![1u8; 16]);
    let mut out = Vec::new();
    assert_eq!(copy_zip_entry_limited(&mut src, &mut out, 16).unwrap(), 16);
    assert_eq!(out.len(), 16);

    let mut src = std::io::Cursor::new(vec![1u8; 17]);
    let mut out = Vec::new();
    assert!(copy_zip_entry_limited(&mut src, &mut out, 16).is_err());
}

#[test]
fn htpasswd_is_apr1_and_matches_known_vector() {
    // Format + salt round-trip: re-hashing with the embedded salt is stable.
    let h = dn7_edge::htpasswd_hash("s3cret");
    assert!(h.starts_with("$apr1$"), "expected an apr1 hash, got {h}");
    let salt = h.trim_start_matches("$apr1$").split('$').next().unwrap();
    assert_eq!(dn7_edge::apr1_with_salt("s3cret", salt), h);
    assert_ne!(dn7_edge::apr1_with_salt("wrong", salt), h);
    // Known apr1 vector (matches Apache htpasswd / openssl passwd -apr1).
    assert_eq!(
        dn7_edge::apr1_with_salt("myPassword", "r31....."),
        "$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/"
    );
}

#[test]
fn access_validators() {
    assert!(valid_access_name("Internal only"));
    assert!(!valid_access_name(""));
    assert!(!valid_access_name("bad\"quote"));
    assert!(valid_auth_username("bob.smith_1"));
    assert!(!valid_auth_username("has:colon"));
    assert!(valid_client_address("all"));
    assert!(valid_client_address("192.168.0.0/16"));
    assert!(valid_client_address("2001:db8::/32"));
    assert!(!valid_client_address("1.2.3.4; rm -rf"));
}

#[test]
fn trusted_cidrs_sanitize() {
    // Valid IPs / CIDRs, normalized to a space-separated list.
    assert_eq!(
        sanitize_trusted_cidrs("10.0.0.0/8, 203.0.113.5").unwrap(),
        "10.0.0.0/8 203.0.113.5"
    );
    assert_eq!(
        sanitize_trusted_cidrs("2001:db8::/32").unwrap(),
        "2001:db8::/32"
    );
    // Empty stays empty (caller falls back to the safe private-range default).
    assert_eq!(sanitize_trusted_cidrs("   ").unwrap(), "");
    // Malformed address / prefix / injection attempts are rejected.
    assert!(sanitize_trusted_cidrs("999.1.1.1").is_err());
    assert!(sanitize_trusted_cidrs("10.0.0.0/40").is_err());
    assert!(sanitize_trusted_cidrs("1.2.3.4; rm -rf /").is_err());
}

// (the `ss_pids` parser test was removed with the ss shell-out — PID-on-port
// detection is now the pure-Rust /proc parser `proc_pids_on_port`.)
