use super::*;

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
fn cert_name_validation() {
    assert!(valid_cert_name("mysite-2026"));
    assert!(valid_cert_name("a.b_c"));
    assert!(!valid_cert_name(""));
    assert!(!valid_cert_name(".."));
    assert!(!valid_cert_name("a/b"));
    assert!(!valid_cert_name("a b"));
}

#[test]
fn with_port_defaults_80() {
    assert_eq!(with_scheme_port("host", "http"), "host:80");
    assert_eq!(with_scheme_port("host:8080", "http"), "host:8080");
    assert_eq!(with_scheme_port("host", "https"), "host:443");
}

fn lo_test() -> Layout {
    Layout {
        confd: std::path::PathBuf::from("/tmp/dn7-test-confd"),
        cert_ref: "/tmp/dn7-test-certs".into(),
        www_ref: "/tmp/dn7-test-www".into(),
        cert_store: std::path::PathBuf::from("/tmp/dn7-test-certs"),
        www_store: std::path::PathBuf::from("/tmp/dn7-test-www"),
    }
}

fn mk_site(kind: &str, ssl: bool) -> Site {
    Site {
        id: "s1".into(),
        server_name: "example.com".into(),
        kind: kind.into(),
        target_url: "10.0.0.5:8080".into(),
        container: "app".into(),
        container_port: 3000,
        root: "site1".into(),
        local_root: String::new(),
        ssl,
        cert_mode: "self".into(),
        cert_name: String::new(),
        scheme: "http".into(),
        cache: false,
        block_attacks: false,
        websockets: true,
        force_ssl: true,
        http2: true,
        hsts: false,
        hsts_sub: false,
        trust_proxy: false,
        trust_proxy_cidrs: String::new(),
        locations: Vec::new(),
        extra_conf: String::new(),
        access_id: String::new(),
    }
}

#[tokio::test]
async fn renders_proxy_host() {
    let lo = lo_test();
    let site = mk_site("proxy_host", false);
    let body = render_location(&lo, &site, false).await.unwrap();
    assert!(body.contains("proxy_pass http://10.0.0.5:8080;"));
    assert!(body.contains("Upgrade $http_upgrade"));
}

#[tokio::test]
async fn renders_static_root() {
    let lo = lo_test();
    let site = mk_site("static", false);
    let body = render_location(&lo, &site, false).await.unwrap();
    assert!(body.contains("root /tmp/dn7-test-www/site1;"));
}

#[tokio::test]
async fn renders_https_scheme_and_options() {
    let lo = lo_test();
    let mut site = mk_site("proxy_host", false);
    site.scheme = "https".into();
    site.cache = true;
    site.block_attacks = true;
    site.websockets = false;
    let body = render_location(&lo, &site, false).await.unwrap();
    // https upstream, asset-cache location, exploit block, no ws headers.
    assert!(body.contains("proxy_pass https://10.0.0.5:8080;"));
    assert!(body.contains("location ~* \\.("));
    assert!(body.contains("block common exploits"));
    assert!(!body.contains("Upgrade $http_upgrade"));
}

#[tokio::test]
async fn renders_custom_locations() {
    let lo = lo_test();
    let mut site = mk_site("proxy_host", false);
    site.locations = vec![Location {
        path: "/api".into(),
        scheme: "http".into(),
        target: "127.0.0.1:3001".into(),
        websockets: true,
        kind: "host".into(),
        container: String::new(),
        container_port: 0,
    }];
    let body = render_location(&lo, &site, false).await.unwrap();
    assert!(body.contains("location /api {"));
    assert!(body.contains("proxy_pass http://127.0.0.1:3001;"));
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
fn htpasswd_is_apr1_and_matches_known_vector() {
    // Format + salt round-trip: re-hashing with the embedded salt is stable.
    let h = htpasswd_hash("s3cret");
    assert!(h.starts_with("$apr1$"), "expected an apr1 hash, got {h}");
    let salt = h.trim_start_matches("$apr1$").split('$').next().unwrap();
    assert_eq!(apr1_with_salt("s3cret", salt), h);
    assert_ne!(apr1_with_salt("wrong", salt), h);
    // Known apr1 vector (matches Apache htpasswd / openssl passwd -apr1).
    assert_eq!(
        apr1_with_salt("myPassword", "r31....."),
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

#[test]
fn trusted_proxy_sources_never_trusts_whole_internet() {
    // No explicit list → private + loopback ranges only, never 0.0.0.0/0.
    let site = mk_site("proxy_host", true);
    let def = trusted_proxy_sources(&site);
    assert!(def.contains(&"127.0.0.0/8".to_string()));
    assert!(def.contains(&"10.0.0.0/8".to_string()));
    assert!(def.contains(&"::1/128".to_string()));
    assert!(!def.iter().any(|c| c == "0.0.0.0/0" || c == "::/0"));
    // Explicit list is honoured verbatim.
    let mut site2 = mk_site("proxy_host", true);
    site2.trust_proxy_cidrs = "203.0.113.5 10.0.0.0/8".into();
    assert_eq!(
        trusted_proxy_sources(&site2),
        vec!["203.0.113.5", "10.0.0.0/8"]
    );
}
