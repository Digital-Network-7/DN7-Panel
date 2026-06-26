use super::*;

#[test]
fn sanitizes_binary_log() {
    // Control bytes + invalid UTF-8 are dropped; text + newlines/CJK kept.
    let raw = String::from_utf8_lossy(b"hi\n\x16\x03\x01\x00ok\xEE\x01world\t!");
    let out = sanitize_log(&raw);
    assert_eq!(out, "hi\nokworld\t!");
    assert_eq!(sanitize_log("日志 ok"), "日志 ok");
    // Literal web-server-style hex escapes in an access log line are stripped.
    let access = "1.2.3.4 - - \"\\x16\\x03\\x01\\x00\\xEE\" 400 154 \"-\"";
    assert_eq!(sanitize_log(access), "1.2.3.4 - - \"\" 400 154 \"-\"");
}

#[test]
fn validates_refs() {
    assert!(validate_token("nginx:latest").is_ok());
    assert!(validate_token("user/app:1.2.3").is_ok());
    assert!(validate_token("m.daocloud.io/docker.io/nginx").is_ok());
    assert!(validate_token("sha256:abc123").is_ok());
    assert!(validate_token("-v").is_err());
    assert!(validate_token("a; rm -rf /").is_err());
    assert!(validate_token("a b").is_err());
    assert!(validate_token("").is_err());
}

#[test]
fn docker_io_path_qualifies() {
    assert_eq!(
        docker_io_path("nginx"),
        Some("docker.io/library/nginx:latest".into())
    );
    assert_eq!(
        docker_io_path("nginx:1.25"),
        Some("docker.io/library/nginx:1.25".into())
    );
    assert_eq!(
        docker_io_path("user/app"),
        Some("docker.io/user/app:latest".into())
    );
    assert_eq!(docker_io_path("gcr.io/foo/bar"), None);
    assert_eq!(docker_io_path("localhost:5000/x"), None);
}

#[test]
fn default_tag() {
    assert_eq!(with_default_tag("nginx"), "nginx:latest");
    assert_eq!(with_default_tag("nginx:1.25"), "nginx:1.25");
    assert_eq!(with_default_tag("user/app"), "user/app:latest");
    assert_eq!(with_default_tag("img@sha256:abc"), "img@sha256:abc");
}

#[test]
fn mirror_whitelist() {
    // The default mirror list (no settings file present) gates the pull.
    assert!(mirror_allowed("docker.m.daocloud.io"));
    assert!(!mirror_allowed("evil.example.com"));
    assert!(!registry_allowed("evil.example.com"));
}

#[test]
fn host_line_and_log_validation() {
    assert!(valid_host_line("registry.example.com:5000"));
    assert!(valid_host_line("docker.m.daocloud.io"));
    assert!(!valid_host_line("https://x.com"));
    assert!(!valid_host_line("a b"));
    assert!(valid_log_size("10m"));
    assert!(valid_log_size("512k"));
    assert!(!valid_log_size("10"));
    assert!(!valid_log_size("abc"));
}

#[test]
fn op_registry_lifecycle() {
    let id = "test-op-1";
    op_create(id, "pull", "nginx:latest");
    op_push(id, "layer 1");
    op_finish(id, "done", "", "nginx:latest");
    let log = op_log(id);
    assert_eq!(log["status"], "done");
    assert_eq!(log["result_image"], "nginx:latest");
    op_dismiss(id);
    assert_eq!(op_log(id)["status"], "gone");
}

fn mk_req(image: &str) -> Req {
    Req {
        id: 0,
        op: "create_container".into(),
        image: Some(image.into()),
        mirror: None,
        registry: None,
        settings: None,
        reference: None,
        tail: None,
        op_id: None,
        name: None,
        ports: None,
        env: None,
        volumes: None,
        restart: None,
        start: None,
        network: None,
        networks: None,
        driver: None,
        subnet: None,
        gateway: None,
        ip_range: None,
        mac: None,
        ipv4: None,
        hostname: None,
        domainname: None,
        dns: None,
        cpu_shares: None,
        privileged: None,
        replace: None,
        new_name: None,
        repo: None,
        tag: None,
        tags: None,
        backup: None,
        path: None,
        command: None,
        tty: None,
        interactive: None,
        cpus: None,
        memory: None,
        channel: None,
        region: None,
    }
}

#[test]
fn restart_whitelist() {
    assert!(restart_allowed("no"));
    assert!(restart_allowed("unless-stopped"));
    assert!(restart_allowed("always"));
    assert!(!restart_allowed("on-failure"));
    assert!(!restart_allowed("; rm -rf /"));
}

#[test]
fn install_script_selection() {
    // distro channel → native package per family
    assert!(build_install_script("debian", "distro", "global").contains("docker.io"));
    assert!(build_install_script("rhel", "distro", "global").contains("install docker"));
    assert!(build_install_script("arch", "distro", "cn").contains("pacman"));
    assert!(build_install_script("alpine", "distro", "cn").contains("apk add"));
    // ce channel + unknown distro → official convenience script
    assert!(build_install_script("debian", "ce", "global").contains("get.docker.com"));
    assert!(build_install_script("unknown", "distro", "global").contains("get.docker.com"));
    // CN networks add the Aliyun package mirror; global does not.
    assert!(get_docker_script("cn").contains("--mirror Aliyun"));
    assert!(!get_docker_script("global").contains("--mirror"));
}

#[test]
fn name_validation() {
    assert!(validate_name("my-app_1.0").is_ok());
    assert!(validate_name("-leading").is_err());
    assert!(validate_name("bad name").is_err());
    assert!(validate_name("a; ls").is_err());
}

#[test]
fn path_validation() {
    assert!(validate_path("/data/app").is_ok());
    assert!(validate_path("relative/path").is_err());
    assert!(validate_path("/data;rm").is_err());
    assert!(validate_path("/data$(x)").is_err());
    assert!(validate_path("").is_err());
}

#[test]
fn env_validation() {
    assert!(validate_env("KEY=value").is_ok());
    assert!(validate_env("MY_VAR=a b c").is_ok());
    assert!(validate_env("_X=1").is_ok());
    assert!(validate_env("noequals").is_err());
    assert!(validate_env("=novalue").is_err());
    assert!(validate_env("1BAD=x").is_err());
    assert!(validate_env("bad key=x").is_err());
}

#[test]
fn build_create_spec_basic() {
    let mut req = mk_req("nginx:latest");
    req.name = Some("web".into());
    req.ports = Some(vec![PortMap {
        host: 8080,
        container: 80,
        proto: None,
        ipv6: None,
    }]);
    req.env = Some(vec!["FOO=bar".into()]);
    req.volumes = Some(vec![VolumeMap {
        host: "/srv/html".into(),
        container: "/usr/share/nginx/html".into(),
        readonly: true,
    }]);
    let (spec, name) = build_create_spec(&req).unwrap();
    assert_eq!(name, "web");
    assert_eq!(spec.name.as_deref(), Some("web"));
    assert_eq!(spec.config.image.as_deref(), Some("nginx:latest"));
    let hc = spec.config.host_config.as_ref().unwrap();
    // default restart policy applied
    assert_eq!(
        hc.restart_policy.as_ref().unwrap().name,
        Some(bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED)
    );
    // port binding host 8080 -> container 80/tcp
    let pb = hc.port_bindings.as_ref().unwrap();
    let bind = pb.get("80/tcp").unwrap().as_ref().unwrap();
    assert_eq!(bind[0].host_port.as_deref(), Some("8080"));
    // env + bind present
    assert!(spec
        .config
        .env
        .as_ref()
        .unwrap()
        .contains(&"FOO=bar".to_string()));
    assert!(hc
        .binds
        .as_ref()
        .unwrap()
        .contains(&"/srv/html:/usr/share/nginx/html:ro".to_string()));
    assert!(spec.start);
}

#[test]
fn build_create_spec_rejects_bad_port() {
    let mut req = mk_req("nginx");
    req.ports = Some(vec![PortMap {
        host: 0,
        container: 80,
        proto: None,
        ipv6: None,
    }]);
    assert!(build_create_spec(&req).is_err());
}

#[test]
fn build_create_spec_rejects_bad_restart() {
    let mut req = mk_req("nginx");
    req.restart = Some("on-failure".into());
    assert!(build_create_spec(&req).is_err());
}

#[test]
fn spec_binds_rejects_host_escape_paths() {
    for denied in ["/var/run/docker.sock", "/etc/shadow", "/root/.ssh", "/"] {
        let mut req = mk_req("nginx");
        req.volumes = Some(vec![VolumeMap {
            host: denied.into(),
            container: "/data".into(),
            readonly: false,
        }]);
        assert!(
            build_create_spec(&req).is_err(),
            "bind mount of {denied} must be rejected"
        );
    }
    // An ordinary data path is still accepted.
    let mut req = mk_req("nginx");
    req.volumes = Some(vec![VolumeMap {
        host: "/srv/data".into(),
        container: "/data".into(),
        readonly: false,
    }]);
    assert!(build_create_spec(&req).is_ok());
}

#[test]
fn create_policy_gates_privileged_and_host_network_to_super() {
    // Privileged: denied for a non-super admin, allowed for the super-admin.
    let mut req = mk_req("nginx");
    req.privileged = Some(true);
    assert!(enforce_create_policy(&req, false).is_err());
    assert!(enforce_create_policy(&req, true).is_ok());

    // Host network mode: same gate.
    let mut req = mk_req("nginx");
    req.network = Some("host".into());
    assert!(enforce_create_policy(&req, false).is_err());
    assert!(enforce_create_policy(&req, true).is_ok());

    // A normal container passes for any admin.
    let req = mk_req("nginx");
    assert!(enforce_create_policy(&req, false).is_ok());
}

#[test]
fn build_create_spec_includes_network() {
    let mut req = mk_req("nginx");
    req.network = Some("my-net".into());
    let (spec, _) = build_create_spec(&req).unwrap();
    let hc = spec.config.host_config.as_ref().unwrap();
    assert_eq!(hc.network_mode.as_deref(), Some("my-net"));
}

#[test]
fn build_create_spec_rejects_bad_network() {
    let mut req = mk_req("nginx");
    req.network = Some("bad net".into());
    assert!(build_create_spec(&req).is_err());
}

#[test]
fn build_create_spec_tty_and_command() {
    let mut req = mk_req("ubuntu");
    req.tty = Some(true);
    req.command = Some("sleep infinity".into());
    let (spec, _) = build_create_spec(&req).unwrap();
    assert_eq!(spec.config.tty, Some(true));
    assert_eq!(spec.config.open_stdin, Some(true));
    assert_eq!(
        spec.config.cmd.as_ref().unwrap(),
        &vec!["sleep".to_string(), "infinity".to_string()]
    );
}

#[test]
fn validates_network_fields() {
    assert!(valid_ipv4("172.20.0.5").is_ok());
    assert!(valid_ipv4("999.1.1.1").is_err());
    assert!(valid_ipv4("172.20.0.5/24").is_err());
    assert!(valid_cidr("172.20.0.0/16").is_ok());
    assert!(valid_cidr("172.20.0.0/33").is_err());
    assert!(valid_cidr("172.20.0.0").is_err());
    assert!(valid_mac("02:42:ac:11:00:02").is_ok());
    assert!(valid_mac("02-42-ac-11-00-02").is_err());
    assert!(valid_mac("02:42:ac:11:00").is_err());
    assert!(valid_hostname("web-01").is_ok());
    assert!(valid_hostname("web.example.com").is_ok());
    assert!(valid_hostname("-bad").is_err());
    assert!(valid_hostname("bad_underscore").is_err());
    assert!(net_driver_allowed("bridge"));
    assert!(net_driver_allowed("macvlan"));
    assert!(!net_driver_allowed("weird"));
}

#[test]
fn build_create_spec_endpoint_and_resources() {
    let mut req = mk_req("nginx");
    req.network = Some("mynet".into());
    req.ipv4 = Some("172.20.0.10".into());
    req.mac = Some("02:42:ac:14:00:0a".into());
    req.hostname = Some("web-01".into());
    req.domainname = Some("example.com".into());
    req.dns = Some(vec!["1.1.1.1".into(), "8.8.8.8".into()]);
    req.cpu_shares = Some(2048);
    req.privileged = Some(true);
    let (spec, _) = build_create_spec(&req).unwrap();
    let hc = spec.config.host_config.as_ref().unwrap();
    assert_eq!(hc.cpu_shares, Some(2048));
    assert_eq!(hc.privileged, Some(true));
    assert_eq!(hc.dns.as_ref().unwrap().len(), 2);
    assert_eq!(spec.config.hostname.as_deref(), Some("web-01"));
    assert_eq!(spec.config.domainname.as_deref(), Some("example.com"));
    let nc = spec.config.networking_config.as_ref().unwrap();
    let ep = nc.endpoints_config.get("mynet").unwrap();
    assert_eq!(ep.mac_address.as_deref(), Some("02:42:ac:14:00:0a"));
    assert_eq!(
        ep.ipam_config.as_ref().unwrap().ipv4_address.as_deref(),
        Some("172.20.0.10")
    );
}

#[test]
fn build_create_spec_rejects_endpoint_without_network() {
    // A NetAttach with an empty network name is skipped (not an endpoint).
    let mut req = mk_req("nginx");
    req.networks = Some(vec![NetAttach {
        network: String::new(),
        mac: None,
        ipv4: Some("172.20.0.10".into()),
    }]);
    let (spec, _) = build_create_spec(&req).unwrap();
    assert!(spec.config.networking_config.is_none());
    assert!(spec.extra_networks.is_empty());
}

#[test]
fn build_create_spec_multi_network() {
    let mut req = mk_req("nginx");
    req.networks = Some(vec![
        NetAttach {
            network: "neta".into(),
            mac: Some("02:42:ac:14:00:0a".into()),
            ipv4: Some("172.20.0.10".into()),
        },
        NetAttach {
            network: "netb".into(),
            mac: None,
            ipv4: None,
        },
    ]);
    let (spec, _) = build_create_spec(&req).unwrap();
    // First network on the create call.
    assert_eq!(
        spec.config
            .host_config
            .as_ref()
            .unwrap()
            .network_mode
            .as_deref(),
        Some("neta")
    );
    let nc = spec.config.networking_config.as_ref().unwrap();
    assert!(nc.endpoints_config.contains_key("neta"));
    // Second network connected after creation.
    assert_eq!(spec.extra_networks.len(), 1);
    assert_eq!(spec.extra_networks[0].network, "netb");
}

#[test]
fn build_create_spec_rejects_bad_cpu_shares() {
    let mut req = mk_req("nginx");
    req.cpu_shares = Some(1);
    assert!(build_create_spec(&req).is_err());
}

#[test]
fn build_create_spec_resource_limits() {
    let mut req = mk_req("nginx");
    req.cpus = Some("0.5".into());
    req.memory = Some("512m".into());
    let (spec, _) = build_create_spec(&req).unwrap();
    let hc = spec.config.host_config.as_ref().unwrap();
    assert_eq!(hc.nano_cpus, Some(500_000_000));
    assert_eq!(hc.memory, Some(512 * 1024 * 1024));
}

#[test]
fn validates_limits() {
    assert!(validate_cpus("0.5").is_ok());
    assert!(validate_cpus("2").is_ok());
    assert!(validate_cpus("0").is_err());
    assert!(validate_cpus("abc").is_err());
    assert!(validate_memory("512m").is_ok());
    assert!(validate_memory("1g").is_ok());
    assert!(validate_memory("268435456").is_ok());
    assert!(validate_memory("0").is_err());
    assert!(validate_memory("12x").is_err());
}

#[test]
fn mem_to_bytes_units() {
    assert_eq!(mem_to_bytes("512m"), 512 * 1024 * 1024);
    assert_eq!(mem_to_bytes("1g"), 1024 * 1024 * 1024);
    assert_eq!(mem_to_bytes("2048"), 2048);
    assert_eq!(mem_to_bytes("1k"), 1024);
}

#[test]
fn splits_command() {
    assert_eq!(
        split_command("sleep infinity").unwrap(),
        vec!["sleep", "infinity"]
    );
    assert_eq!(
        split_command("sh -c \"echo hi there\"").unwrap(),
        vec!["sh", "-c", "echo hi there"]
    );
    assert!(split_command("bad 'quote").is_err());
}
