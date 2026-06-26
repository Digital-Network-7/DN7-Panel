//! [M6] Edge server tests.
//!
//! These exercise the fully-real M0 FOUNDATION (`build`/`validate`/`store`) plus
//! the M4 `security` data plane and the panel's apr1 htpasswd verifier. They are
//! pure-Rust + hermetic: cert/www roots live under a per-test unique subdir of
//! `std::env::temp_dir()` (no `tempfile` crate), nothing binds a fixed port, and
//! nothing reaches the network — so they run under the musl-static CI.
//!
//! As a child module of `edge`, these reach the siblings via `super::{..}`.

#[cfg(test)]
mod edge_tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::super::build::{self, ConsoleParams, ReloadInput};
    use super::super::config::{
        AccessControl, AclNet, AclRule, DefaultRoute, RouteKind, RuntimeConfig, ServerRoute,
    };
    use super::super::store;
    use super::super::validate;

    use crate::core::website::{
        AccessClient, AccessList, AccessUser, DefaultSite, HttpTuning, Location, Site,
    };

    // ---- helpers ----------------------------------------------------------

    /// A unique temp directory for this test process + a monotonic counter, so
    /// parallel tests never collide on cert/www roots. We never create the dir
    /// (the cert loader tolerates missing files); callers `create_dir_all` only
    /// when they actually write material.
    fn unique_tmp(tag: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("dn7-edge-test-{tag}-{pid}-{n}"))
    }

    /// The config store is process-global (one `ArcSwap` for the whole binary),
    /// so any test that *publishes* must run mutually-exclusive with the others —
    /// otherwise one test's `publish` swaps the whole table out from under
    /// another's assertions. Every store-mutating test holds this for its
    /// duration. (Tests that only `build`/`validate` a local config don't need it.)
    fn serial() -> &'static tokio::sync::Mutex<()> {
        static S: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        S.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// A minimal `Site` with every toggle off; tests mutate the fields they care
    /// about. Mirrors a freshly-created proxy site before any options are set.
    fn base_site(id: &str, server_name: &str, kind: &str) -> Site {
        Site {
            id: id.to_string(),
            server_name: server_name.to_string(),
            kind: kind.to_string(),
            target_url: String::new(),
            container: String::new(),
            container_port: 0,
            root: String::new(),
            local_root: String::new(),
            ssl: false,
            cert_mode: String::new(),
            cert_name: String::new(),
            scheme: String::new(),
            cache: false,
            block_attacks: false,
            websockets: false,
            // These two default `true` in the model's serde; mirror that so a
            // built proxy behaves like a deserialized one.
            force_ssl: true,
            http2: true,
            hsts: false,
            hsts_sub: false,
            trust_proxy: false,
            trust_proxy_cidrs: String::new(),
            locations: Vec::<Location>::new(),
            extra_conf: String::new(),
            access_id: String::new(),
        }
    }

    /// An "already initialized, no external console address" console fixture, so
    /// the synthesized console route only claims localhost/127.0.0.1 and never
    /// becomes the catch-all (`console_fallback`) — keeping these tests focused
    /// on user-site routing + default_site behaviour.
    fn test_console() -> ConsoleParams {
        ConsoleParams {
            external_address: String::new(),
            https_mode: "none".to_string(),
            initialized: true,
        }
    }

    /// A `ReloadInput` over the given sites with empty access/default/tuning and
    /// fresh (non-existent) cert/www roots — the common build fixture.
    fn reload_input(sites: Vec<Site>) -> ReloadInput {
        ReloadInput {
            sites,
            access: Vec::new(),
            default_site: DefaultSite::default(),
            tuning: HttpTuning::default(),
            cert_dir: unique_tmp("certs"),
            www_dir: unique_tmp("www"),
            console: test_console(),
        }
    }

    // ---- build::build_runtime --------------------------------------------

    #[test]
    fn build_projects_proxy_static_and_degrades_ssl_without_cert() {
        // A plain proxy host.
        let mut proxy = base_site("p1", "proxy.example.com", "proxy_host");
        proxy.target_url = "10.0.0.5:8080".to_string();

        // A static site in upload mode (root joined under www_dir).
        let mut stat = base_site("s1", "static.example.com", "static");
        stat.root = "site-files".to_string();

        // An ssl site whose cert PEM does NOT exist on disk → must degrade.
        let mut ssl = base_site("c1", "secure.example.com", "proxy_host");
        ssl.target_url = "10.0.0.9:443".to_string();
        ssl.ssl = true;

        let input = reload_input(vec![proxy, stat, ssl]);
        let cfg = build::build_runtime(&input).expect("clean multi-site build succeeds");

        // proxy_host → RouteKind::Proxy.
        let p = cfg
            .route_for("proxy.example.com")
            .expect("proxy host indexed");
        assert!(
            matches!(p.kind, RouteKind::Proxy(_)),
            "proxy_host must project to RouteKind::Proxy"
        );

        // static → RouteKind::Static with the root joined under www_dir.
        let s = cfg
            .route_for("static.example.com")
            .expect("static host indexed");
        match &s.kind {
            RouteKind::Static(root) => {
                assert_eq!(
                    root.root,
                    input.www_dir.join("site-files"),
                    "upload-mode static root is <www_dir>/<root>"
                );
            }
            _ => panic!("static site must project to RouteKind::Static"),
        }

        // ssl-without-cert → ssl flag degraded to false (one cert-less site must
        // not break the reload; it just serves plain HTTP).
        let c = cfg
            .route_for("secure.example.com")
            .expect("ssl host indexed");
        assert!(
            !c.ssl,
            "an ssl site with no cert material must degrade to ssl=false"
        );
        assert!(
            !c.force_ssl,
            "force_ssl is meaningless once ssl degraded off"
        );
    }

    #[test]
    fn location_matching_merges_slashes_like_nginx() {
        use super::super::router::{collapse_slashes, location_matches};

        // merge_slashes: `//api//x` normalizes to `/api/x`.
        assert_eq!(collapse_slashes("//api//x"), "/api/x");
        assert_eq!(collapse_slashes("/clean/path"), "/clean/path");

        // A `/api` location must match the normalized path (so `//api/x` can't
        // sneak past the location and hit the main handler instead).
        assert!(location_matches("/api", &collapse_slashes("//api/x")));
        // Segment-boundary semantics: `/api` does not match `/apixyz`.
        assert!(!location_matches("/api", &collapse_slashes("/apixyz")));
        // Exact prefix still matches.
        assert!(location_matches("/api", &collapse_slashes("/api")));
    }

    #[test]
    fn wildcard_matches_single_label_only() {
        use super::super::config::wildcard_matches;
        // `*.example.com` is stored as the suffix `.example.com`.
        let suffix = ".example.com";
        assert!(
            wildcard_matches("foo.example.com", suffix),
            "one label matches"
        );
        assert!(
            !wildcard_matches("foo.bar.example.com", suffix),
            "a deeper subdomain must NOT match (nginx single-label semantics)"
        );
        assert!(
            !wildcard_matches("example.com", suffix),
            "the bare apex (empty label) must not match the wildcard"
        );
        assert!(
            !wildcard_matches("foo.other.com", suffix),
            "different domain"
        );
    }

    #[test]
    fn build_rejects_duplicate_server_name() {
        // Two distinct sites both claiming the same host: nginx -t-style refusal.
        let a = base_site("a", "dup.example.com", "static");
        let b = base_site("b", "dup.example.com", "static");

        let input = reload_input(vec![a, b]);
        // `expect_err` would need `RuntimeConfig: Debug`; match instead so the
        // config tree needn't derive Debug over its rustls cert material.
        let err = match build::build_runtime(&input) {
            Ok(_) => panic!("two sites with the same server_name must be a collision error"),
            Err(e) => e,
        };
        assert!(
            err.contains("dup.example.com"),
            "collision error names the offending host, got: {err}"
        );
    }

    // ---- validate::validate ----------------------------------------------

    /// Hand-build a `RuntimeConfig` with a single route, so a validate test does
    /// not depend on cert files existing. `build` would have degraded an ssl site
    /// with no cert, but `validate` must independently reject an `ssl` route whose
    /// cert does not resolve (the fail-closed assertion).
    fn route(id: &str, host: &str, ssl: bool, kind: RouteKind) -> RuntimeConfig {
        let route = Arc::new(ServerRoute {
            id: id.to_string(),
            server_names: vec![host.to_string()],
            ssl,
            force_ssl: false,
            hsts: None,
            block_attacks: false,
            trust_proxy: None,
            access: None,
            kind,
            locations: Vec::new(),
            extra_headers: Vec::new(),
        });
        let mut hosts = HashMap::new();
        hosts.insert(host.to_string(), route);
        RuntimeConfig {
            hosts,
            ..RuntimeConfig::default()
        }
    }

    #[test]
    fn validate_rejects_ssl_route_without_cert() {
        // ssl == true but the (empty) CertStore resolves no cert → Err.
        let cfg = route("ssl1", "secure.example.com", true, RouteKind::Maintenance);
        let err = validate::validate(&cfg)
            .expect_err("ssl route with no resolvable cert must fail validation");
        assert!(
            err.contains("secure.example.com") || err.contains("certificate"),
            "error should mention the cert problem, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_redirect_default_with_empty_url() {
        let cfg = RuntimeConfig {
            default_site: DefaultRoute::Redirect(String::new()),
            ..RuntimeConfig::default()
        };
        let err = validate::validate(&cfg)
            .expect_err("redirect default with no target URL must fail validation");
        assert!(
            err.to_lowercase().contains("redirect"),
            "error should mention the redirect target, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_clean_config() {
        // A plain-HTTP static site with an absolute root: nothing for the
        // semantic gate to reject.
        let cfg = route(
            "ok1",
            "ok.example.com",
            false,
            RouteKind::Static(super::super::config::StaticRoot {
                root: PathBuf::from("/srv/www/ok"),
                cache_assets: false,
            }),
        );
        validate::validate(&cfg).expect("a clean plain-HTTP config validates");
    }

    // ---- store: the zero-drop reload primitive ---------------------------

    #[tokio::test]
    async fn store_publishes_and_swaps_atomically() {
        // Serialize against the other store-mutating tests (see `serial`): the
        // store is process-global, so a parallel `publish` would otherwise swap
        // the table between our publish and our `store::current()` read.
        let _g = serial().lock().await;

        let host_a = "store-a.example.test";
        let host_b = "store-b.example.test";

        let cfg1 = route("st-a", host_a, false, RouteKind::Maintenance);
        store::publish(Arc::new(cfg1));
        let live = store::current();
        assert!(
            live.route_for(host_a).is_some(),
            "published config must be visible via store::current()"
        );
        assert!(live.route_for(host_b).is_none(), "host_b not published yet");

        // Publish a second config: the swap must be visible immediately. The Arc
        // `live` we still hold keeps serving its old snapshot (zero-drop) — it
        // must NOT see host_b, proving the swap doesn't mutate in place.
        let cfg2 = route("st-b", host_b, false, RouteKind::Maintenance);
        store::publish(Arc::new(cfg2));
        let live2 = store::current();
        assert!(
            live2.route_for(host_b).is_some(),
            "the new snapshot must reflect the swapped-in config"
        );
        assert!(
            live2.route_for(host_a).is_none(),
            "the new snapshot replaced the old table"
        );
        // The previously-loaded Arc is unchanged — the rollback/zero-drop story.
        assert!(
            live.route_for(host_a).is_some(),
            "an in-flight Arc keeps serving its old snapshot after a swap"
        );
        assert!(
            live.route_for(host_b).is_none(),
            "an in-flight Arc never sees a later swap's routes"
        );
    }

    // ---- security (M4) ----------------------------------------------------

    #[test]
    fn security_blocks_script_injection_query() {
        use super::super::security;
        // A classic script-injection query trips BLOCK_EXPLOITS.
        assert!(
            security::blocked_by_attacks("q=<script>alert(1)</script>"),
            "a script-injection query must be blocked"
        );
        // A benign search query must pass.
        assert!(
            !security::blocked_by_attacks("q=hello+world&page=2"),
            "a normal query must not be blocked"
        );
    }

    #[test]
    fn security_deny_all_with_satisfy_any_returns_403_without_auth() {
        use super::super::security;
        use http::HeaderMap;

        // satisfy any + a single `deny all` rule and NO users: the IP factor
        // fails for every client and there is no auth factor to satisfy, so the
        // request is forbidden (403), never challenged (401).
        let access = AccessControl {
            satisfy_all: false,
            users: Vec::new(),
            rules: vec![AclRule {
                allow: false,
                net: AclNet::All,
            }],
            realm: "test".to_string(),
        };
        let headers = HeaderMap::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        let resp = security::check_access(Some(&access), &headers, ip)
            .expect("deny-all must short-circuit the request");
        assert_eq!(
            resp.status(),
            http::StatusCode::FORBIDDEN,
            "deny-all with no auth factor must be 403, not a 401 challenge"
        );
    }

    #[test]
    fn security_real_ip_returns_peer_when_trust_is_none() {
        use super::super::listener::ConnCtx;
        use super::super::security;
        use http::HeaderMap;

        // No trusted proxy configured → XFF must be ignored entirely and the
        // immediate peer returned, even if a client forged X-Forwarded-For.
        let peer: std::net::SocketAddr = "198.51.100.42:50000".parse().unwrap();
        let ctx = ConnCtx {
            tls: false,
            sni: None,
            peer,
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());

        let got = security::real_ip(&ctx, &headers, None);
        assert_eq!(
            got,
            peer.ip(),
            "with no TrustProxy, real_ip must be the peer IP (never trust XFF)"
        );
    }

    // ---- apr1 htpasswd verification --------------------------------------

    #[test]
    fn apr1_htpasswd_verifies_correct_password_only() {
        // A real Apache `$apr1$` hash (the format the panel writes) for the
        // password "secret-pw", salt "abcd1234". Generated with
        // `openssl passwd -apr1 -salt abcd1234 secret-pw`.
        let hash = "$apr1$abcd1234$oftWSoe5k1oxqcJ5vs93v/";
        assert!(
            crate::infra::website::verify_htpasswd_hash(hash, "secret-pw"),
            "the right password must verify against its apr1 hash"
        );
        assert!(
            !crate::infra::website::verify_htpasswd_hash(hash, "wrong-pw"),
            "a wrong password must fail apr1 verification"
        );
    }

    // ---- a richer build fixture: access lists + ACLs ---------------------

    #[test]
    fn build_wires_access_list_onto_site() {
        // A site referencing an access list with a deny rule and a user; build
        // must attach an AccessControl carrying both factors.
        let mut site = base_site("guarded", "guarded.example.com", "static");
        site.root = "files".to_string();
        site.access_id = "acl1".to_string();

        let access = AccessList {
            id: "acl1".to_string(),
            name: "Guarded Realm".to_string(),
            satisfy: "all".to_string(),
            pass_auth: false,
            users: vec![AccessUser {
                username: "alice".to_string(),
                hash: "$apr1$abcd1234$oftWSoe5k1oxqcJ5vs93v/".to_string(),
            }],
            clients: vec![AccessClient {
                directive: "deny".to_string(),
                address: "203.0.113.0/24".to_string(),
            }],
        };

        let input = ReloadInput {
            sites: vec![site],
            access: vec![access],
            default_site: DefaultSite::default(),
            tuning: HttpTuning::default(),
            cert_dir: unique_tmp("certs"),
            www_dir: unique_tmp("www"),
            console: test_console(),
        };
        let cfg = build::build_runtime(&input).expect("guarded site builds");
        let route = cfg
            .route_for("guarded.example.com")
            .expect("guarded indexed");
        let ac = route.access.as_ref().expect("access list must be attached");
        assert!(
            ac.satisfy_all,
            "satisfy \"all\" projects to satisfy_all=true"
        );
        assert!(ac.has_auth(), "the access list's user must be carried");
        assert!(ac.has_acl(), "the access list's deny rule must be carried");
        assert_eq!(ac.realm, "Guarded Realm", "realm comes from the list name");
    }

    // ---- live end-to-end (real sockets, real HTTP) -----------------------

    /// Spin up a throwaway upstream HTTP server on `127.0.0.1:0` that echoes back
    /// the `Host` / `X-Forwarded-For` / `X-Forwarded-Proto` it received and the
    /// request path, so the test can assert the edge rewrote headers correctly.
    /// Returns its bound address.
    async fn spawn_upstream() -> std::net::SocketAddr {
        use http_body_util::Full;
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                        let h = |n: &str| {
                            req.headers()
                                .get(n)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string()
                        };
                        let body = format!(
                            "UPSTREAM host={} xff={} xfp={} path={}",
                            h("host"),
                            h("x-forwarded-for"),
                            h("x-forwarded-proto"),
                            req.uri().path(),
                        );
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            bytes::Bytes::from(body),
                        )))
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        addr
    }

    /// Bind the edge plain-HTTP listener on an ephemeral loopback port, start
    /// serving the live config, and return the address to point a client at.
    async fn spawn_edge() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(super::super::listener::serve_plain(listener));
        addr
    }

    /// `{SHA}` htpasswd hash for a password (the cheap legacy format the verifier
    /// also accepts) — avoids shelling out to openssl in the test.
    fn sha_hash(pw: &str) -> String {
        use base64::Engine;
        use sha1::{Digest, Sha1};
        format!(
            "{{SHA}}{}",
            base64::engine::general_purpose::STANDARD.encode(Sha1::digest(pw.as_bytes()))
        )
    }

    /// Build + publish a route table: a proxy site, a static site (a temp dir
    /// with an index.html), and a basic-auth-guarded proxy site.
    fn publish_full_config(upstream: std::net::SocketAddr, www: &std::path::Path) {
        std::fs::create_dir_all(www).unwrap();
        std::fs::write(www.join("index.html"), "STATIC-OK").unwrap();
        // A hidden file the static handler must never serve.
        std::fs::write(www.join(".secret"), "TOPSECRET").unwrap();

        let mut proxy = base_site("p", "proxy.example.test", "proxy_host");
        proxy.target_url = upstream.to_string();
        proxy.force_ssl = false; // serve over plain HTTP for the test

        let mut stat = base_site("s", "static.example.test", "static");
        stat.local_root = www.to_string_lossy().to_string();
        stat.force_ssl = false;

        let mut guarded = base_site("g", "auth.example.test", "proxy_host");
        guarded.target_url = upstream.to_string();
        guarded.force_ssl = false;
        guarded.access_id = "acl".to_string();

        let access = AccessList {
            id: "acl".to_string(),
            name: "Members".to_string(),
            satisfy: "any".to_string(),
            pass_auth: true,
            users: vec![AccessUser {
                username: "user".to_string(),
                hash: sha_hash("pw"),
            }],
            clients: Vec::new(),
        };

        let input = ReloadInput {
            sites: vec![proxy, stat, guarded],
            access: vec![access],
            default_site: DefaultSite::default(),
            tuning: HttpTuning::default(),
            cert_dir: unique_tmp("certs"),
            www_dir: unique_tmp("www-base"),
            console: test_console(),
        };
        let cfg = build::build_runtime(&input).expect("full config builds");
        store::publish(std::sync::Arc::new(cfg));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_proxy_static_auth_end_to_end() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream().await;
        let www = unique_tmp("live-static");
        publish_full_config(upstream, &www);
        let edge = spawn_edge().await;

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let base = format!("http://{edge}/");
        let host = reqwest::header::HOST;

        // (1) Reverse proxy: the upstream is reached and the edge rewrote Host to
        // the upstream authority + synthesised X-Forwarded-For/Proto.
        let r = client
            .get(format!("{base}hello"))
            .header(host.clone(), "proxy.example.test")
            .send()
            .await
            .expect("proxy request reaches the edge");
        assert_eq!(r.status(), 200, "proxy site returns the upstream's 200");
        let body = r.text().await.unwrap();
        assert!(body.starts_with("UPSTREAM"), "got upstream body: {body}");
        assert!(
            body.contains(&format!("host={upstream}")),
            "Host rewritten to upstream authority: {body}"
        );
        assert!(
            body.contains("xff=127.0.0.1"),
            "X-Forwarded-For carries the client IP: {body}"
        );
        assert!(body.contains("xfp=http"), "X-Forwarded-Proto set: {body}");
        assert!(body.contains("path=/hello"), "path forwarded: {body}");

        // (2) Static serving from the document root.
        let r = client
            .get(&base)
            .header(host.clone(), "static.example.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "STATIC-OK");

        // (2a) Hidden files are never served (no .env/.git/.secret disclosure).
        let r = client
            .get(format!("{base}.secret"))
            .header(host.clone(), "static.example.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "a dotfile must not be served");

        // (2b) Byte-range request → 206 with the exact slice + Content-Range.
        let r = client
            .get(&base)
            .header(host.clone(), "static.example.test")
            .header(reqwest::header::RANGE, "bytes=0-3")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 206, "a satisfiable Range yields 206");
        assert_eq!(
            r.headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            Some("bytes 0-3/9"),
            "Content-Range reports the slice and total length"
        );
        assert_eq!(
            r.text().await.unwrap(),
            "STAT",
            "the first 4 bytes of STATIC-OK"
        );

        // (3) Basic auth: 401 without creds, 200 with the right creds.
        let r = client
            .get(&base)
            .header(host.clone(), "auth.example.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "guarded site challenges without creds");
        assert!(r.headers().contains_key(reqwest::header::WWW_AUTHENTICATE));

        let r = client
            .get(&base)
            .header(host.clone(), "auth.example.test")
            .basic_auth("user", Some("pw"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "correct credentials are admitted");

        let r = client
            .get(&base)
            .header(host.clone(), "auth.example.test")
            .basic_auth("user", Some("WRONG"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "wrong password is rejected");

        // (4) Unmanaged host → the default-site 404.
        let r = client
            .get(&base)
            .header(host, "nobody.example.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "unmatched host hits the default site");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_reload_under_concurrency_drops_nothing() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream().await;
        let www = unique_tmp("reload-static");
        publish_full_config(upstream, &www);
        let edge = spawn_edge().await;

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let base = format!("http://{edge}/");

        // Hammer the proxy with concurrent requests while repeatedly republishing
        // the config underneath them. The ArcSwap swap must never drop or error a
        // request: an in-flight one finishes on its snapshot, a new one picks up
        // the next. We assert every single request got a 200.
        let mut tasks = Vec::new();
        for i in 0..200u32 {
            let client = client.clone();
            let base = base.clone();
            tasks.push(tokio::spawn(async move {
                let r = client
                    .get(format!("{base}req/{i}"))
                    .header(reqwest::header::HOST, "proxy.example.test")
                    .send()
                    .await?;
                let status = r.status();
                // Drain the body so the connection can be reused/closed cleanly.
                let _ = r.bytes().await?;
                Ok::<u16, reqwest::Error>(status.as_u16())
            }));

            // Interleave reloads with the in-flight traffic.
            if i % 20 == 0 {
                publish_full_config(upstream, &www);
            }
        }

        let mut ok = 0;
        for t in tasks {
            let status = t
                .await
                .expect("request task did not panic")
                .expect("no transport error");
            assert_eq!(status, 200, "every request under reload must succeed");
            ok += 1;
        }
        assert_eq!(
            ok, 200,
            "all 200 concurrent requests completed across reloads"
        );
    }

    /// A throughput + latency benchmark (run explicitly). Fires `EDGE_BENCH_TOTAL`
    /// requests through the proxy with up to `EDGE_BENCH_CONCURRENCY` in flight at
    /// once and reports req/s, error count, and a latency distribution — a stress
    /// check that the data plane holds up under high concurrency without dropping
    /// or erroring requests. #[ignore] so it never runs in the normal suite.
    ///
    /// e.g. 10k concurrency:
    ///   EDGE_BENCH_CONCURRENCY=10000 EDGE_BENCH_TOTAL=100000 \
    ///     cargo test --release --bin dn7-panel edge_bench -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "throughput benchmark; run with --ignored --nocapture"]
    async fn edge_bench_throughput() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream().await;
        let www = unique_tmp("bench-static");
        publish_full_config(upstream, &www);
        let edge = spawn_edge().await;

        let total: usize = std::env::var("EDGE_BENCH_TOTAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20_000);
        let concurrency: usize = std::env::var("EDGE_BENCH_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(256);

        let client = std::sync::Arc::new(
            reqwest::Client::builder()
                .no_proxy()
                // Warm pool as large as the concurrency so keepalive connections
                // are reused rather than re-dialed every request.
                .pool_max_idle_per_host(concurrency)
                .build()
                .unwrap(),
        );
        let base = format!("http://{edge}/");

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let start = std::time::Instant::now();
        let mut handles = Vec::with_capacity(total);
        for _ in 0..total {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let base = base.clone();
            // Each task returns its latency in µs (None on error), so we collect
            // the distribution without a shared lock on the hot path.
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let t0 = std::time::Instant::now();
                match client
                    .get(&base)
                    .header(reqwest::header::HOST, "proxy.example.test")
                    .send()
                    .await
                {
                    Ok(r) if r.status() == 200 => {
                        let _ = r.bytes().await;
                        Some(t0.elapsed().as_micros() as u64)
                    }
                    _ => None,
                }
            }));
        }

        let mut lats: Vec<u64> = Vec::with_capacity(total);
        let mut errs = 0u64;
        for h in handles {
            match h.await {
                Ok(Some(us)) => lats.push(us),
                _ => errs += 1,
            }
        }
        let elapsed = start.elapsed();

        lats.sort_unstable();
        let pct = |p: f64| -> f64 {
            if lats.is_empty() {
                return 0.0;
            }
            let idx = ((lats.len() as f64 * p) as usize).min(lats.len() - 1);
            lats[idx] as f64 / 1000.0
        };
        let avg_ms = if lats.is_empty() {
            0.0
        } else {
            lats.iter().sum::<u64>() as f64 / lats.len() as f64 / 1000.0
        };
        let max_ms = lats.last().copied().unwrap_or(0) as f64 / 1000.0;
        let rps = total as f64 / elapsed.as_secs_f64();
        println!(
            "\n[edge bench] total={total} concurrency={concurrency}: {rps:.0} req/s in {:.2}s, errors={errs}",
            elapsed.as_secs_f64()
        );
        println!(
            "[edge bench] latency (ms): avg={avg_ms:.2} p50={:.2} p90={:.2} p99={:.2} max={max_ms:.2}\n",
            pct(0.50),
            pct(0.90),
            pct(0.99),
        );
        assert_eq!(errs, 0, "no request may error under sustained concurrency");
    }

    // ---- external high-concurrency benchmark (oha) ------------------------

    /// A throwaway upstream HTTP server on its OWN dedicated multi-thread runtime
    /// (separate OS threads), so it doesn't steal worker threads from the edge's
    /// runtime during the load test. Returns its bound address.
    fn spawn_upstream_dedicated(threads: usize) -> std::net::SocketAddr {
        use http_body_util::Full;
        use hyper::service::service_fn;
        use hyper::Response;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        continue;
                    };
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(async move {
                        let svc = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                bytes::Bytes::from_static(b"UPSTREAM-OK"),
                            )))
                        });
                        let _ = auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
        });
        rx.recv().unwrap()
    }

    /// Drive `url` (with a `Host` header) using the external `oha` load tool — a
    /// SEPARATE process, so the load generator never competes with the edge for
    /// its own runtime threads. Returns oha's full text report.
    async fn run_oha(url: &str, host: &str, conc: usize, dur: &str, insecure: bool) -> String {
        let conc_s = conc.to_string();
        let host_h = format!("Host: {host}");
        let mut args: Vec<&str> = vec!["--no-tui", "-c", &conc_s, "-z", dur, "-H", &host_h];
        if insecure {
            args.push("--insecure"); // self-signed cert in the TLS benchmark
        }
        args.push(url);
        let out = tokio::process::Command::new("oha")
            .args(&args)
            .output()
            .await
            .expect("run oha (is it installed?)");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// High-concurrency benchmark with a clean topology: the edge on its own
    /// runtime, the upstream on a dedicated runtime, and `oha` (an external
    /// process) generating the load. Run explicitly:
    ///   EDGE_BENCH_CONCURRENCY=10000 EDGE_BENCH_DURATION=10s \
    ///     cargo test --release --bin dn7-panel edge_oha -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "external oha load test; run with --ignored --nocapture"]
    async fn edge_oha_high_concurrency() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream_dedicated(4);
        let www = unique_tmp("oha-static");
        publish_full_config(upstream, &www);
        let edge = spawn_edge().await;

        let conc: usize = std::env::var("EDGE_BENCH_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let dur = std::env::var("EDGE_BENCH_DURATION").unwrap_or_else(|_| "10s".into());
        let url = format!("http://{edge}/");

        println!("\n========== REVERSE-PROXY path · concurrency={conc} · {dur} ==========");
        println!(
            "{}",
            run_oha(&url, "proxy.example.test", conc, &dur, false).await
        );

        println!("========== STATIC path · concurrency={conc} · {dur} ==========");
        println!(
            "{}",
            run_oha(&url, "static.example.test", conc, &dur, false).await
        );
    }

    /// Write a self-signed cert as the catch-all `default.crt`/`default.key` in
    /// `cert_dir`, so the edge's SNI resolver presents it for any host (the TLS
    /// benchmark drives it with `oha --insecure`).
    fn write_default_cert(cert_dir: &std::path::Path) {
        std::fs::create_dir_all(cert_dir).unwrap();
        // Same rcgen API the panel's own self-signed path uses (certs/issue.rs).
        let params = rcgen::CertificateParams::new(vec![
            "localhost".to_string(),
            "proxy.example.test".to_string(),
            "static.example.test".to_string(),
        ])
        .unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        std::fs::write(cert_dir.join("default.crt"), cert.pem()).unwrap();
        std::fs::write(cert_dir.join("default.key"), key_pair.serialize_pem()).unwrap();
    }

    /// Build + publish a 2-site (proxy + static) TLS runtime from `cert_dir`.
    /// Callers that need the cert/static files on disk write them first.
    fn publish_tls_runtime(
        upstream: std::net::SocketAddr,
        www: &std::path::Path,
        cert_dir: &std::path::Path,
    ) {
        let mut proxy = base_site("p", "proxy.example.test", "proxy_host");
        proxy.target_url = upstream.to_string();
        proxy.force_ssl = false;

        let mut stat = base_site("s", "static.example.test", "static");
        stat.local_root = www.to_string_lossy().to_string();
        stat.force_ssl = false;

        let input = ReloadInput {
            sites: vec![proxy, stat],
            access: Vec::new(),
            default_site: DefaultSite::default(),
            tuning: HttpTuning::default(),
            cert_dir: cert_dir.to_path_buf(),
            www_dir: unique_tmp("tls-www"),
            console: test_console(),
        };
        let cfg = build::build_runtime(&input).expect("tls config builds");
        store::publish(std::sync::Arc::new(cfg));
    }

    /// Like `publish_full_config`, but writes a default cert into `cert_dir` so
    /// the TLS listener has a certificate to present.
    fn publish_tls_config(
        upstream: std::net::SocketAddr,
        www: &std::path::Path,
        cert_dir: &std::path::Path,
    ) {
        std::fs::create_dir_all(www).unwrap();
        std::fs::write(www.join("index.html"), "STATIC-OK").unwrap();
        write_default_cert(cert_dir);
        publish_tls_runtime(upstream, www, cert_dir);
    }

    /// Bind the edge TLS listener on an ephemeral loopback port and start serving.
    async fn spawn_edge_tls() -> std::net::SocketAddr {
        // The proxy's HTTPS upstream client (built lazily) resolves the rustls
        // process-default provider; install ring so it can't panic. Idempotent.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(super::super::tls::server_config().unwrap());
        tokio::spawn(super::super::listener::serve_tls(listener, acceptor));
        addr
    }

    /// TLS high-concurrency benchmark — same clean topology as the plain run but
    /// terminating TLS (rustls/ring). Measures the handshake + record-layer cost
    /// at high concurrency. Run explicitly:
    ///   EDGE_BENCH_CONCURRENCY=10000 EDGE_BENCH_DURATION=10s \
    ///     cargo test --release --bin dn7-panel edge_oha_tls -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "external oha TLS load test; run with --ignored --nocapture"]
    async fn edge_oha_tls_high_concurrency() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream_dedicated(4);
        let www = unique_tmp("oha-tls-static");
        let cert_dir = unique_tmp("oha-tls-certs");
        publish_tls_config(upstream, &www, &cert_dir);
        let edge = spawn_edge_tls().await;

        let conc: usize = std::env::var("EDGE_BENCH_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let dur = std::env::var("EDGE_BENCH_DURATION").unwrap_or_else(|_| "10s".into());
        let url = format!("https://{edge}/");

        println!("\n========== TLS REVERSE-PROXY · concurrency={conc} · {dur} ==========");
        println!(
            "{}",
            run_oha(&url, "proxy.example.test", conc, &dur, true).await
        );

        println!("========== TLS STATIC · concurrency={conc} · {dur} ==========");
        println!(
            "{}",
            run_oha(&url, "static.example.test", conc, &dur, true).await
        );
    }

    // ---- soak / leak test (fd + RSS over load→drain cycles) ---------------

    /// Run a shell snippet and parse its stdout as a number (0 on failure).
    async fn sh_num(cmd: &str) -> u64 {
        let out = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await
            .expect("run shell probe");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0)
    }

    /// Total open file descriptors for `pid` (lsof; one line per fd + a header).
    async fn count_fds(pid: u32) -> u64 {
        sh_num(&format!("lsof -p {pid} -n -P 2>/dev/null | wc -l")).await
    }

    /// Open network sockets for `pid` (the connection-leak signal).
    async fn count_net_fds(pid: u32) -> u64 {
        sh_num(&format!("lsof -a -p {pid} -i -n -P 2>/dev/null | wc -l")).await
    }

    /// Resident set size of `pid` in KiB (macOS/Linux `ps`).
    async fn rss_kb(pid: u32) -> u64 {
        sh_num(&format!("ps -o rss= -p {pid} 2>/dev/null")).await
    }

    /// Endurance test: drive sustained load in cycles and verify the process's
    /// file descriptors and memory return to a steady level after each burst
    /// drains — i.e. nothing (sockets, file handles, tasks holding either) leaks
    /// across cycles. The proxy path exercises the richest surface: inbound
    /// connections, the upstream connection pool, body/timeout wrappers, and the
    /// container-resolution cache. Run explicitly (it takes a few minutes):
    ///   cargo test --release --bin dn7-panel edge_soak -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "long-running soak/leak test; run with --ignored --nocapture"]
    async fn edge_soak_no_leak() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream_dedicated(2);
        let www = unique_tmp("soak-static");
        publish_full_config(upstream, &www);
        let edge = spawn_edge().await;
        let pid = std::process::id();

        let cycles: usize = std::env::var("EDGE_SOAK_CYCLES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        let load = std::env::var("EDGE_SOAK_LOAD").unwrap_or_else(|_| "15s".into());
        let conc: usize = std::env::var("EDGE_SOAK_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);
        // Drain window must exceed the pool's reaper worst case: the idle reaper
        // runs on an interval, so a connection can take up to ~2x the 30s idle
        // timeout to be closed. 70s lets fds fully return to baseline.
        let drain: u64 = std::env::var("EDGE_SOAK_DRAIN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(70);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let fd_base = count_fds(pid).await;
        let net_base = count_net_fds(pid).await;
        let rss_base = rss_kb(pid).await;
        println!("\n[soak] baseline: fds={fd_base} net={net_base} rss={rss_base}KiB");
        println!("[soak] {cycles} cycles · load={load} · concurrency={conc} · drain={drain}s\n");

        let mut rest_fds = Vec::new();
        let mut rest_rss = Vec::new();
        for c in 1..=cycles {
            // Load burst (proxy path).
            let _ = run_oha(
                &format!("http://{edge}/"),
                "proxy.example.test",
                conc,
                &load,
                false,
            )
            .await;
            let fd_peak = count_fds(pid).await;
            let net_peak = count_net_fds(pid).await;

            // Let connections + idle pool drain, then sample the resting level.
            tokio::time::sleep(std::time::Duration::from_secs(drain)).await;
            let fd_rest = count_fds(pid).await;
            let net_rest = count_net_fds(pid).await;
            let rss = rss_kb(pid).await;
            println!(
                "[soak] cycle {c}: peak fds={fd_peak} (net {net_peak}) → rest fds={fd_rest} (net {net_rest}) rss={rss}KiB"
            );
            rest_fds.push(fd_rest);
            rest_rss.push(rss);
        }

        let fd0 = rest_fds[0];
        let fd_last = *rest_fds.last().unwrap();
        let rss0 = rest_rss[0];
        let rss_last = *rest_rss.last().unwrap();
        println!("\n[soak] resting fds:  first={fd0}  last={fd_last}  (baseline {fd_base})");
        println!(
            "[soak] resting rss:  first={rss0}KiB  last={rss_last}KiB  (baseline {rss_base}KiB)\n"
        );

        // fd/socket leak: after draining, the resting fd count must not ratchet
        // up cycle over cycle. A small slack absorbs lsof timing + a few lingering
        // TIME_WAIT-ish handles.
        assert!(
            fd_last <= fd0 + 64,
            "fd leak suspected: resting fds grew {fd0} → {fd_last} across {cycles} cycles"
        );
        // Memory: the allocator may retain freed pages, so allow generous slack,
        // but catch unbounded growth across cycles.
        assert!(
            rss_last <= rss0 + rss0 / 2 + 50_000,
            "rss leak suspected: resting rss grew {rss0}KiB → {rss_last}KiB across {cycles} cycles"
        );
    }

    // ---- CPU probe --------------------------------------------------------

    /// Total CPU time (user + system) this process has consumed, in seconds,
    /// via getrusage(2) — microsecond resolution.
    fn cpu_time_secs() -> f64 {
        // SAFETY: getrusage just fills a zeroed rusage we own and returns a
        // status we ignore.
        let mut u: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe {
            libc::getrusage(libc::RUSAGE_SELF, &mut u);
        }
        let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        tv(u.ru_utime) + tv(u.ru_stime)
    }

    /// A `ps` field parsed as f64 (e.g. %cpu).
    async fn ps_f64(cmd: &str) -> f64 {
        let out = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await
            .expect("run ps probe");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0.0)
    }

    /// Pull the `[200]` success count out of an oha report.
    fn parse_oha_200(report: &str) -> u64 {
        for line in report.lines() {
            let l = line.trim();
            if l.starts_with("[200]") {
                return l
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        0
    }

    /// Pull `Requests/sec:` out of an oha report.
    fn parse_oha_rps(report: &str) -> f64 {
        for line in report.lines() {
            if line.contains("Requests/sec:") {
                return line
                    .split_whitespace()
                    .last()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
            }
        }
        0.0
    }

    /// Probe CPU cost: idle %CPU, then CPU-seconds consumed under a load burst
    /// → CPU-µs per request and cores-busy. NOTE: the process also runs the
    /// colocated test upstream, so these slightly OVERSTATE the edge's own cost.
    ///   cargo test --release --bin dn7-panel edge_cpu -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "CPU probe; run with --ignored --nocapture"]
    async fn edge_cpu_probe() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream_dedicated(2);
        let www = unique_tmp("cpu-static");
        publish_full_config(upstream, &www);
        let edge = spawn_edge().await;
        let pid = std::process::id();

        let conc: usize = std::env::var("EDGE_BENCH_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);
        let secs = 15.0_f64;

        // Idle: no traffic for a few seconds, then read the instantaneous %CPU.
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        let idle = ps_f64(&format!("ps -o %cpu= -p {pid}")).await;
        println!(
            "\n[cpu] idle (no traffic): {idle:.1}% of one core (process incl. colocated upstream)"
        );

        // Under load: CPU-time delta over the burst.
        let t0 = cpu_time_secs();
        let report = run_oha(
            &format!("http://{edge}/"),
            "proxy.example.test",
            conc,
            &format!("{secs:.0}s"),
            false,
        )
        .await;
        let cpu_used = cpu_time_secs() - t0;
        let reqs = parse_oha_200(&report);
        let rps = parse_oha_rps(&report);
        let per_req_us = if reqs > 0 {
            cpu_used * 1e6 / reqs as f64
        } else {
            0.0
        };
        println!("[cpu] under load (proxy, concurrency={conc}):");
        println!("        {rps:.0} req/s · {reqs} reqs served");
        println!(
            "        {cpu_used:.1} CPU-seconds consumed → {per_req_us:.1} µs CPU/req → ~{:.1} cores busy",
            cpu_used / secs
        );
        println!("        (these include the colocated upstream — the edge alone is lower)\n");
    }

    // ---- handshake-cost experiment ----------------------------------------

    /// Run oha with a fully custom arg list (returns the text report).
    async fn oha_raw(mut args: Vec<String>) -> String {
        args.insert(0, "--no-tui".to_string());
        let out = tokio::process::Command::new("oha")
            .args(&args)
            .output()
            .await
            .expect("run oha");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// Why does a reverse proxy burn CPU at a LOW request rate? Almost always
    /// per-request TLS handshakes / connection setup when keepalive isn't reused.
    /// This holds the request RATE fixed (so throughput is identical across runs)
    /// and measures CPU-µs/request for {plain, TLS} × {keepalive, fresh
    /// connection per request, via --disable-keepalive}. The delta between
    /// keepalive and fresh-connection isolates the inbound connect/handshake
    /// cost — the thing an untuned nginx pays. Run:
    ///   cargo test --release --bin dn7-panel edge_handshake -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "handshake-cost experiment; run with --ignored --nocapture"]
    async fn edge_handshake_cost() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream_dedicated(2);
        let www = unique_tmp("hs-static");
        let cert_dir = unique_tmp("hs-certs");
        publish_tls_config(upstream, &www, &cert_dir);
        // Both listeners read the same published config; one terminates TLS.
        let plain = spawn_edge().await;
        let tls = spawn_edge_tls().await;

        let rate: u64 = std::env::var("EDGE_HS_RATE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);
        let dur = std::env::var("EDGE_HS_DUR").unwrap_or_else(|_| "12s".into());
        // Drain TIME_WAIT between runs so fresh-connection runs don't exhaust
        // loopback ports.
        let drain = 25u64;

        // (label, url, insecure, disable_keepalive)
        let combos: [(&str, String, bool, bool); 4] = [
            (
                "plain · keepalive   ",
                format!("http://{plain}/"),
                false,
                false,
            ),
            (
                "plain · fresh-conn  ",
                format!("http://{plain}/"),
                false,
                true,
            ),
            (
                "TLS   · keepalive   ",
                format!("https://{tls}/"),
                true,
                false,
            ),
            (
                "TLS   · fresh-conn  ",
                format!("https://{tls}/"),
                true,
                true,
            ),
        ];

        println!(
            "\n[hs] fixed rate = {rate} req/s · {dur} per run (CPU incl. colocated upstream)\n"
        );
        let mut per_req = Vec::new();
        for (label, url, insecure, no_ka) in combos {
            tokio::time::sleep(std::time::Duration::from_secs(drain)).await;
            let mut args = vec![
                "-H".to_string(),
                "Host: proxy.example.test".to_string(),
                "-c".to_string(),
                "50".to_string(),
                "-q".to_string(),
                rate.to_string(),
                "-z".to_string(),
                dur.clone(),
            ];
            if insecure {
                args.push("--insecure".to_string());
            }
            if no_ka {
                args.push("--disable-keepalive".to_string());
            }
            args.push(url);

            let t0 = cpu_time_secs();
            let report = oha_raw(args).await;
            let cpu = cpu_time_secs() - t0;
            let reqs = parse_oha_200(&report);
            let rps = parse_oha_rps(&report);
            let per = if reqs > 0 {
                cpu * 1e6 / reqs as f64
            } else {
                0.0
            };
            println!("[hs] {label}: {rps:>5.0} req/s · {reqs:>6} reqs · {cpu:>5.2} CPU-s → {per:>6.0} µs CPU/req");
            per_req.push(per);
        }

        let (p_ka, p_new, t_ka, t_new) = (per_req[0], per_req[1], per_req[2], per_req[3]);
        println!("\n[hs] ── isolated per-request costs ──");
        println!(
            "[hs] TCP connect (plain fresh − keepalive):   {:>6.0} µs/req",
            p_new - p_ka
        );
        println!(
            "[hs] TLS handshake (TLS fresh − TLS keepalive):{:>6.0} µs/req",
            t_new - t_ka
        );
        println!(
            "[hs] → pure TLS-handshake CPU (minus TCP):     {:>6.0} µs/req",
            (t_new - t_ka) - (p_new - p_ka)
        );
        if t_ka > 0.0 {
            println!(
                "[hs] → TLS fresh-conn costs {:.1}× the CPU/req of TLS keepalive\n",
                t_new / t_ka
            );
        }
    }

    // ---- RSA vs ECDSA handshake cost --------------------------------------

    /// Generate an RSA-2048 self-signed cert (via openssl) as the default cert,
    /// to contrast with the ECDSA P-256 one `write_default_cert` produces. oha
    /// runs with `--insecure`, so the cert's name/SAN don't need to match.
    async fn write_rsa_cert(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).unwrap();
        let crt = dir.join("default.crt");
        let key = dir.join("default.key");
        let cmd = format!(
            "openssl req -x509 -newkey rsa:2048 -keyout '{}' -out '{}' -days 365 -nodes -subj '/CN=localhost' 2>/dev/null",
            key.display(),
            crt.display()
        );
        let status = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status()
            .await
            .expect("run openssl");
        assert!(
            status.success() && crt.exists() && key.exists(),
            "openssl RSA cert generation failed"
        );
    }

    /// (Re)publish the TLS config from `cert_dir` (which must already contain
    /// default.crt/default.key). The TLS listener's SNI resolver reads the store
    /// live, so this swaps the presented cert without re-binding.
    fn republish_tls_config(
        upstream: std::net::SocketAddr,
        www: &std::path::Path,
        cert_dir: &std::path::Path,
    ) {
        publish_tls_runtime(upstream, www, cert_dir);
    }

    /// Measure CPU-µs/request for a TLS run at a fixed rate (returns cpu/req).
    async fn measure_tls_cpu(url: &str, no_ka: bool, rate: u64, dur: &str) -> f64 {
        let mut args = vec![
            "-H".to_string(),
            "Host: proxy.example.test".to_string(),
            "-c".to_string(),
            "50".to_string(),
            "-q".to_string(),
            rate.to_string(),
            "-z".to_string(),
            dur.to_string(),
            "--insecure".to_string(),
        ];
        if no_ka {
            args.push("--disable-keepalive".to_string());
        }
        args.push(url.to_string());
        let t0 = cpu_time_secs();
        let report = oha_raw(args).await;
        let cpu = cpu_time_secs() - t0;
        let reqs = parse_oha_200(&report);
        if reqs > 0 {
            cpu * 1e6 / reqs as f64
        } else {
            0.0
        }
    }

    /// The cert-type effect: RSA-2048 vs ECDSA P-256 TLS-handshake CPU cost. The
    /// server-side RSA private-key operation is far more expensive than ECDSA,
    /// which is the likely reason an RSA-cert nginx burns cores at a low request
    /// rate where an ECDSA edge stays cheap. Run:
    ///   cargo test --release --bin dn7-panel edge_rsa -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "RSA-vs-ECDSA handshake experiment; run with --ignored --nocapture"]
    async fn edge_rsa_vs_ecdsa_handshake() {
        let _g = serial().lock().await;
        let upstream = spawn_upstream_dedicated(2);
        let www = unique_tmp("hsx-static");
        std::fs::create_dir_all(&www).unwrap();
        std::fs::write(www.join("index.html"), "OK").unwrap();
        let dir_ec = unique_tmp("hsx-ec");
        let dir_rsa = unique_tmp("hsx-rsa");
        write_default_cert(&dir_ec); // ECDSA P-256 (rcgen default)
        write_rsa_cert(&dir_rsa).await; // RSA-2048 (openssl)
        let tls = spawn_edge_tls().await;
        let url = format!("https://{tls}/");

        let rate: u64 = std::env::var("EDGE_HS_RATE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);
        let dur = "12s";
        let drain = 25u64;
        let nap = || tokio::time::sleep(std::time::Duration::from_secs(drain));

        println!(
            "\n[rsa] fixed rate = {rate} req/s · {dur} per run (CPU incl. colocated upstream)\n"
        );

        republish_tls_config(upstream, &www, &dir_ec);
        nap().await;
        let ec_ka = measure_tls_cpu(&url, false, rate, dur).await;
        nap().await;
        let ec_new = measure_tls_cpu(&url, true, rate, dur).await;

        republish_tls_config(upstream, &www, &dir_rsa);
        nap().await;
        let rsa_ka = measure_tls_cpu(&url, false, rate, dur).await;
        nap().await;
        let rsa_new = measure_tls_cpu(&url, true, rate, dur).await;

        let hs_ec = ec_new - ec_ka;
        let hs_rsa = rsa_new - rsa_ka;
        println!("[rsa] ECDSA P-256: keepalive {ec_ka:>5.0} / fresh {ec_new:>5.0} µs/req → handshake {hs_ec:>5.0} µs/req");
        println!("[rsa] RSA-2048   : keepalive {rsa_ka:>5.0} / fresh {rsa_new:>5.0} µs/req → handshake {hs_rsa:>5.0} µs/req");
        println!("[rsa] (each handshake delta includes ~40µs common TCP connect)");
        if hs_ec > 0.0 {
            println!(
                "[rsa] → RSA-2048 handshake costs {:.1}× the CPU of ECDSA P-256\n",
                hs_rsa / hs_ec
            );
        }
    }
}
