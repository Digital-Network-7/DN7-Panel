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

    use super::super::build::{self, ReloadInput};
    use super::super::config::{
        AccessControl, AclNet, AclRule, DefaultRoute, RouteKind, RuntimeConfig, ServerRoute,
    };
    use super::super::store;
    use super::super::validate;

    use crate::core::nginx::{
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
        let p = cfg.route_for("proxy.example.com").expect("proxy host indexed");
        assert!(
            matches!(p.kind, RouteKind::Proxy(_)),
            "proxy_host must project to RouteKind::Proxy"
        );

        // static → RouteKind::Static with the root joined under www_dir.
        let s = cfg.route_for("static.example.com").expect("static host indexed");
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
        let c = cfg.route_for("secure.example.com").expect("ssl host indexed");
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
        assert!(wildcard_matches("foo.example.com", suffix), "one label matches");
        assert!(
            !wildcard_matches("foo.bar.example.com", suffix),
            "a deeper subdomain must NOT match (nginx single-label semantics)"
        );
        assert!(
            !wildcard_matches("example.com", suffix),
            "the bare apex (empty label) must not match the wildcard"
        );
        assert!(!wildcard_matches("foo.other.com", suffix), "different domain");
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
        let cfg = route(
            "ssl1",
            "secure.example.com",
            true,
            RouteKind::Maintenance,
        );
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
        assert!(
            live.route_for(host_b).is_none(),
            "host_b not published yet"
        );

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
            crate::infra::nginx::verify_htpasswd_hash(hash, "secret-pw"),
            "the right password must verify against its apr1 hash"
        );
        assert!(
            !crate::infra::nginx::verify_htpasswd_hash(hash, "wrong-pw"),
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
        };
        let cfg = build::build_runtime(&input).expect("guarded site builds");
        let route = cfg.route_for("guarded.example.com").expect("guarded indexed");
        let ac = route.access.as_ref().expect("access list must be attached");
        assert!(ac.satisfy_all, "satisfy \"all\" projects to satisfy_all=true");
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
        assert_eq!(r.text().await.unwrap(), "STAT", "the first 4 bytes of STATIC-OK");

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
            let status = t.await.expect("request task did not panic").expect("no transport error");
            assert_eq!(status, 200, "every request under reload must succeed");
            ok += 1;
        }
        assert_eq!(ok, 200, "all 200 concurrent requests completed across reloads");
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
    async fn run_oha(url: &str, host: &str, conc: usize, dur: &str) -> String {
        let out = tokio::process::Command::new("oha")
            .args([
                "--no-tui",
                "-c",
                &conc.to_string(),
                "-z",
                dur,
                "-H",
                &format!("Host: {host}"),
                url,
            ])
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
        println!("{}", run_oha(&url, "proxy.example.test", conc, &dur).await);

        println!("========== STATIC path · concurrency={conc} · {dur} ==========");
        println!("{}", run_oha(&url, "static.example.test", conc, &dur).await);
    }
}
