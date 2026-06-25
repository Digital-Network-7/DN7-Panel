//! [M2] Reverse-proxy data plane: forward a request to an upstream, stream the
//! response back, and tunnel WebSocket upgrades.
//!
//! This is the in-process replacement for the `proxy_pass` half of the generated
//! nginx `location` blocks. Two request shapes are handled:
//!
//!   * Ordinary requests go through a process-wide pooled `hyper_util` legacy
//!     client (keepalive + HTTP/1.1 and HTTP/2 to the upstream, https via rustls
//!     with the webpki roots). The upstream body is streamed straight back with
//!     no buffering.
//!   * WebSocket upgrades (and any other `Connection: upgrade`) can't ride the
//!     pooled client because we need to take ownership of both the inbound and
//!     the upstream byte streams after the `101`. For those we open a dedicated
//!     one-shot `hyper::client::conn::http1` connection, forward the upgrade
//!     headers verbatim, relay the `101`, and `copy_bidirectional` the two
//!     upgraded streams until either side closes.
//!
//! Header rewriting mirrors `confgen`'s `proxy_location`: rebuild `Host` to the
//! upstream authority, set `X-Real-IP`, synthesise `X-Forwarded-For`
//! (`$proxy_add_x_forwarded_for`), set `X-Forwarded-Proto` from the inbound
//! scheme, optionally strip `Authorization`, and drop hop-by-hop headers in both
//! directions (kept intact only for the WS handshake).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, StatusCode};
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::sync::RwLock;

use super::config::{ProxyTarget, Tuning, Upstream};
use super::listener::ConnCtx;
use super::response::{self, Resp};
use super::timeout_body::ProxyReqBody;

/// How long a resolved `proxy_container` upstream address is cached before we
/// ask the Docker daemon again. Resolving per request would put a daemon
/// round-trip on the hot path for every request to a container-backed site —
/// orders of magnitude slower than nginx under load. A short TTL keeps us fast
/// while still healing an IP/port drift within a few seconds (the panel's
/// background resync handles the slower-moving cases). Fixed upstreams never
/// touch this path.
const CONTAINER_TTL: Duration = Duration::from_secs(3);

/// Bound a single container resolution (Docker daemon round-trip) so a hung
/// daemon can't pin request tasks.
const CONTAINER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Upstream connect timeout — a hung dial must not pin a request (or a pooled
/// connection slot) indefinitely; fail fast to 502 instead.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Request-body inactivity timeout (nginx `client_body_timeout` equivalent): a
/// proxied upload that stalls for this long is aborted, so a trickle/slowloris
/// body can't hold a connection open. Resets on every byte, so a slow-but-steady
/// large upload is fine.
const BODY_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

/// Hop-by-hop headers (RFC 7230 §6.1) that are scoped to a single transport hop
/// and must not be forwarded through a proxy. Stripped from both the request we
/// send upstream and the response we send back — except during a WebSocket
/// upgrade, where `connection`/`upgrade` are exactly the headers that carry the
/// handshake and must survive end to end.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The process-wide pooled upstream client. Built once on first use so we keep
/// connection pools/keepalive across requests instead of dialing per request.
/// Body type pinned to [`Incoming`] so we can forward `req.into_body()` directly
/// without re-boxing the request body.
static CLIENT: OnceLock<Client<HttpsConnector, ProxyReqBody>> = OnceLock::new();

/// The connector type for the pooled client: rustls-over-TCP with HTTP/1 and
/// HTTP/2 negotiated via ALPN, falling back to plain HTTP for `http://`
/// upstreams.
type HttpsConnector = hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

/// Lazily build (and cache) the shared pooled client. Tuned for a busy edge:
/// bounded idle pool per host with keepalive reuse, TCP_NODELAY for low latency,
/// and a connect timeout so a dead upstream fails fast instead of pinning slots.
fn client() -> &'static Client<HttpsConnector, ProxyReqBody> {
    CLIENT.get_or_init(|| {
        // The base TCP connector: NODELAY (proxies are latency-sensitive) and a
        // bounded connect timeout so a black-holed upstream can't stall a request
        // (and its pooled slot) forever.
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));
        // TCP keepalive so a dead pooled upstream connection is detected and
        // reaped instead of being handed out as a half-open zombie.
        http.set_keepalive(Some(Duration::from_secs(30)));
        http.enforce_http(false); // let the https layer handle `https://` upstreams

        // webpki roots keep us pure-Rust (no system trust store / C openssl);
        // `https_or_http` lets a single connector serve both http and https
        // upstreams so we don't branch the pooled path on scheme.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);

        Client::builder(TokioExecutor::new())
            // Keep a large warm pool per upstream so high-concurrency bursts reuse
            // keepalive connections instead of dialing (and exhausting ephemeral
            // ports) on every request.
            .pool_max_idle_per_host(8192)
            // Reap connections idle longer than this so a busy-then-quiet upstream
            // doesn't hold fds forever. CRITICAL: the idle reaper only runs when a
            // `pool_timer` is set — without it `pool_idle_timeout` is a no-op and
            // idle connections linger until reused (a soak test caught this).
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_timer(TokioTimer::new())
            .build(connector)
    })
}

/// Proxy `req` to `target`. `client_ip` is the already-resolved real client IP
/// (post real_ip), `ctx` carries the inbound scheme for `X-Forwarded-Proto`.
pub(crate) async fn handle(
    mut req: Request<Incoming>,
    target: &ProxyTarget,
    ctx: &ConnCtx,
    client_ip: IpAddr,
    tuning: &Tuning,
) -> Resp {
    // Enforce `client_max_body_size` early via the declared Content-Length, so an
    // oversized upload is rejected with 413 before we dial the upstream. (The
    // body is streamed, never buffered, so this is parity with nginx's cap rather
    // than a memory-safety guard; a chunked body without Content-Length is capped
    // by the upstream, not here.)
    if tuning.client_max_body_size > 0 {
        if let Some(len) = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if len > tuning.client_max_body_size {
                return response::text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "413 Request Entity Too Large",
                );
            }
        }
    }

    // Resolve the upstream `host:port` now (containers resolve through a short
    // TTL cache so a drift heals without a reload and without a per-request
    // daemon call). An unresolvable container upstream is the maintenance
    // signal: serve 503, not a hard 502.
    let authority = match resolve_authority(&target.upstream).await {
        Some(a) => a,
        None => return response::status(StatusCode::SERVICE_UNAVAILABLE),
    };

    // Detect the WebSocket (Upgrade) handshake up front: it needs a dedicated
    // connection and a different header policy (keep connection/upgrade).
    let is_ws = target.websockets && is_websocket_upgrade(req.headers());

    // "Cache assets" on a proxy site: long-cache the response for static-asset
    // paths (mirrors confgen's proxied-asset `expires 7d` block). Decided from the
    // ORIGINAL request path, before the URI is rewritten to the upstream.
    let add_asset_cache = target.cache_assets && !is_ws && is_asset_path(req.uri().path());

    // Build the upstream request URI: scheme://authority/path?query.
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri_str = format!("{}://{}{}", target.scheme, authority, path_and_query);
    let new_uri = match uri_str.parse::<http::Uri>() {
        Ok(u) => u,
        Err(_) => return response::status(StatusCode::BAD_GATEWAY),
    };
    *req.uri_mut() = new_uri;

    // Rewrite the forwarded headers (Host/X-Real-IP/XFF/XFP/strip-auth). For a
    // WS upgrade we must NOT strip connection/upgrade — they carry the handshake.
    rewrite_request_headers(req.headers_mut(), &authority, ctx, client_ip, target, is_ws);

    let mut resp = if is_ws {
        proxy_websocket(req, target, &authority).await
    } else {
        proxy_plain(req).await
    };
    if add_asset_cache {
        // Don't clobber an upstream that already set its own caching policy.
        if !resp.headers().contains_key(http::header::CACHE_CONTROL) {
            resp.headers_mut().insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=604800"),
            );
        }
    }
    resp
}

/// Static-asset file extensions that get a long cache lifetime under the proxy
/// "cache assets" toggle (mirrors confgen's `ASSET_EXT` set).
const ASSET_EXTS: &[&str] = &[
    "css", "js", "jpg", "jpeg", "png", "gif", "ico", "svg", "webp", "avif", "woff", "woff2", "ttf",
    "otf", "eot", "mp4", "webm", "mp3", "map",
];

/// Whether the request path's last segment ends in a cacheable asset extension.
fn is_asset_path(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        Some((_, ext)) => ASSET_EXTS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

/// Resolve the upstream into a concrete `host:port` authority. A `Fixed`
/// upstream is used verbatim; a `Container` upstream is resolved at request time
/// against the docker daemon. `None` means "unresolvable" (→ 503).
async fn resolve_authority(upstream: &Upstream) -> Option<String> {
    match upstream {
        Upstream::Fixed(hostport) => Some(hostport.clone()),
        Upstream::Container { name, port } => resolve_container_cached(name, *port).await,
    }
}

/// The process-wide `proxy_container` resolution cache: `"name:port"` →
/// (resolved `host:port`, when-resolved).
fn container_cache() -> &'static RwLock<HashMap<String, (String, Instant)>> {
    static C: OnceLock<RwLock<HashMap<String, (String, Instant)>>> = OnceLock::new();
    C.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Per-key single-flight locks: under a stampede (many concurrent first
/// requests to the same container), only ONE task talks to the Docker daemon;
/// the rest wait on its result. Without this a burst would fan out one daemon
/// round-trip per request — exactly the per-request-daemon-call cost the cache
/// exists to avoid.
fn container_inflight() -> &'static std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    static M: OnceLock<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Resolve a container upstream through the TTL cache with single-flight. A
/// fresh hit returns immediately (no daemon call); on a miss exactly one task
/// resolves via the daemon (bounded by a timeout) while concurrent callers for
/// the same key wait and then reuse the freshly-cached result. On a resolution
/// error the stale entry is evicted so we fail closed (503) rather than proxy to
/// a recycled address.
async fn resolve_container_cached(name: &str, port: i64) -> Option<String> {
    let key = format!("{name}:{port}");

    // Fast path: a fresh cached address under a read lock (lets many concurrent
    // requests share one resolution).
    if let Some(addr) = fresh_cached(&key).await {
        return Some(addr);
    }

    // Miss/stale: take the per-key single-flight lock so a burst collapses to one
    // daemon call.
    let gate = {
        let mut map = container_inflight().lock().unwrap_or_else(|p| p.into_inner());
        map.entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _flight = gate.lock().await;

    // Re-check the cache: another task may have resolved while we waited.
    if let Some(addr) = fresh_cached(&key).await {
        return Some(addr);
    }

    // Resolve via the daemon, bounded by a timeout so a hung daemon can't pin
    // request tasks.
    let resolved = tokio::time::timeout(
        CONTAINER_RESOLVE_TIMEOUT,
        crate::infra::nginx::resolve_container_upstream(name, port),
    )
    .await;

    match resolved {
        Ok(Ok(hp)) => {
            let mut cache = container_cache().write().await;
            cache.insert(key, (hp.clone(), Instant::now()));
            prune_stale(&mut cache);
            Some(hp)
        }
        Ok(Err(e)) => {
            tracing::warn!(container = %name, port, error = %e, "edge proxy: container upstream unresolvable");
            container_cache().write().await.remove(&key);
            None
        }
        Err(_) => {
            tracing::warn!(container = %name, port, "edge proxy: container resolution timed out");
            container_cache().write().await.remove(&key);
            None
        }
    }
}

/// A still-fresh cached address for `key`, if any.
async fn fresh_cached(key: &str) -> Option<String> {
    let cache = container_cache().read().await;
    cache.get(key).and_then(|(addr, at)| {
        (at.elapsed() < CONTAINER_TTL).then(|| addr.clone())
    })
}

/// Drop long-abandoned cache entries (a container deleted long ago) so the map
/// can't grow without bound across a deployment's lifetime.
fn prune_stale(cache: &mut HashMap<String, (String, Instant)>) {
    const MAX_AGE: Duration = Duration::from_secs(300);
    cache.retain(|_, (_, at)| at.elapsed() < MAX_AGE);
}

/// The pooled, non-upgrade path: send through the shared client and stream the
/// upstream response body straight back. Hop-by-hop headers are stripped from
/// the response so we don't leak the upstream's transport framing to the client.
async fn proxy_plain(req: Request<Incoming>) -> Resp {
    // Apply the body-inactivity timeout only to requests that actually carry a
    // body (a declared Content-Length or chunked Transfer-Encoding) so a bodyless
    // GET — the common case — doesn't allocate a timer.
    let has_body = req.headers().contains_key(http::header::CONTENT_LENGTH)
        || req.headers().contains_key(http::header::TRANSFER_ENCODING);
    let req = req.map(|incoming| {
        super::timeout_body::prepare(incoming, BODY_INACTIVITY_TIMEOUT, has_body)
    });
    match client().request(req).await {
        Ok(upstream) => {
            let (mut parts, body) = upstream.into_parts();
            strip_hop_by_hop(&mut parts.headers, false);
            // Stream the body back without buffering; `boxed` adapts the legacy
            // client's body into the unified `ResBody`. `Parts` carries no body
            // type, so re-pairing it with our boxed body is a plain `from_parts`.
            http::Response::from_parts(parts, response::boxed(body))
        }
        Err(e) => {
            tracing::warn!(error = %e, "edge proxy: upstream request failed");
            response::status(StatusCode::BAD_GATEWAY)
        }
    }
}

/// The WebSocket / upgrade path. We can't use the pooled client because after a
/// `101` we need raw ownership of both byte streams. So: take the inbound
/// upgrade future *before* consuming the request, open a one-shot upstream
/// connection (plain TCP or rustls), forward the handshake, and on a `101` spawn
/// a task that copies bytes both ways once both upgrades complete.
async fn proxy_websocket(mut req: Request<Incoming>, target: &ProxyTarget, authority: &str) -> Resp {
    use tokio::net::TcpStream;

    // Grab the inbound upgrade future now — `hyper::upgrade::on` must be called
    // while we still hold the inbound request; the `101` we return later is what
    // actually drives the client side of this upgrade to completion.
    let inbound = hyper::upgrade::on(&mut req);

    // Dial the upstream over a dedicated connection.
    let tcp = match TcpStream::connect(authority).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, %authority, "edge proxy(ws): upstream connect failed");
            return response::status(StatusCode::BAD_GATEWAY);
        }
    };
    let _ = tcp.set_nodelay(true);
    // TCP keepalive so a half-open upstream (dead peer, dropped conntrack) is
    // detected by the OS and the tunnel tears down instead of leaking forever.
    super::listener::set_keepalive(&tcp);

    // Run the HTTP/1 handshake over either the raw TCP stream (http upstream) or
    // a rustls client stream (https upstream). Both branches yield a
    // `SendRequest<Incoming>` we forward the upgrade request over, plus a driver
    // future we must poll for the connection (`with_upgrades`) to make progress.
    if target.scheme == "https" {
        let tls = match connect_tls(tcp, authority).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, %authority, "edge proxy(ws): upstream TLS failed");
                return response::status(StatusCode::BAD_GATEWAY);
            }
        };
        ws_handshake(TokioIo::new(tls), req, inbound).await
    } else {
        ws_handshake(TokioIo::new(tcp), req, inbound).await
    }
}

/// Perform the upstream HTTP/1 handshake over an already-connected (optionally
/// TLS-wrapped) IO, forward the upgrade request, and wire up the bidirectional
/// copy on a `101`. Generic over the upstream IO so the http and https branches
/// share this code.
async fn ws_handshake<I>(
    io: I,
    req: Request<Incoming>,
    inbound: hyper::upgrade::OnUpgrade,
) -> Resp
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, "edge proxy(ws): upstream handshake failed");
            return response::status(StatusCode::BAD_GATEWAY);
        }
    };

    // Drive the upstream connection, allowing it to surface the upgraded IO.
    // `with_upgrades` is required for `hyper::upgrade::on(upstream_resp)` to
    // resolve; the connection future must be polled for the request to proceed.
    // Hold the handle: on the 101 path we abort it when the tunnel ends so a
    // stuck driver can't outlive the tunnel (on the non-101 path the handle is
    // dropped/detached so the driver keeps relaying the response body).
    let driver = tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "edge proxy(ws): upstream connection ended");
        }
    });

    let upstream_resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "edge proxy(ws): upstream request failed");
            return response::status(StatusCode::BAD_GATEWAY);
        }
    };

    // Not a switch: the upstream declined the upgrade. Relay its response as-is
    // (stripping hop-by-hop) so the client sees the real status (e.g. 4xx/5xx).
    if upstream_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (mut parts, body) = upstream_resp.into_parts();
        strip_hop_by_hop(&mut parts.headers, false);
        return http::Response::from_parts(parts, response::boxed(body));
    }

    // It's a 101. Snapshot the upstream's handshake response (status + headers,
    // e.g. `Sec-WebSocket-Accept`) BEFORE consuming it for the upgrade — the
    // client needs those verbatim to accept the handshake. Then take the upgrade
    // future. Returning a 101 from the service is what makes hyper complete the
    // *client* upgrade and resolve `inbound`.
    let mut resp_parts = upstream_resp.headers().clone();
    // Keep connection/upgrade (the handshake), drop other hop-by-hop framing.
    strip_hop_by_hop(&mut resp_parts, true);
    let upstream_upgrade = hyper::upgrade::on(upstream_resp);

    // Bridge the two streams once both upgrades resolve. Spawned detached so the
    // service can return the 101 immediately and let hyper finish the upgrade.
    tokio::spawn(async move {
        let (client_io, server_io) = match tokio::try_join!(inbound, upstream_upgrade) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!(error = %e, "edge proxy(ws): upgrade did not complete");
                driver.abort();
                return;
            }
        };
        let mut client_io = TokioIo::new(client_io);
        let mut server_io = TokioIo::new(server_io);
        // Pump bytes both ways until either side closes; this is the tunnel. A
        // half-open peer is torn down by TCP keepalive (set on both sockets), so
        // this returns instead of hanging forever.
        if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut server_io).await {
            tracing::debug!(error = %e, "edge proxy(ws): tunnel closed");
        }
        // Tunnel finished — ensure the upstream driver task can't outlive it.
        driver.abort();
    });

    // Build the 101 we return to the client: copy the upstream's handshake
    // headers (Upgrade, Connection, Sec-WebSocket-Accept, …) verbatim. We
    // deliberately keep connection/upgrade here — they ARE the handshake.
    let mut resp = http::Response::new(response::empty());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *resp.headers_mut() = resp_parts;
    resp
}

/// Open a rustls client TLS stream to `authority` over an established TCP
/// connection, using the webpki roots and the ring provider (pure-Rust, no C).
async fn connect_tls(
    tcp: tokio::net::TcpStream,
    authority: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use std::sync::Arc;

    // `ConfigBuilderExt` adds `.with_webpki_roots()` to rustls' builder, so we
    // get the pure-Rust webpki trust anchors via hyper-rustls (a direct dep)
    // without naming the `webpki-roots` crate ourselves.
    use hyper_rustls::ConfigBuilderExt;
    use tokio_rustls::TlsConnector;

    // Reuse one client config across calls: building the root store every time
    // is wasteful, and the config is immutable once built.
    static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = TLS_CONFIG.get_or_init(|| {
        // webpki roots → pure-Rust trust anchors; ring provider is the one the
        // musl-static build pins (never aws-lc-rs).
        let cfg = rustls::ClientConfig::builder()
            .with_webpki_roots()
            .with_no_client_auth();
        Arc::new(cfg)
    });

    // SNI = the upstream host (strip the port). An IP literal can't be an SNI
    // server name; rustls handles that distinction via `ServerName::try_from`.
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid upstream TLS server name: {host}"))?;

    let connector = TlsConnector::from(config.clone());
    let stream = connector.connect(server_name, tcp).await?;
    Ok(stream)
}

/// Whether the request is a WebSocket upgrade: `Connection` contains `upgrade`
/// (token, case-insensitive) and `Upgrade` is `websocket`.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    let upgrade_ws = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    connection_upgrade && upgrade_ws
}

/// Apply the forwarded-header rewrite (mirrors `confgen::proxy_location`):
///   * `Host` → the upstream authority (so the upstream sees its own vhost).
///   * `X-Real-IP` → the resolved client IP.
///   * `X-Forwarded-For` → existing value + `, ip`, else just `ip`.
///   * `X-Forwarded-Proto` → `https`/`http` from the inbound scheme.
///   * strip `Authorization` when `target.strip_auth`.
///   * drop hop-by-hop headers (except connection/upgrade on a WS handshake).
fn rewrite_request_headers(
    headers: &mut HeaderMap,
    authority: &str,
    ctx: &ConnCtx,
    client_ip: IpAddr,
    target: &ProxyTarget,
    is_ws: bool,
) {
    // Strip hop-by-hop first so a client-supplied `Connection: close` etc. can't
    // leak through; on a WS handshake we keep connection/upgrade intact.
    strip_hop_by_hop(headers, is_ws);

    // Host = upstream authority.
    if let Ok(v) = HeaderValue::from_str(authority) {
        headers.insert(http::header::HOST, v);
    }

    // X-Real-IP = client IP.
    if let Ok(v) = HeaderValue::from_str(&client_ip.to_string()) {
        headers.insert(HeaderName::from_static("x-real-ip"), v);
    }

    // X-Forwarded-For = existing chain + this client (the
    // `$proxy_add_x_forwarded_for` synthesis).
    let xff = HeaderName::from_static("x-forwarded-for");
    let appended = match headers.get(&xff).and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}, {client_ip}"),
        _ => client_ip.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&appended) {
        headers.insert(xff, v);
    }

    // X-Forwarded-Proto = inbound scheme.
    let proto = if ctx.tls { "https" } else { "http" };
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(proto),
    );

    // Optionally strip the client Authorization (access list, Pass-Auth off).
    if target.strip_auth {
        headers.remove(http::header::AUTHORIZATION);
    }
}

/// Remove hop-by-hop headers from a header map. When `keep_upgrade` is set (an
/// active WebSocket handshake), `connection` and `upgrade` are preserved because
/// they carry the handshake end to end; everything else is still dropped.
///
/// RFC 9110 §7.6.1: in addition to the fixed set, ANY header field NAMED in the
/// `Connection` header is connection-specific and must not be forwarded. We
/// collect those names first (e.g. a backend that sets `Connection: X-Internal`)
/// and drop them too, then drop the fixed set — closing a request-smuggling /
/// header-leak gap a fixed list alone misses.
fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    // Names listed in `Connection` are themselves hop-by-hop. Collect before we
    // remove `connection` itself. Skip `upgrade`/`connection` when keeping the WS
    // handshake.
    let named: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty() && t != "close" && t != "keep-alive")
        .filter(|t| !(keep_upgrade && (t == "upgrade" || t == "connection")))
        .collect();
    for name in named {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&hn);
        }
    }

    for name in HOP_BY_HOP {
        if keep_upgrade && (*name == "connection" || *name == "upgrade") {
            continue;
        }
        // Header names are ASCII case-insensitive; `remove` handles that.
        headers.remove(*name);
    }
}
