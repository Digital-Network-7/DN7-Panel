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
use http_body::Body as _;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::sync::{OwnedSemaphorePermit, RwLock};

use super::config::{ProxyTarget, Tuning, Upstream};
use super::conn_limit::ConnGuard;
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

/// Upstream response-header timeout (nginx `proxy_read_timeout` for the
/// time-to-first-byte): bound how long we wait for the upstream to return its
/// response *head*. An upstream that accepts the request but never answers (a
/// deadlocked worker whose TCP still ACKs, so connect/keepalive never fire) would
/// otherwise pin the request task — and the per-IP `ConnGuard` wrapped around the
/// response body — forever. On elapse we abandon the request and return 504.
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// Upstream response-body inactivity timeout (the streaming half of
/// `proxy_read_timeout`): once headers are in, bound the gap between response
/// body frames the same way [`BODY_INACTIVITY_TIMEOUT`] bounds the request side.
/// An upstream that sends headers and then stalls mid-body (again, TCP still
/// ACKs, so keepalive never fires) would otherwise hold the request task and its
/// `ConnGuard` open indefinitely; the timer resets on every frame, so a
/// slow-but-steady download is untouched. Aborting the body drops the guard,
/// releasing the per-IP slot instead of leaking it toward the global ceiling.
const RESPONSE_BODY_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

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
type HttpsConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

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
///
/// `conn_guard` is the per-IP concurrency slot the router acquired for this
/// request (`None` when the route is unlimited / loopback-exempt). It is returned
/// so the router can thread it into the response body — EXCEPT on a WebSocket
/// upgrade, where the tunnel outlives this response: there the guard is moved
/// INTO the detached tunnel task and this returns `None`, so the per-IP slot is
/// held for the tunnel's whole lifetime instead of dropping the instant the empty
/// `101` body drains (which would let one client open unbounded long-lived
/// tunnels for free).
pub(crate) async fn handle(
    mut req: Request<Incoming>,
    target: &ProxyTarget,
    ctx: &ConnCtx,
    client_ip: IpAddr,
    tuning: &Tuning,
    conn_guard: Option<ConnGuard>,
) -> (Resp, Option<ConnGuard>) {
    // Enforce `client_max_body_size` early via the declared Content-Length, so an
    // oversized upload is rejected with 413 before we dial the upstream. This is
    // the fast path only: a chunked / HTTP-2 body carries no length up front, so
    // it can't be caught here — that shape is bounded by the cumulative
    // `limit_body` wrapper applied to the forwarded request body below (which
    // fails the stream once it crosses the cap). The body is streamed, never
    // buffered, so this is parity with nginx's cap rather than a memory-safety
    // guard.
    if tuning.client_max_body_size > 0 {
        if let Some(len) = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if len > tuning.client_max_body_size {
                return (
                    response::text(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "413 Request Entity Too Large",
                    ),
                    conn_guard,
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
        None => {
            return (
                response::status(StatusCode::SERVICE_UNAVAILABLE),
                conn_guard,
            )
        }
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
        Err(_) => return (response::status(StatusCode::BAD_GATEWAY), conn_guard),
    };
    *req.uri_mut() = new_uri;

    // Rewrite the forwarded headers (Host/X-Real-IP/XFF/XFP/strip-auth). For a
    // WS upgrade we must NOT strip connection/upgrade — they carry the handshake.
    rewrite_request_headers(req.headers_mut(), &authority, ctx, client_ip, target, is_ws);

    // `leftover_guard` is the per-IP slot the router should thread into the
    // response body. On the WS path it is moved into the tunnel task (so it lives
    // for the tunnel, not just the empty 101) and `None` is left here.
    let (mut resp, leftover_guard) = if is_ws {
        (
            proxy_websocket(req, target, &authority, conn_guard, ctx.conn_permit.clone()).await,
            None,
        )
    } else {
        // The upstream (a managed site or the loopback console) speaks HTTP/1.
        // The inbound request may be HTTP/2 — the edge's TLS listener negotiates
        // h2 via ALPN — and forwarding it as-is makes the h1 upstream client
        // reject it ("Connection is HTTP/1, but request requires HTTP/2" ->
        // 502). Terminate the client's protocol here and speak h1 to the backend.
        *req.version_mut() = http::Version::HTTP_11;
        (
            proxy_plain(req, tuning.client_max_body_size).await,
            conn_guard,
        )
    };
    // Only cache a SUCCESSFUL asset response — never a transient upstream error
    // (502/503/504) or a 404, which would otherwise be pinned for a week.
    if add_asset_cache && resp.status().is_success() {
        // Don't clobber an upstream that already set its own caching policy.
        if !resp.headers().contains_key(http::header::CACHE_CONTROL) {
            resp.headers_mut().insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=604800"),
            );
        }
    }
    (resp, leftover_guard)
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
        let mut map = container_inflight()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
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
        crate::resolve_container_upstream(name, port),
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
    cache
        .get(key)
        .and_then(|(addr, at)| (at.elapsed() < CONTAINER_TTL).then(|| addr.clone()))
}

/// Drop long-abandoned cache entries (a container deleted long ago) so the map
/// can't grow without bound across a deployment's lifetime.
fn prune_stale(cache: &mut HashMap<String, (String, Instant)>) {
    const MAX_AGE: Duration = Duration::from_secs(300);
    cache.retain(|_, (_, at)| at.elapsed() < MAX_AGE);
}

/// Whether a forwarded request body needs the inactivity-timeout wrapper, given
/// the body's `size_hint().exact()`. A genuinely bodyless request is the only
/// one hyper reports as `Some(0)` (END_STREAM on the headers, or an explicit
/// `Content-Length: 0`); a streaming body with no declared length — including
/// the HTTP/2-with-no-Content-Length shape — reports `None`, so it is treated as
/// body-bearing and gets the timeout. A header-only check would misclassify that
/// shape and skip the timeout, which was the H2 slowloris hole.
pub(crate) fn body_needs_timeout(exact: Option<u64>) -> bool {
    exact != Some(0)
}

/// The pooled, non-upgrade path: send through the shared client and stream the
/// upstream response body straight back. Hop-by-hop headers are stripped from
/// the response so we don't leak the upstream's transport framing to the client.
///
/// `max_body` is the route's `client_max_body_size` (0 = unlimited): the
/// forwarded request body is wrapped so a chunked / HTTP-2 upload that carries
/// no `Content-Length` (and so slips the early cap in `handle`) still fails once
/// its cumulative size crosses the limit, aborting the upstream request instead
/// of streaming an unbounded payload through.
async fn proxy_plain(req: Request<Incoming>, max_body: u64) -> Resp {
    // Decide whether the request carries a body from the body's own size hint,
    // NOT from Content-Length / Transfer-Encoding headers: an HTTP/2 upload
    // streams DATA frames with no Transfer-Encoding (H2 forbids it) and often no
    // Content-Length, so a header check would miss it and let the body skip both
    // the cap and the inactivity timeout.
    let carries_body = body_needs_timeout(req.body().size_hint().exact());
    let req = req.map(|incoming| {
        // Inactivity timeout: armed only for a body-bearing request so a bodyless
        // GET — the common case — doesn't allocate a timer.
        let body = super::timeout_body::prepare(incoming, BODY_INACTIVITY_TIMEOUT, carries_body);
        // Cumulative size cap: always applied. `limit` self-noops when
        // `max_body == 0` (unlimited), so this is free for uncapped routes and,
        // unlike the old header-gated path, still catches an H2 body that carries
        // no Content-Length.
        super::limit_body::limit(body, max_body)
    });
    // Bound the wait for the upstream response *head* (time-to-first-byte). The
    // pooled client only carries a connect timeout + TCP keepalive; an upstream
    // that accepts the request and then deadlocks (still ACKing, so keepalive
    // never fires) would otherwise pin this task — and the per-IP `ConnGuard`
    // threaded into the response body downstream — forever. On elapse we abandon
    // the request future (dropping it cancels the in-flight upstream request) and
    // return 504.
    //
    // The bound is applied ONLY to a bodyless request (the GET/HEAD common case).
    // A body-bearing request folds the *upload* time into `client().request()` —
    // a legitimate large upload (up to `client_max_body_size`, default 1 GiB) over
    // a slow link can steadily take far longer than this timeout, and killing it
    // mid-upload would be a regression. Its send phase is already bounded by the
    // request-body *inactivity* timeout above (a stalled upload aborts), and its
    // response read is bounded by the response-body inactivity timeout below, so
    // the absolute header cap is unnecessary — and unsafe — for that shape.
    let request = client().request(req);
    let sent = if carries_body {
        request.await
    } else {
        match tokio::time::timeout(RESPONSE_HEADER_TIMEOUT, request).await {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!("edge proxy: upstream response-header timeout");
                return response::status(StatusCode::GATEWAY_TIMEOUT);
            }
        }
    };
    match sent {
        Ok(upstream) => {
            let (mut parts, body) = upstream.into_parts();
            strip_hop_by_hop(&mut parts.headers, false);
            // Stream the body back without buffering; `boxed` adapts the legacy
            // client's body into the unified `ResBody`. `Parts` carries no body
            // type, so re-pairing it with our boxed body is a plain `from_parts`.
            // The body is then wrapped in a response-side inactivity timeout so a
            // mid-stream stall aborts the body (and drops the downstream
            // `ConnGuard`) instead of hanging forever.
            let body = resp_timeout::wrap(response::boxed(body), RESPONSE_BODY_INACTIVITY_TIMEOUT);
            http::Response::from_parts(parts, body)
        }
        Err(e) => {
            tracing::warn!(error = %e, "edge proxy: upstream request failed");
            response::status(StatusCode::BAD_GATEWAY)
        }
    }
}

/// A response-side inactivity-timeout body wrapper — the streaming half of nginx's
/// `proxy_read_timeout`. It mirrors [`super::timeout_body::TimeoutBody`] (the
/// request-side guard) but over the response body type ([`ResBody`], whose error
/// is `std::io::Error`): if the upstream makes no progress (data/trailers/EOF)
/// within the window, the body errors out, tearing down a stalled response and,
/// crucially, dropping any per-IP `ConnGuard` wrapped further out so its slot is
/// released rather than leaked. A body that keeps making progress is never
/// interrupted (the timer resets on every frame).
mod resp_timeout {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use http_body::{Body, Frame, SizeHint};
    use http_body_util::BodyExt;

    use super::response::ResBody;

    struct RespTimeoutBody {
        inner: ResBody,
        timeout: Duration,
        sleep: Pin<Box<tokio::time::Sleep>>,
    }

    impl Body for RespTimeoutBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            // `RespTimeoutBody` is `Unpin` (UnsyncBoxBody + Pin<Box<Sleep>> +
            // Duration), so we can take a plain `&mut`.
            let this = self.get_mut();
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(v) => {
                    // Progress made — reset the inactivity deadline.
                    let next = tokio::time::Instant::now() + this.timeout;
                    this.sleep.as_mut().reset(next);
                    Poll::Ready(v)
                }
                Poll::Pending => match this.sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upstream response inactivity timeout",
                    )))),
                    Poll::Pending => Poll::Pending,
                },
            }
        }

        fn is_end_stream(&self) -> bool {
            self.inner.is_end_stream()
        }

        fn size_hint(&self) -> SizeHint {
            self.inner.size_hint()
        }
    }

    /// Wrap a response body with an inactivity deadline (resets on every frame).
    /// Boxed via `boxed_unsync` (not `response::boxed`) because `RespTimeoutBody`'s
    /// error is already `std::io::Error` — re-wrapping through `boxed`'s `map_err`
    /// would flatten the timeout's `ErrorKind::TimedOut` into `Other` and add a
    /// redundant box layer.
    pub(super) fn wrap(inner: ResBody, timeout: Duration) -> ResBody {
        RespTimeoutBody {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
        .boxed_unsync()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::response::boxed;
        use http_body_util::{BodyExt, Full};

        /// A body that yields `first` (if any) once and then stalls forever
        /// (`Pending`, never `Ready`) — models an upstream that sends some bytes
        /// and then deadlocks mid-stream while its TCP still ACKs.
        struct StallBody {
            first: Option<Bytes>,
        }

        impl Body for StallBody {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
                match self.first.take() {
                    Some(b) => Poll::Ready(Some(Ok(Frame::data(b)))),
                    // No waker registered: the body never makes progress again.
                    None => Poll::Pending,
                }
            }
        }

        #[tokio::test(start_paused = true)]
        async fn errors_when_upstream_body_stalls() {
            // Headers already arrived; the body yields one chunk then hangs. With a
            // short inactivity window the wrapper must surface an error (which, in
            // the router, drops the ConnGuard) rather than block forever. Paused
            // time auto-advances once the task can make no other progress, firing
            // the inactivity sleep deterministically.
            let inner = boxed(StallBody {
                first: Some(Bytes::from_static(b"partial")),
            });
            let err = wrap(inner, Duration::from_millis(50))
                .collect()
                .await
                .expect_err("a stalled response body must error out, not hang");
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        }

        #[tokio::test(start_paused = true)]
        async fn passes_a_complete_body_through_untouched() {
            // A body that completes promptly is delivered verbatim — the timeout
            // is armed but never fires because EOF arrives first.
            let data = b"the whole response body";
            let inner = boxed(Full::new(Bytes::from_static(data)));
            let got = wrap(inner, Duration::from_secs(60))
                .collect()
                .await
                .expect("a complete body must not error")
                .to_bytes();
            assert_eq!(got.as_ref(), data);
        }
    }
}

/// The WebSocket / upgrade path. We can't use the pooled client because after a
/// `101` we need raw ownership of both byte streams. So: take the inbound
/// upgrade future *before* consuming the request, open a one-shot upstream
/// connection (plain TCP or rustls), forward the handshake, and on a `101` spawn
/// a task that copies bytes both ways once both upgrades complete.
/// `conn_guard` is the per-IP concurrency slot for this request; on a successful
/// `101` it is moved into the tunnel copy task so the slot is held for the whole
/// tunnel lifetime. On any pre-101 failure it simply drops here (the request is
/// over, so there is nothing to keep the slot alive for).
async fn proxy_websocket(
    mut req: Request<Incoming>,
    target: &ProxyTarget,
    authority: &str,
    conn_guard: Option<ConnGuard>,
    conn_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Resp {
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
        ws_handshake(TokioIo::new(tls), req, inbound, conn_guard, conn_permit).await
    } else {
        ws_handshake(TokioIo::new(tcp), req, inbound, conn_guard, conn_permit).await
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
    conn_guard: Option<ConnGuard>,
    conn_permit: Option<Arc<OwnedSemaphorePermit>>,
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
    //
    // Both the per-IP `ConnGuard` AND the global connection permit are MOVED into
    // this task and only dropped when it returns (i.e. when `copy_bidirectional`
    // finishes). Because the connection's service returns the empty 101
    // immediately — which drops the router-side response body and lets
    // serve_conn's connection future complete — the tunnel would otherwise be
    // counted by NO limiter: one client could open unbounded long-lived tunnels.
    // Holding the per-IP guard makes `conn_per_ip` count active tunnels, and
    // holding the refcounted global permit keeps the tunnel counted against
    // `MAX_CONNECTIONS`, closing both halves of that hole.
    tokio::spawn(async move {
        // Both held for the tunnel lifetime; released (slots freed) on task return.
        let _conn_guard = conn_guard;
        let _conn_permit = conn_permit;
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
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
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
///   * `X-Forwarded-Host` → the original client Host (before the rewrite below).
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

    // X-Forwarded-Host = the ORIGINAL Host the client used, captured before we
    // overwrite Host with the upstream authority below. A proxied app (e.g. the
    // console's WebSocket same-origin check) needs the real external host, not
    // the loopback upstream it's now being sent to.
    if let Some(orig_host) = headers.get(http::header::HOST).cloned() {
        headers.insert(HeaderName::from_static("x-forwarded-host"), orig_host);
    }

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

    // X-DN7-Forwarded = positive proof this request was proxied by the edge.
    // The loopback console keys its root-only CLI-control-token gate off the
    // ABSENCE of this marker (a direct `dn7` hit has none); `insert()` overwrites
    // any client-supplied copy, so an external client can't forge a "direct" hit.
    headers.insert(
        HeaderName::from_static("x-dn7-forwarded"),
        HeaderValue::from_static("1"),
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
