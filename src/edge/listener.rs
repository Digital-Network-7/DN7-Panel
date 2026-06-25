//! [M1] The TCP listeners + per-connection HTTP serving.
//!
//! Binds the edge's two well-known ports and serves every accepted connection
//! with the hyper-util "auto" server (HTTP/1.1 + HTTP/2 negotiated per ALPN for
//! TLS, per HTTP/2 prior-knowledge for plain). Each connection runs in its own
//! task and loads the *current* published config snapshot per request, so a
//! reload swaps the route table under live traffic without dropping a socket.
//!
//!   - :80 (plain)  → `ConnCtx{ tls:false, sni:None, peer }`.
//!   - :443 (TLS)   → terminate with `tokio_rustls::TlsAcceptor` built from
//!     `tls::server_config`, record the negotiated SNI, then serve over the
//!     `TlsStream`: `ConnCtx{ tls:true, sni, peer }`.
//!
//! `serve_connection_with_upgrades` is used (not the plain variant) so a
//! WebSocket `Upgrade` the proxy relays can complete — hyper hands the upgraded
//! IO back through the connection future, which the upgrade-aware serve drives.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::{router, store, tls};

/// Slowloris guard: a client must send the complete request head within this
/// window or the connection is dropped. Without it a trickle of header bytes can
/// pin a connection (and its task) indefinitely — a cheap DoS nginx defends
/// against by default (`client_header_timeout`). hyper arms this deadline on
/// entry to reading each request head — including the wait for the *next*
/// request on a kept-alive connection — so it doubles as the idle-keepalive reap
/// (tighter than nginx's default `keepalive_timeout`).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Cap concurrent HTTP/2 streams per connection. Bounds the work a single
/// connection can fan out (and blunts stream-reset–flood / "Rapid Reset" class
/// abuse, on top of the h2 crate's own mitigations).
const H2_MAX_CONCURRENT_STREAMS: u32 = 256;

/// Global ceiling on concurrent accepted connections across BOTH listeners —
/// the in-process equivalent of nginx's `worker_connections`. Without it a
/// connection flood (even idle or mid-handshake sockets) spawns unbounded tasks
/// and consumes unbounded fds/memory until the process hits the OS limit. When
/// the ceiling is reached the accept loops stop accepting (new sockets queue in
/// the listen backlog, then are refused) — bounded, predictable resource use.
const MAX_CONNECTIONS: usize = 16_384;

/// A slow or never-completing TLS handshake must not pin a task/fd forever
/// (slowloris on :443). Drop the connection if the handshake doesn't finish in
/// this window.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// TCP keepalive applied to every accepted data socket (and the proxy's upstream
/// sockets). On a half-open connection — peer host crash, NAT/conntrack drop,
/// cable pull, no FIN/RST — keepalive probes let the OS detect the dead peer and
/// tear the socket down, so a relayed (e.g. WebSocket) tunnel can't leak its
/// tasks/fds forever. Mirrors the protection nginx gets from `proxy_read_timeout`.
pub(crate) fn keepalive() -> socket2::TcpKeepalive {
    socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
}

/// Apply [`keepalive`] to a tokio TCP stream (best-effort).
pub(crate) fn set_keepalive(stream: &tokio::net::TcpStream) {
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive());
}

/// The process-wide connection limiter (lazily sized to [`MAX_CONNECTIONS`]).
fn conn_limiter() -> Arc<Semaphore> {
    static L: OnceLock<Arc<Semaphore>> = OnceLock::new();
    L.get_or_init(|| Arc::new(Semaphore::new(MAX_CONNECTIONS))).clone()
}

/// Bind the edge listeners and serve forever. Spawned from `edge::spawn` when
/// the edge is enabled. Returns `Err` only when a *bind* fails (a hard,
/// startup-fatal condition); per-connection errors are logged and swallowed so
/// one misbehaving client can never take the accept loop down.
pub(crate) async fn run() -> anyhow::Result<()> {
    // Build the TLS server config once; the SNI resolver inside reads the live
    // published cert store on every handshake, so renewed certs are presented
    // without re-binding. A bad config here is startup-fatal (propagated).
    let tls_config = tls::server_config()?;
    let acceptor = TlsAcceptor::from(tls_config);

    // Try to bind both ports. A port held by a foreign process (a host
    // nginx/Apache bound without SO_REUSEPORT) yields `AddrInUse`; we record the
    // conflict and return WITHOUT serving, so the UI can offer to force-start
    // (kill the occupant). Any listener that did bind is dropped here so we never
    // half-serve — force-start rebinds both cleanly.
    let http = super::lifecycle::bind(([0, 0, 0, 0], 80).into()).await;
    let https = super::lifecycle::bind(([0, 0, 0, 0], 443).into()).await;

    let mut conflicts = Vec::new();
    let http = classify_bind(http, 80, &mut conflicts);
    let https = classify_bind(https, 443, &mut conflicts);

    if !conflicts.is_empty() {
        tracing::warn!(
            ?conflicts,
            "edge: port(s) occupied by a foreign process; not started (force-start available)"
        );
        super::status::set(super::status::RunState::PortConflict(conflicts));
        return Ok(()); // not fatal: the operator resolves it via force-start
    }

    let http = http.expect("no conflict ⇒ :80 bound");
    let https = https.expect("no conflict ⇒ :443 bound");
    super::status::set(super::status::RunState::Running);
    tracing::info!("edge: listening on :80 and :443");

    // Drive both accept loops concurrently on this task; neither returns under
    // normal operation, so `run` parks here for the process lifetime.
    tokio::select! {
        r = serve_plain(http) => r,
        r = serve_tls(https, acceptor) => r,
    }
}

/// Classify a bind result: a bound listener, or a recorded conflict (the port
/// is in use, or any other bind error — both mean we can't serve it and the
/// operator should resolve the occupant).
fn classify_bind(
    res: std::io::Result<tokio::net::TcpListener>,
    port: u16,
    conflicts: &mut Vec<u16>,
) -> Option<tokio::net::TcpListener> {
    match res {
        Ok(l) => Some(l),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::AddrInUse {
                tracing::error!("edge: bind :{port} failed: {e}");
            }
            conflicts.push(port);
            None
        }
    }
}

/// Accept loop for the plain-HTTP :80 listener. `pub(crate)` so the integration
/// tests can drive it on an ephemeral loopback port.
pub(crate) async fn serve_plain(listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    let limiter = conn_limiter();
    loop {
        // Acquire a connection slot BEFORE accepting: at the ceiling the loop
        // parks here, leaving new sockets in the listen backlog (then refused) —
        // the worker_connections backpressure. The permit is moved into the
        // connection task and released when it finishes.
        let permit = limiter
            .clone()
            .acquire_owned()
            .await
            .expect("connection semaphore is never closed");

        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            // A transient accept error (e.g. fd exhaustion) must not kill the
            // loop; log and keep accepting (the permit drops here, freeing the slot).
            Err(e) => {
                tracing::warn!("edge :80 accept error: {e}");
                continue;
            }
        };

        // Proxies are latency-sensitive; disable Nagle so small responses aren't
        // delayed waiting to coalesce. Keepalive detects dead peers (leak guard).
        let _ = stream.set_nodelay(true);
        set_keepalive(&stream);

        tokio::spawn(async move {
            let _permit = permit; // released when this connection finishes
            let ctx = ConnCtx {
                tls: false,
                sni: None,
                peer,
            };
            serve_conn(TokioIo::new(stream), ctx).await;
        });
    }
}

/// Accept loop for the TLS :443 listener. Each connection completes its own
/// handshake inside its task so a slow/incomplete TLS client can't stall the
/// accept loop for everyone else.
pub(crate) async fn serve_tls(
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
) -> anyhow::Result<()> {
    let limiter = conn_limiter();
    loop {
        let permit = limiter
            .clone()
            .acquire_owned()
            .await
            .expect("connection semaphore is never closed");

        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("edge :443 accept error: {e}");
                continue;
            }
        };

        let _ = stream.set_nodelay(true);
        set_keepalive(&stream);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when this connection finishes
                                  // Terminate TLS under a deadline so a slow/incomplete handshake
                                  // (slowloris on :443) can't pin the task/fd. A failed or timed-out
                                  // handshake is per-connection: log and drop.
            let tls_stream = match tokio::time::timeout(
                TLS_HANDSHAKE_TIMEOUT,
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!("edge :443 TLS handshake from {peer} failed: {e}");
                    return;
                }
                Err(_) => {
                    tracing::debug!("edge :443 TLS handshake from {peer} timed out");
                    return;
                }
            };

            // Recover the SNI hostname the client offered from the completed
            // rustls server connection (the `.1` of the inner `(IO, ServerConn)`
            // pair). The router uses it only as a fallback host hint.
            let sni = tls_stream
                .get_ref()
                .1
                .server_name()
                .map(|s| s.to_string());

            let ctx = ConnCtx {
                tls: true,
                sni,
                peer,
            };
            serve_conn(TokioIo::new(tls_stream), ctx).await;
        });
    }
}

/// Serve a single accepted connection with the auto (h1/h2) server, dispatching
/// every request through `router::handle` against the live config snapshot.
/// Upgrade-aware so relayed WebSocket connections can complete.
async fn serve_conn<I>(io: TokioIo<I>, ctx: ConnCtx)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // The context is shared by every request multiplexed on this connection
    // (HTTP/2 fans many requests over one socket), so it lives behind an `Arc`.
    let ctx = Arc::new(ctx);

    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move {
            // Load the current config per request: an in-flight reload published
            // since the connection opened is picked up by the next request here.
            let resp = router::handle(req, &ctx, store::current()).await;
            Ok::<_, std::convert::Infallible>(resp)
        }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    // HTTP/1: a timer + header-read timeout (slowloris guard).
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    // HTTP/2: bound per-connection stream concurrency + keepalive PINGs to reap
    // dead peers.
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .keep_alive_interval(Duration::from_secs(20))
        .keep_alive_timeout(Duration::from_secs(20));

    if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
        // Client disconnects mid-response are routine; keep them at debug.
        tracing::debug!("edge: connection error: {e}");
    }
}

/// Per-connection context handed to the router: how the request arrived.
pub(crate) struct ConnCtx {
    /// Arrived over TLS (`https`).
    pub(crate) tls: bool,
    /// The SNI hostname the client offered (TLS only).
    pub(crate) sni: Option<String>,
    /// The peer socket address (the immediate TCP client).
    pub(crate) peer: std::net::SocketAddr,
}

/// Type alias kept so other modules can name the shared config handle.
pub(crate) type SharedConfig = Arc<super::config::RuntimeConfig>;
