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
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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
    L.get_or_init(|| Arc::new(Semaphore::new(MAX_CONNECTIONS)))
        .clone()
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

    // Assemble the ports to bind, de-duplicated (a BTreeMap keyed by port, so an
    // accidental overlap collapses to one listener). Port 80 is ALWAYS bound: it
    // is the website HTTP listener when that port is 80, else an ACME-only
    // issuance listener. The website HTTPS port terminates TLS. A dedicated
    // console port (≠ the website ports) gets its own Console listener; a `0` /
    // merged console rides the website ports by Host (today's behaviour).
    let ports = super::ports::listen_ports();
    let mut plan: std::collections::BTreeMap<u16, (ListenerRole, bool)> =
        std::collections::BTreeMap::new(); // port → (role, terminates-TLS)
    plan.insert(ports.website_https, (ListenerRole::Website, true));
    plan.entry(ports.website_http)
        .or_insert((ListenerRole::Website, false));
    plan.entry(80).or_insert_with(|| {
        if ports.website_http == 80 {
            (ListenerRole::Website, false)
        } else {
            (ListenerRole::AcmeOnly, false)
        }
    });
    if ports.console != 0 {
        plan.insert(ports.console, (ListenerRole::Console, ports.console_tls));
    }

    // Bind every planned port. A port held by a foreign process yields AddrInUse;
    // record the conflict. ANY conflict → return WITHOUT serving (dropping the
    // listeners that did bind, so we never half-serve); the operator resolves it
    // via force-start, which re-attempts every bind cleanly.
    let mut conflicts = Vec::new();
    let mut bound: Vec<(tokio::net::TcpListener, ListenerRole, bool)> = Vec::new();
    for (&port, &(role, tls)) in &plan {
        let res = super::lifecycle::bind(([0, 0, 0, 0], port).into()).await;
        if let Some(l) = classify_bind(res, port, &mut conflicts) {
            bound.push((l, role, tls));
        }
    }

    if !conflicts.is_empty() {
        tracing::warn!(
            ?conflicts,
            "edge: port(s) occupied by a foreign process; not started (force-start available)"
        );
        super::status::set(super::status::RunState::PortConflict(conflicts));
        return Ok(()); // not fatal: the operator resolves it via force-start
    }

    super::status::set(super::status::RunState::Running);
    let listening: Vec<u16> = plan.keys().copied().collect();
    tracing::info!(ports = ?listening, "edge: listening");

    // Drive every accept loop; none returns under normal operation, so `run`
    // parks here for the process lifetime. The first loop to exit (an error) ends
    // `run` and the JoinSet drop aborts the rest — the same all-or-nothing
    // semantics the two-listener `select!` had, so force-start rebinds them all.
    let mut set = tokio::task::JoinSet::new();
    for (listener, role, tls) in bound {
        if tls {
            let acc = acceptor.clone();
            set.spawn(async move { serve_tls(listener, acc, role).await });
        } else {
            set.spawn(async move { serve_plain(listener, role).await });
        }
    }
    match set.join_next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => Err(anyhow::anyhow!("edge serve task failed: {e}")),
        None => Ok(()),
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

/// Accept loop for a plain-HTTP listener with the given `role`. `pub(crate)` so
/// the integration tests can drive it on an ephemeral loopback port.
pub(crate) async fn serve_plain(
    listener: tokio::net::TcpListener,
    role: ListenerRole,
) -> anyhow::Result<()> {
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
                tracing::warn!("edge plain accept error: {e}");
                continue;
            }
        };

        // Proxies are latency-sensitive; disable Nagle so small responses aren't
        // delayed waiting to coalesce. Keepalive detects dead peers (leak guard).
        let _ = stream.set_nodelay(true);
        set_keepalive(&stream);

        tokio::spawn(async move {
            // The connection slot rides inside ConnCtx as a refcounted permit so
            // that on a WebSocket upgrade the detached tunnel task can keep a
            // clone alive past serve_conn's return — live tunnels then count
            // against MAX_CONNECTIONS instead of freeing the slot the instant the
            // empty 101 drains (which let one client open unbounded tunnels for
            // free). For a plain request it drops exactly when serve_conn ends.
            let ctx = ConnCtx {
                tls: false,
                role,
                sni: None,
                peer,
                conn_permit: Some(Arc::new(permit)),
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
    role: ListenerRole,
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
                tracing::warn!("edge TLS accept error: {e}");
                continue;
            }
        };

        let _ = stream.set_nodelay(true);
        set_keepalive(&stream);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            // Terminate TLS under a deadline so a slow/incomplete handshake
            // (slowloris on :443) can't pin the task/fd. A failed or timed-out
            // handshake is per-connection: log and drop — `permit` is still owned
            // by this task, so it releases the slot on those early returns; on
            // success it moves into ConnCtx below (see serve_plain for why).
            let tls_stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
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
            let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());

            let ctx = ConnCtx {
                tls: true,
                role,
                sni,
                peer,
                conn_permit: Some(Arc::new(permit)),
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

/// What a listener's port is for — drives per-connection routing in the router.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ListenerRole {
    /// Normal Host-routed hosted websites + ACME HTTP-01 + force-SSL redirect —
    /// the role of the website HTTP/HTTPS ports (the classic :80/:443).
    Website,
    /// ACME HTTP-01 challenges ONLY; every other request 404s. Port 80 stays bound
    /// in this role purely for Let's Encrypt issuance when the website HTTP port
    /// was moved off 80.
    AcmeOnly,
    /// Always the console, Host ignored — a dedicated console listener.
    Console,
}

/// Per-connection context handed to the router: how the request arrived.
pub(crate) struct ConnCtx {
    /// Arrived over TLS (`https`).
    pub(crate) tls: bool,
    /// Which listener (and therefore role) accepted this connection.
    pub(crate) role: ListenerRole,
    /// The SNI hostname the client offered (TLS only).
    pub(crate) sni: Option<String>,
    /// The peer socket address (the immediate TCP client).
    pub(crate) peer: std::net::SocketAddr,
    /// The global connection-slot permit for this connection, refcounted so a
    /// WebSocket tunnel can keep it alive for the tunnel's lifetime (moved into
    /// the detached copy task). `None` only on synthetic contexts (tests) that
    /// never went through the accept-loop limiter.
    pub(crate) conn_permit: Option<Arc<OwnedSemaphorePermit>>,
}

/// Type alias kept so other modules can name the shared config handle.
pub(crate) type SharedConfig = Arc<super::config::RuntimeConfig>;
