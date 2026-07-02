//! [M5] Listener lifecycle, port binding, coexistence + migration.
//!
//! This module owns the *one* place where the edge server opens a listening
//! socket. Centralising it keeps the bind strategy (socket options, reuse
//! semantics, coexistence checks) consistent between :80 and :443 and between
//! the running binary and a self-updated successor.
//!
//! ## Why `SO_REUSEADDR` + `SO_REUSEPORT`
//!
//! The panel performs in-place self-updates: it execs a freshly downloaded
//! binary which must bring up its own :80/:443 listeners *before* the old
//! process drops its sockets, so that no inbound connection is refused during
//! the handoff. With only `SO_REUSEADDR` the new process would still race the
//! old one for the listen socket and could hit `EADDRINUSE`. `SO_REUSEPORT`
//! (Linux/musl, and the BSD/macOS variant) lets two processes hold the same
//! `addr:port` simultaneously, with the kernel load-balancing accepts between
//! them — the old process can then finish draining and exit while the new one
//! already serves. `SO_REUSEADDR` additionally lets us re-bind immediately
//! after a crash without waiting out `TIME_WAIT`.
//!
//! ## Coexistence & migration decision (MVP)
//!
//! On an existing-host install a host nginx/Apache may already be listening on
//! :80/:443. For the MVP we *coexist* rather than forcibly take over:
//!
//!   - Because we bind with `SO_REUSEPORT`, the edge can co-bind the same ports
//!     the host nginx holds. Both processes receive a share of new connections.
//!     That is acceptable for staged rollout / smoke-testing the edge in place,
//!     and it is the only option that never drops the operator's existing
//!     traffic at flip time.
//!   - `SO_REUSEPORT` only shares a port between sockets that *all* set the
//!     option. A legacy host nginx that bound *without* `SO_REUSEPORT` will not
//!     share, so a plain co-bind can still fail with `EADDRINUSE`; that is why
//!     [`bind`] surfaces a clear, actionable error and [`port_in_use`] lets the
//!     caller probe ahead of time and decide.
//!   - True *takeover* — stopping/disabling the previously managed host nginx so
//!     the edge becomes the sole owner of :80/:443 — is intentionally deferred
//!     to a later milestone. It is a destructive, operator-visible action
//!     (it can drop the host's in-flight connections and must be reversible on
//!     rollback), so it needs an explicit operator choice and its own migration
//!     path rather than happening implicitly the first time the edge binds.

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// Bind a TCP listener for the edge server with the reuse semantics required
/// for a graceful, zero-drop binary handoff (see the module docs).
///
/// We build the socket by hand via `socket2` so we can set `SO_REUSEADDR` and
/// `SO_REUSEPORT` *before* `bind(2)` — these options are only honoured if set
/// on the unbound socket, which `tokio::net::TcpListener::bind` does not do for
/// us. The resulting `std::net::TcpListener` is then adopted by tokio.
///
/// Returns the raw [`std::io::Result`] so the caller can distinguish
/// `AddrInUse` (a foreign process holds the port → offer force-start) from other
/// failures. The common cause of `AddrInUse` here is a host nginx/Apache that
/// bound *without* `SO_REUSEPORT`, so our co-bind is refused.
pub(crate) async fn bind(addr: std::net::SocketAddr) -> std::io::Result<TcpListener> {
    // Match the socket domain to the address family so an IPv6 bind works and an
    // IPv4 bind does not accidentally request a dual-stack socket.
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;

    // Allow immediate re-bind after a crash (skip TIME_WAIT) and, on a successor
    // binary, co-bind while the previous process still holds the port.
    socket.set_reuse_address(true)?;

    // SO_REUSEPORT is the load-balancing co-bind that powers the graceful
    // handoff. It is a Unix-only option; skip it on platforms that lack it so
    // the code still builds (production targets are musl Linux).
    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    // tokio requires a non-blocking listener; set it before handing the fd over.
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;

    // Reasonable accept backlog; the edge fans connections out to the hyper
    // auto-server, so a deep-ish queue smooths bursts during reloads.
    socket.listen(1024)?;

    // Adopt the prepared std socket into tokio's reactor.
    TcpListener::from_std(socket.into())
}

/// Best-effort probe for whether `port` is already held on all interfaces.
///
/// Used by the coexistence/migration logic (not yet wired in) to decide ahead
/// of [`bind`] whether a host web server is occupying :80/:443. We attempt a
/// *plain* `TcpListener::bind` on `0.0.0.0:port` — deliberately without the
/// reuse options — so that a successful bind means the port is genuinely free,
/// and an error means something already owns it. The probe socket is dropped
/// immediately, releasing the port before the real [`bind`] runs.
///
/// This is advisory only: it races other binders and cannot see a holder that
/// itself used `SO_REUSEPORT`, so callers must still handle a `bind` failure.
#[allow(dead_code)] // reserved for the deferred host-nginx takeover/coexistence migration
pub(crate) async fn port_in_use(port: u16) -> bool {
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));
    // A successful plain bind proves the port is free; any error (typically
    // AddrInUse) means it is occupied. The listener is dropped at end of scope.
    TcpListener::bind(addr).await.is_err()
}
