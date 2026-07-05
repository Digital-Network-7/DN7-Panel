//! The edge's client-facing listen ports — set by the panel from `WebSettings`
//! before [`super::spawn`] and read once by the listener at bind time.

/// The edge's client-facing listen ports. Bound ONCE at listener startup
/// (changing them needs a panel restart). The defaults are the well-known web
/// ports with the console merged onto them (today's behaviour), so a standalone
/// edge / the tests work unconfigured.
#[derive(Clone, Copy, Debug)]
pub struct ListenPorts {
    /// Public plain-HTTP port for hosted websites (default 80).
    pub website_http: u16,
    /// Public TLS port for hosted websites (default 443).
    pub website_https: u16,
    /// Dedicated console listen port. `0` = merged (the console is served on the
    /// website ports by Host — today's behaviour); a non-zero value that differs
    /// from both website ports opens a dedicated console listener.
    pub console: u16,
    /// The dedicated console listener terminates TLS (console SSL is on).
    pub console_tls: bool,
}

impl Default for ListenPorts {
    fn default() -> Self {
        Self {
            website_http: 80,
            website_https: 443,
            console: 0,
            console_tls: false,
        }
    }
}

static LISTEN_PORTS: std::sync::OnceLock<ListenPorts> = std::sync::OnceLock::new();

/// Set the edge's listen ports once, before `spawn()`. A later call is ignored —
/// ports bind once, so changing them requires a panel restart.
pub fn set_listen_ports(p: ListenPorts) {
    let _ = LISTEN_PORTS.set(p);
}

/// The configured listen ports (defaults until [`set_listen_ports`] is called).
pub(crate) fn listen_ports() -> ListenPorts {
    LISTEN_PORTS.get().copied().unwrap_or_default()
}
