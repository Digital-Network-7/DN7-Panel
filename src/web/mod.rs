//! On-box web management console.
//!
//! A small axum HTTP server bound to `0.0.0.0:<port>` (default 1080) that
//! exposes the panel's existing capabilities (monitoring, terminal, Docker,
//! Nginx, MySQL, file transfer, processes) directly on the host — no backend
//! round-trip. It reuses the same per-capability JSON dispatchers the backend
//! relay uses (`docker::web_dispatch`, etc.) and the same PTY/file code.
//!
//! SECURITY MODEL (per product decision): the console binds to all interfaces
//! over plain HTTP and authenticates with an auto-generated random password.
//! A login mints a bearer session token (in-memory, expiring). Login attempts
//! are rate-limited. Because traffic is plaintext, operators are advised to
//! firewall the port to trusted sources. The password + settings persist in
//! `<data>/web.json` (0600).
//!
//! Disabling/changing the port is done from the console's settings page and
//! persisted; a restart applies a new port.

mod auth;
mod branding;
mod server;
mod settings;

pub use server::spawn;

/// The current console password in plaintext, read from `<data>/web.json`
/// without seeding a new file. None when the console hasn't been initialized.
/// Used by the `dn7-panel password` subcommand so an operator can retrieve the
/// (encrypted-at-rest) password on the host without it ever being logged.
pub fn console_password() -> Option<String> {
    settings::load().map(|s| s.password_plain())
}

/// Console info for the startup banner. Reads the settings, **seeding them on
/// first run** so the auto-generated password exists. The password is returned
/// only while it's still the auto-generated default; once the operator sets
/// their own, it's hidden (`password = None`, `customized = true`).
pub struct ConsoleInfo {
    pub enabled: bool,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub customized: bool,
}

pub fn console_info(default_enabled: bool, default_port: u16) -> ConsoleInfo {
    let s = settings::load_or_init(default_enabled, default_port);
    ConsoleInfo {
        enabled: s.enabled,
        port: s.port,
        username: s.username.clone(),
        password: if s.pw_default {
            Some(s.password_plain())
        } else {
            None
        },
        customized: !s.pw_default,
    }
}
