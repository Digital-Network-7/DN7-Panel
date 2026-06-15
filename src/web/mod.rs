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

mod branding;
mod server;
mod settings;
mod totp;
mod users;

pub use server::spawn;

/// Console info for the startup banner. Reads the settings, **seeding them on
/// first run** so the password exists. `new_password` is `Some` only on the run
/// that generated it (shown once); otherwise the password is irrecoverable and
/// the banner points the operator to `dn7 panel reset`.
pub struct ConsoleInfo {
    pub port: u16,
    pub username: String,
    pub new_password: Option<String>,
    /// Safe-entry path ("/" when disabled) and whether HTTPS is on — for the
    /// access URL shown in the banner / CLI.
    pub entry_path: String,
    pub https: bool,
}

pub fn console_info(default_port: u16) -> ConsoleInfo {
    let (s, fresh) = settings::load_or_init(default_port);
    ConsoleInfo {
        port: s.port,
        username: s.username,
        new_password: fresh,
        entry_path: s.entry_path,
        https: s.https,
    }
}

/// Build the access URL from the persisted settings + a host. Returns None when
/// the console isn't initialized.
pub fn access_url(host: &str) -> Option<String> {
    let s = settings::load()?;
    let scheme = if s.https { "https" } else { "http" };
    let entry = if s.entry_path == "/" {
        String::new()
    } else {
        s.entry_path.clone()
    };
    Some(format!("{scheme}://{host}:{}{entry}", s.port))
}

/// Set the console port (random high port when `None`). Returns the new port.
pub fn console_port_set(port: Option<u16>) -> anyhow::Result<u16> {
    let mut s = settings::load()
        .ok_or_else(|| anyhow::anyhow!("console not initialized — start the panel once first"))?;
    s.port = port.unwrap_or_else(settings::gen_port);
    settings::save(&s)?;
    Ok(s.port)
}

/// Set the safe-entry path (random when `None`). Returns the new "/<token>".
pub fn console_entry_set(path: Option<String>) -> anyhow::Result<String> {
    let mut s = settings::load()
        .ok_or_else(|| anyhow::anyhow!("console not initialized — start the panel once first"))?;
    let entry = match path {
        Some(p) => settings::normalize_entry(&p).ok_or_else(|| {
            anyhow::anyhow!("invalid entry path (use letters/digits/_- up to 32)")
        })?,
        None => settings::gen_entry(),
    };
    s.entry_path = entry.clone();
    settings::save(&s)?;
    Ok(entry)
}

/// uid of the OS user that first initialized the console (for the reset
/// authorization check). None when the console isn't initialized yet.
pub fn console_owner_uid() -> Option<u32> {
    settings::load().map(|s| s.owner_uid)
}

/// Reset the console account + password to a freshly-generated default,
/// returning the new plaintext password (to show once). Caller is responsible
/// for the owner/root authorization check (see `console_owner_uid`).
pub fn reset_console() -> anyhow::Result<String> {
    let mut s = settings::load()
        .ok_or_else(|| anyhow::anyhow!("console not initialized — start the panel once first"))?;
    let pw = s.reset();
    settings::save(&s)?;
    Ok(pw)
}
