//! Console management API used by the CLI / banner (port, entry path, owner,
//! reset) and the startup banner info. Reads/writes the persisted web settings.
use super::settings;

/// Console info for the startup banner. Reads the settings, **seeding them on
/// first run** (uninitialized, with a one-time init token). Before setup the
/// banner shows the token-gated init URLs; after setup, the console access URL.
pub struct ConsoleInfo {
    /// One-time init token (empty once initialized).
    pub init_token: String,
    /// Whether first-run setup is complete.
    pub initialized: bool,
    /// The configured external access address (IP or domain); empty pre-init.
    pub external_address: String,
    /// Console HTTPS mode: "none" | "selfsigned" | "le".
    pub https_mode: String,
}

pub fn console_info(default_port: u16) -> ConsoleInfo {
    let (s, _fresh) = settings::load_or_init(default_port);
    ConsoleInfo {
        init_token: s.init_token,
        initialized: s.initialized,
        external_address: s.external_address,
        https_mode: s.https_mode,
    }
}

/// The console access URL once initialized (None while the wizard is pending).
/// Uses the configured external address (falling back to `host`) + the chosen
/// scheme; the edge serves the console on :80/:443 (no port, no entry path).
pub fn access_url(host: &str) -> Option<String> {
    let s = settings::load()?;
    if !s.initialized {
        return None;
    }
    let scheme = if s.https_mode == "none" { "http" } else { "https" };
    let h = if s.external_address.is_empty() {
        host.to_string()
    } else {
        s.external_address.clone()
    };
    Some(format!("{scheme}://{h}/"))
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
