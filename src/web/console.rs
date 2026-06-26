//! Console management API used by the CLI / banner (owner check, reset) and the
//! startup banner info. Reads/writes the persisted web settings.
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

/// uid of the OS user that first initialized the console (for the reset
/// authorization check). None when the console isn't initialized yet.
pub fn console_owner_uid() -> Option<u32> {
    settings::load().map(|s| s.owner_uid)
}

/// Reset the console to the uninitialized state, returning the freshly-armed
/// init token (so `dn7 panel reset` can print it). Caller is responsible for the
/// owner/root authorization check (see `console_owner_uid`).
pub fn reset_console() -> anyhow::Result<String> {
    let mut s = settings::load()
        .ok_or_else(|| anyhow::anyhow!("console not initialized — start the panel once first"))?;
    let token = s.reset();
    settings::save(&s)?;
    Ok(token)
}
