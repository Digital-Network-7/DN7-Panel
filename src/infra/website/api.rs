//! App-facing nginx adapters + shared layout/error helpers.
//!
//! The application layer (`app::nginx`) owns op routing and parses the
//! capability commands; this module exposes the infra use-case bodies it
//! delegates to (read accessors + per-op write adapters), plus the on-disk
//! `Layout`, the edge-reload chokepoint, and the typed-error → `ERR_CODE:`
//! bridge shared across the nginx submodules.
use super::*;

/// Build the transitional `anyhow` error for a typed [`WebsiteError`]: prefixes
/// the semantic code with the `ERR_CODE:` transport marker the `op_err_body`
/// web boundary parses into the wire `code`. The marker lives here (infra), not
/// in the domain enum, per §2/§4.
pub(crate) fn website_err(e: WebsiteError) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", e.code())
}

/// Read-only website-settings snapshot for the `get_settings` use-case (owned by
/// `app::nginx`): persisted default-site + http tuning, plus whether each has
/// been configured. Pure read — no nginx reload.
pub(crate) fn web_settings_state() -> (
    crate::core::website::WebGlobal,
    crate::core::website::HttpTuning,
    bool,
    bool,
) {
    (
        load_webglobal(),
        load_tuning_opt().unwrap_or_default(),
        websettings_file().exists(),
        webtuning_file().exists(),
    )
}

/// Read-only managed-site list for the `list_sites` use-case (owned by
/// `app::nginx`). Pure read — manifests only, no nginx contact.
pub(crate) fn sites_snapshot() -> Vec<crate::core::website::Site> {
    load_sites()
}

/// Detached-op-registry read projections for the `app::nginx` `list_ops` /
/// `op_log` use-cases (the registry's own fns are `pub(super)`).
pub(crate) fn ops_snapshot_value() -> Value {
    ops_snapshot()
}
pub(crate) fn op_log_value(op_id: &str) -> Value {
    op_log(op_id)
}

pub(crate) fn op_setup() -> Result<Value> {
    start_setup()
}
pub(crate) async fn op_add_site(cmd: &SiteForm) -> Result<Value> {
    add_site(cmd).await
}
pub(crate) async fn op_update_site(cmd: &SiteForm) -> Result<Value> {
    update_site(cmd).await
}
pub(crate) async fn op_remove_site(cmd: &RemoveSite) -> Result<Value> {
    remove_site(cmd).await
}
pub(crate) async fn op_create_cert(cmd: &CreateCert) -> Result<Value> {
    create_cert(cmd).await
}
pub(crate) async fn op_renew_cert(cmd: &RenewCert) -> Result<Value> {
    renew_cert(cmd).await
}
pub(crate) async fn op_delete_cert(cmd: &DeleteCert) -> Result<Value> {
    delete_cert(cmd).await
}
pub(crate) async fn op_save_access(cmd: &SaveAccess) -> Result<Value> {
    save_access_op(cmd).await
}
pub(crate) async fn op_delete_access(cmd: &DeleteAccess) -> Result<Value> {
    delete_access_op(cmd).await
}
pub(crate) async fn op_reload() -> Result<()> {
    reload().await
}

/// Gather the persisted nginx model and push it into the in-process edge server
/// (the pure-Rust reverse proxy). This is the bridge the reload chokepoint and
/// the panel-role startup call use: it builds + validates + atomically swaps the
/// route table, returning an `nginx -t`-style error (without disturbing the live
/// config) if the new model is invalid.
pub(crate) async fn edge_reload() -> Result<()> {
    // User-site manifests only exist after website setup; the console route is
    // synthesized from WebSettings regardless, so the edge always serves the
    // console / init wizard.
    let setup = is_setup();
    let ws = crate::infra::store::settings::load();
    let console = crate::edge::ConsoleParams {
        external_address: ws.as_ref().map(|w| w.external_address.clone()).unwrap_or_default(),
        https_mode: ws
            .as_ref()
            .map(|w| w.https_mode.clone())
            .unwrap_or_else(|| "none".to_string()),
        initialized: ws.as_ref().map(|w| w.initialized).unwrap_or(false),
    };
    let input = crate::edge::ReloadInput {
        sites: if setup { load_sites() } else { Vec::new() },
        access: if setup { load_access() } else { Vec::new() },
        default_site: if setup {
            load_webglobal().default_site
        } else {
            crate::core::website::DefaultSite::default()
        },
        tuning: current_tuning(),
        cert_dir: certs_dir(),
        www_dir: www_dir(),
        console,
    };
    crate::edge::reload(input).await
}

/// First-run console TLS: issue (or clear) the console cert for the chosen HTTPS
/// mode, writing the fixed `cert-console.*` paths the edge loads for the managed
/// console route. Runs before website setup (no `Layout`). "le" awaits the full
/// ACME dance, so the caller only advances the wizard on a verified cert.
pub(crate) async fn console_apply_tls(https_mode: &str, external_address: &str) -> Result<()> {
    match https_mode {
        "le" => issue_console_le(external_address).await?,
        "selfsigned" => issue_console_self_signed(external_address).await?,
        _ => {
            // "none": drop any stale console cert so the edge serves plain HTTP.
            let _ = std::fs::remove_file(console_crt_path());
            let _ = std::fs::remove_file(console_key_path());
        }
    }
    Ok(())
}

pub(crate) fn op_dismiss_registry(op_id: &str) {
    op_dismiss(op_id);
}

/// Force-start the built-in web server when :80/:443 are held by a foreign
/// process: kill the occupant(s) then re-attempt the bind. Root-only (it signals
/// other processes). Returns the PIDs killed on success, or an error if a port
/// is still occupied afterwards.
pub(crate) async fn force_start() -> Result<Value> {
    if !is_root() {
        return Err(website_err(WebsiteError::NeedRoot));
    }
    // The ports currently in conflict (fall back to the well-known pair).
    let ports = crate::edge::port_conflict().unwrap_or_else(|| vec![80, 443]);
    let killed = kill_port_holders(&ports).await;

    // Re-attempt the bind now the occupants are gone. `spawn()` re-attempts
    // because the previous conflicted run returned (clearing its guard).
    crate::edge::spawn();
    // Give the listener a moment to bind and record its new state.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    match crate::edge::port_conflict() {
        None => Ok(json!({ "started": true, "killed": killed })),
        Some(still) => Err(anyhow!(
            "强制启动后端口 {} 仍被占用，请手动停止占用进程后重试",
            still
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("、")
        )),
    }
}

/// Start the in-process edge server at panel startup. The edge owns :80/:443 on
/// EVERY boot — it fronts the console (and the pre-init wizard), not just user
/// websites — so always bind the listener via the idempotent `spawn()`. Only
/// load the persisted user-site manifests once the website capability is set up;
/// before that the edge serves the empty-config default_site (and, once wired,
/// the console route / init wizard).
pub(crate) async fn edge_autostart() {
    // Always publish the route table (even on a fresh, un-set-up box) so the
    // edge serves the console / init wizard, then bind the listeners.
    if let Err(e) = edge_reload().await {
        tracing::error!("edge: initial config load failed: {e:#}");
    }
    crate::edge::spawn();
}

/// The on-disk directories the edge server reads cert PEMs and static webroots
/// from. The edge LOADS the same files the cert/upload writers produce; there
/// are no generated nginx conf files anymore.
#[derive(Clone)]
pub(crate) struct Layout {
    pub(crate) cert_store: std::path::PathBuf, // where we WRITE cert files
    pub(crate) www_store: std::path::PathBuf,  // where we WRITE webroots
}

pub(crate) fn layout() -> Result<Layout> {
    if !is_setup() {
        return Err(website_err(WebsiteError::NotSetup));
    }
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;
    Ok(Layout {
        cert_store: certs_dir(),
        www_store: www_dir(),
    })
}
