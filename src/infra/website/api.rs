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
    let input = crate::edge::ReloadInput {
        sites: load_sites(),
        access: load_access(),
        default_site: load_webglobal().default_site,
        tuning: current_tuning(),
        cert_dir: certs_dir(),
        www_dir: www_dir(),
    };
    crate::edge::reload(input).await
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

/// Start the in-process edge server at panel startup when the nginx capability
/// has already been set up: load the current manifest into the route table and
/// bind :80/:443. A no-op before setup (nothing to serve yet); `spawn()` is
/// idempotent so this is safe to call alongside the setup flow.
pub(crate) async fn edge_autostart() {
    if is_setup() {
        if let Err(e) = edge_reload().await {
            tracing::error!("edge: initial config load failed: {e:#}");
        }
        crate::edge::spawn();
    }
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
