//! Setup: bring up the built-in (in-process) web server. DN7 Panel serves
//! :80/:443 itself with the pure-Rust edge reverse proxy — there is no external
//! nginx to install or drive.
use super::*;

// Validation (no raw config; everything is form-driven and checked).
// ---------------------------------------------------------------------------

// Validators (valid_server_name, primary_host, valid_host_token, …) live in
// the `validate` submodule.

// ---------------------------------------------------------------------------
// Setup: start the built-in web server. Detached so the UI can stream progress.
// ---------------------------------------------------------------------------

pub(crate) fn start_setup() -> Result<Value> {
    const SETUP_OP: &str = "setup";
    if opreg::op_running(SETUP_OP) {
        return Ok(json!({ "op_id": SETUP_OP, "already_running": true }));
    }
    if !is_root() {
        return Err(website_err(WebsiteError::NeedRoot));
    }

    op_create(SETUP_OP, "setup", "host");
    tokio::spawn(async move {
        match setup_host(SETUP_OP).await {
            Ok(()) => {
                op_push(SETUP_OP, &pmsg("ng.setup_done", &[]));
                op_finish(SETUP_OP, "done", "");
            }
            Err(e) => op_finish(SETUP_OP, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": SETUP_OP, "target": "host" }))
}

/// Bring up the built-in web server: ensure the cert/www state dirs exist, mark
/// setup complete, then start the in-process edge listener and load the current
/// manifests into its route table.
pub(crate) async fn setup_host(op_id: &str) -> Result<()> {
    op_push(op_id, &pmsg("ng.ensure_enable", &[]));
    // Our state dirs (certs + webroots) that the edge reads from.
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;

    // Mark setup so `layout()` / `edge_reload()` are unblocked, then start the
    // built-in web server and bind :80/:443. `spawn()` is idempotent.
    mark_setup()?;
    dn7_edge::spawn();
    edge_reload().await?;
    Ok(())
}
