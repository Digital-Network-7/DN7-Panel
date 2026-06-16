//! App-facing nginx adapters + shared layout/error helpers.
//!
//! The application layer (`app::nginx`) owns op routing and parses the
//! capability commands; this module exposes the infra use-case bodies it
//! delegates to (read accessors + per-op write adapters), plus the on-disk
//! `Layout`, the `nginx -t` conf paths, and the typed-error → `ERR_CODE:`
//! bridge shared across the nginx submodules.
use super::*;

/// Build the transitional `anyhow` error for a typed [`NginxError`]: prefixes
/// the semantic code with the `ERR_CODE:` transport marker the `op_err_body`
/// web boundary parses into the wire `code`. The marker lives here (infra), not
/// in the domain enum, per §2/§4.
pub(crate) fn nginx_err(e: NginxError) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", e.code())
}

/// Read-only website-settings snapshot for the `get_settings` use-case (owned by
/// `app::nginx`): persisted default-site + http tuning, plus whether each has
/// been configured. Pure read — no nginx reload.
pub(crate) fn web_settings_state() -> (
    crate::core::nginx::WebGlobal,
    crate::core::nginx::HttpTuning,
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
pub(crate) fn sites_snapshot() -> Vec<crate::core::nginx::Site> {
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
pub(crate) fn op_dismiss_registry(op_id: &str) {
    op_dismiss(op_id);
}

/// Where generated conf files live, and the paths the running host nginx reads
/// certs/webroots from. Host-only: nginx reads the same on-disk paths we write.
#[derive(Clone)]
pub(crate) struct Layout {
    pub(crate) confd: std::path::PathBuf, // where we WRITE conf files (/etc/nginx/conf.d)
    pub(crate) cert_ref: String,          // dir nginx READS certs from (== cert_store)
    pub(crate) www_ref: String,           // dir nginx READS webroots from (== www_store)
    pub(crate) cert_store: std::path::PathBuf, // where we WRITE cert files
    pub(crate) www_store: std::path::PathBuf, // where we WRITE webroots
}

pub(crate) fn layout() -> Result<Layout> {
    if !is_setup() {
        return Err(nginx_err(NginxError::NotSetup));
    }
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;
    ensure_shared_conf();
    Ok(Layout {
        confd: std::path::PathBuf::from(HOST_CONFD),
        cert_ref: certs_dir().display().to_string(),
        www_ref: www_dir().display().to_string(),
        cert_store: certs_dir(),
        www_store: www_dir(),
    })
}

/// Write the shared http-context `map` once, so proxied sites can set the
/// WebSocket `Connection` header correctly: a normal request → `close`, a real
/// upgrade → `upgrade`. (Hardcoding `Connection: upgrade` on every request, as
/// older builds did, makes some backends abort plain HTTP requests, which the
/// browser surfaces as ERR_EMPTY_RESPONSE.) Named `00-` so it loads first and
/// isn't matched by the `dn7-<id>.conf` orphan cleanup.
pub(crate) fn ensure_shared_conf() {
    let path = std::path::Path::new(HOST_CONFD).join("00-dn7-maps.conf");
    let body = "map $http_upgrade $dn7_conn_upgrade {\n    default upgrade;\n    '' close;\n}\n\n\
                map $http_x_forwarded_proto $dn7_fwd_proto {\n    default $http_x_forwarded_proto;\n    '' $scheme;\n}\n";
    if std::fs::read_to_string(&path).ok().as_deref() != Some(body) {
        let _ = std::fs::create_dir_all(HOST_CONFD);
        let _ = std::fs::write(&path, body);
    }
}

pub(crate) fn conf_path(lo: &Layout, site_id: &str) -> std::path::PathBuf {
    lo.confd.join(format!("dn7-{site_id}.conf"))
}

/// Whether the cert **and** key a site references are present on disk (the
/// per-site `<id>.crt/.key` pair, or a referenced standalone named cert). The
/// single source of truth for "does this SSL site have usable cert material".
pub(crate) fn cert_present(lo: &Layout, site: &Site) -> bool {
    if site.cert_name.is_empty() {
        lo.cert_store.join(format!("{}.crt", site.id)).exists()
            && lo.cert_store.join(format!("{}.key", site.id)).exists()
    } else {
        named_crt_file(lo, &site.cert_name).exists()
    }
}

/// Degrade an SSL site to plain HTTP when its cert material is missing, so one
/// broken site can't fail the whole `nginx -t` reload. No-op for a non-SSL site.
pub(crate) fn degrade_if_cert_missing(lo: &Layout, site: &mut Site) {
    if site.ssl && !cert_present(lo, site) {
        site.ssl = false;
    }
}
