//! App-facing website adapters + shared layout/error helpers.
//!
//! The application layer (`app::website`) owns op routing and parses the
//! capability commands; this module exposes the infra use-case bodies it
//! delegates to (read accessors + per-op write adapters), plus the on-disk
//! `Layout`, the edge-reload chokepoint, and the typed-error → `ERR_CODE:`
//! bridge shared across the website submodules.
use super::*;

/// Build the transitional `anyhow` error for a typed [`WebsiteError`]: prefixes
/// the semantic code with the `ERR_CODE:` transport marker the `op_err_body`
/// web boundary parses into the wire `code`. The marker lives here (infra), not
/// in the domain enum, per §2/§4.
pub(crate) fn website_err(e: WebsiteError) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", e.code())
}

/// Read-only website-settings snapshot for the `get_settings` use-case (owned by
/// `app::website`): persisted default-site + http tuning, plus whether each has
/// been configured. Pure read — no edge reload.
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
/// `app::website`). Pure read — manifests only, no edge contact.
pub(crate) fn sites_snapshot() -> Vec<crate::core::website::Site> {
    load_sites()
}

/// Detached-op-registry read projections for the `app::website` `list_ops` /
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

/// Gather the persisted website model and push it into the in-process edge server
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
    // Inject the container-upstream resolver once (idempotent): the edge crate
    // resolves `proxy_container` upstreams through this instead of depending on
    // the container backend (bollard/dn7) directly.
    dn7_edge::set_upstream_resolver(|name, port| async move {
        crate::infra::website::resolve_container_upstream(&name, port).await
    });

    // Listen ports (bound ONCE by the edge — a change needs a panel restart). The
    // console gets a DEDICATED listener only when its port is set AND differs from
    // both website ports; otherwise it's merged onto a website listener by Host
    // (today's behaviour). `set_listen_ports` is set-once, so the first reload
    // (edge_autostart, before spawn) wins.
    let http_port = ws
        .as_ref()
        .map(|w| w.website_http_port)
        .filter(|p| *p != 0)
        .unwrap_or(80);
    let https_port = ws
        .as_ref()
        .map(|w| w.website_https_port)
        .filter(|p| *p != 0)
        .unwrap_or(443);
    let console_raw = ws.as_ref().map(|w| w.console_port).unwrap_or(0);
    let console_tls = ws.as_ref().map(|w| w.https_mode != "none").unwrap_or(false);
    let dedicated = console_raw != 0 && console_raw != http_port && console_raw != https_port;
    // Load user sites once (reused for the route table below). :80 must stay bound
    // for ACME HTTP-01 when any Let's Encrypt cert exists (the console's, or any LE
    // site) even if the website HTTP port moved off 80.
    let panel_sites = if setup { load_sites() } else { Vec::new() };
    let need_acme_80 = ws.as_ref().map(|w| w.https_mode == "le").unwrap_or(false)
        || panel_sites.iter().any(|s| s.ssl && s.cert_mode == "le");
    dn7_edge::set_listen_ports(dn7_edge::ListenPorts {
        website_http: http_port,
        website_https: https_port,
        console: if dedicated { console_raw } else { 0 },
        console_tls,
        need_acme_80,
    });

    let console = dn7_edge::ConsoleParams {
        external_address: ws
            .as_ref()
            .map(|w| w.external_address.clone())
            .unwrap_or_default(),
        https_mode: ws
            .as_ref()
            .map(|w| w.https_mode.clone())
            .unwrap_or_else(|| "none".to_string()),
        initialized: ws.as_ref().map(|w| w.initialized).unwrap_or(false),
        dedicated_console: dedicated,
    };
    let input = dn7_edge::ReloadInput {
        sites: to_edge(panel_sites)?,
        access: if setup {
            to_edge(load_access())?
        } else {
            Vec::new()
        },
        default_site: if setup {
            to_edge(load_webglobal().default_site)?
        } else {
            dn7_edge::model::DefaultSite::default()
        },
        tuning: to_edge(current_tuning())?,
        cert_dir: certs_dir(),
        www_dir: www_dir(),
        console,
    };
    dn7_edge::reload(input).await
}

/// Convert a panel website-domain value into the edge crate's matching input
/// type via a serde round-trip (the field names line up; the edge model defaults
/// any field the panel doesn't carry). The reload path runs rarely, so the
/// serialize/deserialize cost is irrelevant.
///
/// FAIL-CLOSED: a serialize/deserialize failure (e.g. a field-name drift between
/// the panel and edge models) returns an error so [`edge_reload`] aborts and the
/// edge keeps serving its last-good config (an `nginx -t`-style rejection),
/// rather than silently swapping in a `Default`. A silent `Default` for the
/// access list would be an EMPTY `Vec<AccessList>` — dropping every site's
/// HTTP-Basic / IP protection while reload reported success — which directly
/// contradicts the edge's own fail-closed ACL policy (unparseable rule → deny).
fn to_edge<T, U>(v: T) -> Result<U>
where
    T: serde::Serialize,
    U: serde::de::DeserializeOwned,
{
    let json = serde_json::to_value(v).map_err(|e| anyhow!("edge model serialize failed: {e}"))?;
    serde_json::from_value(json).map_err(|e| anyhow!("edge model deserialize failed: {e}"))
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
    // The ports currently in conflict (fall back to the configured edge ports).
    let ports = dn7_edge::port_conflict().unwrap_or_else(configured_edge_ports);
    let killed = kill_port_holders(&ports).await;

    // Re-attempt the bind now the occupants are gone. `spawn()` re-attempts
    // because the previous conflicted run returned (clearing its guard).
    dn7_edge::spawn();
    // Give the listener a moment to bind and record its new state.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    match dn7_edge::port_conflict() {
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

/// The edge's configured public ports: 80 (always bound for ACME issuance) + the
/// website HTTP/HTTPS ports + a dedicated console port (if any), de-duplicated.
/// Used for the force-start fallback.
pub(crate) fn configured_edge_ports() -> Vec<u16> {
    let ws = crate::infra::store::settings::load();
    let http = ws
        .as_ref()
        .map(|w| w.website_http_port)
        .filter(|p| *p != 0)
        .unwrap_or(80);
    let https = ws
        .as_ref()
        .map(|w| w.website_https_port)
        .filter(|p| *p != 0)
        .unwrap_or(443);
    let mut v = vec![80, http, https];
    if let Some(c) = ws.as_ref().map(|w| w.console_port) {
        if c != 0 && c != http && c != https {
            v.push(c);
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

/// Which of `ports` currently have a listener — a pre-serve check used by the
/// CLI first-run wizard before it offers to take the edge ports over.
pub(crate) async fn ports_with_listener(ports: &[u16]) -> Vec<u16> {
    let mut out = Vec::new();
    for &p in ports {
        if !super::detect::pids_on_port(p).await.is_empty() {
            out.push(p);
        }
    }
    out
}

/// PIDs listening on `port` (for reporting which process/unit holds it).
pub(crate) async fn listeners_on(port: u16) -> Vec<u32> {
    super::detect::pids_on_port(port).await
}

/// Take `ports` over for the panel: SIGTERM→SIGKILL the holders (the same
/// pure-Rust mechanism as `force_start` — no `systemctl`). Returns the ports
/// STILL occupied afterwards (e.g. a systemd service that auto-restarted).
pub(crate) async fn take_over_ports(ports: &[u16]) -> Vec<u16> {
    let _ = super::detect::kill_port_holders(ports).await;
    ports_with_listener(ports).await
}

/// Ensure the console TLS cert exists for the configured HTTPS mode, issuing it
/// if missing. The CLI first-run wizard DEFERS Let's Encrypt (its ACME challenge
/// needs the edge serving :80, which isn't up during pre-serve setup); the panel
/// calls this at startup, once the edge is bound, to finish that issuance.
/// Self-signed was already issued at setup time, so this is a no-op for it (and
/// on reboots). The caller passes the mode/address (the settings live in the
/// `web` layer; infra doesn't read up into it).
pub(crate) async fn ensure_console_cert(https_mode: &str, external_address: &str) {
    if https_mode != "le" && https_mode != "selfsigned" {
        return;
    }
    if console_crt_path().exists() && console_key_path().exists() {
        return; // already issued
    }
    if let Err(e) = console_apply_tls(https_mode, external_address).await {
        tracing::warn!("deferred console cert issuance failed: {e:#}");
    } else if let Err(e) = edge_reload().await {
        tracing::warn!("edge reload after console cert issuance failed: {e:#}");
    } else {
        tracing::info!("console cert issued ({https_mode}) for {external_address}");
    }
}

/// Start the in-process edge server at panel startup. The edge owns :80/:443 on
/// EVERY boot — it fronts the console — so always bind the listener via the
/// idempotent `spawn()`. Only load the persisted user-site manifests once the
/// website capability is set up; before that the edge serves the empty-config
/// default_site (and, once wired, the console route).
pub(crate) async fn edge_autostart() {
    // Always publish the route table (even on a fresh, un-set-up box) so the
    // edge serves the console / init wizard, then bind the listeners.
    if let Err(e) = edge_reload().await {
        tracing::error!("edge: initial config load failed: {e:#}");
    }
    dn7_edge::spawn();
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

#[cfg(test)]
mod parity_tests {
    use super::*;

    /// B1 guard: the panel→edge access-list serde round-trip (`to_edge`) MUST
    /// preserve the auth users + IP rules. `to_edge` is now fail-closed for a
    /// total (de)serialize failure; this catches the subtler PARTIAL drift — a
    /// renamed/dropped field that would silently empty a site's Basic-Auth / IP
    /// protection at the edge while reload reports success.
    #[test]
    fn access_list_round_trips_without_losing_auth_or_ip_rules() {
        let panel = vec![AccessList {
            id: "a1".into(),
            name: "protected".into(),
            satisfy: "all".into(),
            pass_auth: true,
            users: vec![AccessUser {
                username: "admin".into(),
                hash: "{SHA}deadbeef".into(),
            }],
            clients: vec![
                AccessClient {
                    directive: "allow".into(),
                    address: "10.0.0.0/8".into(),
                },
                AccessClient {
                    directive: "deny".into(),
                    address: "all".into(),
                },
            ],
        }];
        let edge: Vec<dn7_edge::model::AccessList> =
            to_edge(panel).expect("access list must round-trip, not fail-closed here");
        assert_eq!(edge.len(), 1, "the access list must not be dropped");
        let a = &edge[0];
        assert_eq!(a.id, "a1");
        assert_eq!(a.satisfy, "all");
        assert!(a.pass_auth);
        assert_eq!(
            a.users.len(),
            1,
            "auth users must survive (else Basic-Auth silently off)"
        );
        assert_eq!(a.users[0].username, "admin");
        assert_eq!(a.users[0].hash, "{SHA}deadbeef");
        assert_eq!(
            a.clients.len(),
            2,
            "IP rules must survive (else IP protection silently off)"
        );
        assert_eq!(a.clients[0].directive, "allow");
        assert_eq!(a.clients[0].address, "10.0.0.0/8");
    }
}
