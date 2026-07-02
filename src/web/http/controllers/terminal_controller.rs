//! Terminal (PTY over WebSocket) handlers (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Terminal (PTY over WebSocket)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct WsAuth {
    #[serde(default)]
    ticket: String,
}

/// Same-origin guard for WebSocket upgrades. When the browser sends an `Origin`,
/// its authority must equal the host the browser used; a cross-site page is
/// refused. A missing `Origin` (non-browser client) is allowed — the one-time
/// ticket still authorizes. Defense in depth: auth is bearer-only (no ambient
/// cookie), so cross-site WS hijacking is already structurally prevented; this
/// also rejects mismatched origins before a ticket is consumed.
///
/// The console runs behind the edge, which rewrites `Host` to the loopback
/// upstream and carries the real external host in `X-Forwarded-Host` — so the
/// comparison uses that (falling back to `Host` for a direct/tunnel connection).
fn ws_origin_ok(headers: &header::HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // no Origin header (non-browser) — ticket is the gate
    };
    let origin_authority = origin.split_once("://").map(|(_, a)| a).unwrap_or(origin);
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    !host.is_empty() && origin_authority == host
}

pub(crate) async fn terminal_ws(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<WsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    if !ws_origin_ok(&headers) {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    // WebSocket upgrades can't carry an Authorization header from the browser,
    // so a one-time ticket (minted via POST /api/ticket) authorizes the upgrade.
    let user = match state.auth.consume_ticket(&q.ticket, "terminal") {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    // Run the shell as the account's system user (non-super), else as root.
    let login_user = resolve_account(&state, &user).and_then(|a| a.system_user);
    // Audit the highest-privilege action in the panel: a root/tenant PTY. Record
    // at session OPEN (ticket + origin already passed) with the effective shell
    // identity as the target, and a paired close record with the duration.
    let shell_id = login_user.clone().unwrap_or_else(|| "root".to_string());
    audit::record(&user, "terminal.open", &shell_id, true, "");
    ws.on_upgrade(move |socket| handle_terminal(socket, login_user, user, shell_id))
}

pub(crate) async fn handle_terminal(
    socket: WebSocket,
    login_user: Option<String>,
    actor: String,
    shell_id: String,
) {
    let started = std::time::Instant::now();
    if let Err(e) = crate::web::terminal::run_web_pty(socket, login_user).await {
        tracing::debug!("web terminal ended: {e}");
    }
    let secs = started.elapsed().as_secs();
    audit::record(
        &actor,
        "terminal.close",
        &shell_id,
        true,
        &format!("{secs}s"),
    );
}

/// WS query for a container terminal: one-time ticket + container ref, plus an
/// optional step-up token required only when the target is a privileged /
/// host-namespaced container (exec into which grants effective host root).
#[derive(serde::Deserialize)]
pub(crate) struct ContainerWsAuth {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    container: String,
    #[serde(default)]
    stepup: String,
}

pub(crate) async fn container_terminal_ws(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<ContainerWsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    if !ws_origin_ok(&headers) {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    // Container exec is a Docker capability — admin only. The ticket owner must
    // resolve to an admin account.
    let user = match state.auth.consume_ticket(&q.ticket, "terminal") {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    let acct = match resolve_account(&state, &user) {
        Some(a) if a.is_admin => a,
        _ => return api_err(StatusCode::FORBIDDEN, "auth.forbidden"),
    };
    let container = q.container.clone();
    if container.is_empty() {
        return api_err(StatusCode::BAD_REQUEST, "terminal.missing_container");
    }
    // A privileged / host-namespaced container grants effective host root via
    // exec, the same escalation the super-only create guardrail blocks. Restrict
    // exec into such a container to the super-admin so a non-super admin can't
    // side-step that guardrail through an already-running container — and
    // additionally require a fresh step-up re-auth (the highest-risk exec path),
    // matching self-update / settings. The step-up token rides the query string
    // because a WS upgrade can't carry the `X-DN7-Stepup` header from a browser.
    if crate::app::docker::container_is_privileged(&container).await {
        if !acct.is_super {
            return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
        }
        if !state.auth.consume_stepup(&q.stepup, &acct.username) {
            return api_err(StatusCode::FORBIDDEN, "auth.stepup_required");
        }
    }
    // Audit every container-exec shell at session OPEN, once all authz — admin,
    // plus super+step-up for a privileged (effective-host-root) target — has
    // passed. Paired close record carries the session duration.
    let actor = acct.username.clone();
    audit::record(&actor, "container.exec", &container, true, "");
    ws.on_upgrade(move |socket| async move {
        let started = std::time::Instant::now();
        if let Err(e) = crate::web::terminal::run_web_container_exec(socket, &container).await {
            tracing::debug!("web container terminal ended: {e}");
        }
        let secs = started.elapsed().as_secs();
        audit::record(
            &actor,
            "container.exec.close",
            &container,
            true,
            &format!("{secs}s"),
        );
    })
}

/// Query for the privileged-container probe.
#[derive(serde::Deserialize)]
pub(crate) struct ContainerPrivQuery {
    #[serde(default)]
    container: String,
}

/// POST /api/container/privileged — does exec into this container grant
/// effective host root (privileged mode / host namespace)? The UI uses the
/// answer to decide whether opening a container terminal needs a step-up
/// re-auth first (so the common, non-privileged case stays frictionless).
/// Admin only; the authoritative gate still lives in `container_terminal_ws`.
pub(crate) async fn container_privileged(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(q): Json<ContainerPrivQuery>,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    if q.container.is_empty() {
        return api_err(StatusCode::BAD_REQUEST, "terminal.missing_container");
    }
    let privileged = crate::app::docker::container_is_privileged(&q.container).await;
    Json(json!({ "ok": true, "data": { "privileged": privileged } })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> header::HeaderMap {
        let mut h = header::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn ws_origin_matches_forwarded_host_behind_edge() {
        // Behind the edge: Host is the loopback upstream, the real host rides
        // X-Forwarded-Host — the Origin must match THAT, not Host.
        assert!(ws_origin_ok(&hm(&[
            ("origin", "https://mypanel.dn7.cn"),
            ("x-forwarded-host", "mypanel.dn7.cn"),
            ("host", "127.0.0.1:1080"),
        ])));
        // Cross-site page: Origin doesn't match the forwarded host -> refused.
        assert!(!ws_origin_ok(&hm(&[
            ("origin", "https://evil.example"),
            ("x-forwarded-host", "mypanel.dn7.cn"),
            ("host", "127.0.0.1:1080"),
        ])));
    }

    #[test]
    fn ws_origin_falls_back_to_host_when_not_proxied() {
        // Direct / SSH-tunnel connection (no X-Forwarded-Host): compare to Host.
        assert!(ws_origin_ok(&hm(&[
            ("origin", "http://localhost:1080"),
            ("host", "localhost:1080"),
        ])));
        // No Origin (non-browser client) is allowed — the ticket is the gate.
        assert!(ws_origin_ok(&hm(&[("host", "127.0.0.1:1080")])));
    }
}
