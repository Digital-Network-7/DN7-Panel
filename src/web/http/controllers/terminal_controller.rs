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
/// its authority must equal the request `Host`; a cross-site page is refused.
/// A missing `Origin` (non-browser client) is allowed — the one-time ticket
/// still authorizes. Defense in depth: auth is bearer-only (no ambient cookie),
/// so cross-site WS hijacking is already structurally prevented; this also
/// rejects mismatched origins before a ticket is consumed.
fn ws_origin_ok(headers: &header::HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // no Origin header (non-browser) — ticket is the gate
    };
    let origin_authority = origin.split_once("://").map(|(_, a)| a).unwrap_or(origin);
    let host = headers
        .get(header::HOST)
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
    ws.on_upgrade(move |socket| handle_terminal(socket, login_user))
}

pub(crate) async fn handle_terminal(socket: WebSocket, login_user: Option<String>) {
    if let Err(e) = crate::web::terminal::run_web_pty(socket, login_user).await {
        tracing::debug!("web terminal ended: {e}");
    }
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
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = crate::web::terminal::run_web_container_exec(socket, &container).await {
            tracing::debug!("web container terminal ended: {e}");
        }
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
