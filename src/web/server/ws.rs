//! Terminal (PTY over WebSocket) handlers (split from web/server.rs).
use super::*;

// ---------------------------------------------------------------------------
// Terminal (PTY over WebSocket)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct WsAuth {
    #[serde(default)]
    ticket: String,
}

pub(crate) async fn terminal_ws(
    State(state): State<Shared>,
    Query(q): Query<WsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    // WebSocket upgrades can't carry an Authorization header from the browser,
    // so a one-time ticket (minted via POST /api/ticket) authorizes the upgrade.
    let user = match state.auth.consume_ticket(&q.ticket) {
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

/// WS query for a container terminal: one-time ticket + container ref.
#[derive(serde::Deserialize)]
pub(crate) struct ContainerWsAuth {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    container: String,
}

pub(crate) async fn container_terminal_ws(
    State(state): State<Shared>,
    Query(q): Query<ContainerWsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    // Container exec is a Docker capability — admin only. The ticket owner must
    // resolve to an admin account.
    let user = match state.auth.consume_ticket(&q.ticket) {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    match resolve_account(&state, &user) {
        Some(a) if a.is_admin => {}
        _ => return api_err(StatusCode::FORBIDDEN, "auth.forbidden"),
    }
    let container = q.container.clone();
    if container.is_empty() {
        return api_err(StatusCode::BAD_REQUEST, "terminal.missing_container");
    }
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = crate::web::terminal::run_web_container_exec(socket, &container).await {
            tracing::debug!("web container terminal ended: {e}");
        }
    })
}
