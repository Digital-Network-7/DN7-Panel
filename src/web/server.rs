//! Axum HTTP server for the on-box web console.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        ConnectInfo, Query, State,
    },
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::auth::{password_matches, AuthState};
use super::settings::{self, WebSettings};
use crate::config::AgentConfig;
use crate::metrics::Collector;

/// Shared web-console state.
pub struct WebState {
    cfg: AgentConfig,
    /// This server's agent token (to authenticate backend wx calls).
    agent_token: String,
    /// HTTP client for backend wx bind/login calls.
    http: reqwest::Client,
    auth: AuthState,
    settings: std::sync::Mutex<WebSettings>,
    /// Reused metrics collector (CPU% needs a persistent handle across reads).
    collector: Mutex<Collector>,
}

type Shared = Arc<WebState>;

/// Start the web console in a background task (no-op when disabled). Returns
/// immediately; the server runs for the process lifetime.
pub fn spawn(cfg: AgentConfig, agent_token: String) {
    let s = settings::load_or_init(cfg.web_enabled, cfg.web_port);
    if !s.enabled {
        tracing::info!("web console disabled; not starting");
        return;
    }
    let port = s.port;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let state: Shared = Arc::new(WebState {
        cfg,
        agent_token,
        http,
        auth: AuthState::new(),
        settings: std::sync::Mutex::new(s),
        collector: Mutex::new(Collector::new()),
    });
    tokio::spawn(async move {
        if let Err(e) = serve(state, port).await {
            tracing::warn!("web console exited: {e}");
        }
    });
}

async fn serve(state: Shared, port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        // Public (no auth): the login page + login endpoint.
        .route("/", get(index_page))
        .route("/api/login", post(login))
        // Authenticated API.
        .route("/api/logout", post(logout))
        .route("/api/metrics", get(metrics))
        .route("/api/procs", get(procs))
        .route("/api/settings", get(get_settings).post(put_settings))
        .route("/api/docker", post(docker_op))
        .route("/api/nginx", post(nginx_op))
        .route("/api/mysql", post(mysql_op))
        .route("/api/terminal", get(terminal_ws))
        // WeChat scan login proxied to the backend (NAT-safe via this agent).
        .route("/api/wx/login/start", post(wx_login_start))
        .route("/api/wx/login/poll", get(wx_login_poll))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "web console listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Extract a bearer token from the Authorization header.
fn bearer(headers: &header::HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
}

/// Require a valid session; returns `Some(response)` to short-circuit when
/// unauthorized, `None` when the request may proceed.
fn require_auth(state: &Shared, headers: &header::HeaderMap) -> Option<Response> {
    let token = bearer(headers).unwrap_or_default();
    if state.auth.valid(&token) {
        None
    } else {
        Some((StatusCode::UNAUTHORIZED, "未授权").into_response())
    }
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct LoginReq {
    #[serde(default)]
    username: String,
    password: String,
}

async fn login(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Response {
    let source = peer.ip().to_string();
    if !state.auth.login_allowed(&source) {
        return (StatusCode::TOO_MANY_REQUESTS, "尝试过于频繁，请稍后再试").into_response();
    }
    let (exp_user, exp_pw) = {
        let s = state.settings.lock().unwrap();
        (s.username.clone(), s.password.clone())
    };
    // Account name must match (case-sensitive) and the password must match.
    let user_ok = req.username == exp_user;
    if user_ok && password_matches(&exp_pw, &req.password) {
        state.auth.clear_failures(&source);
        let token = state.auth.issue();
        Json(json!({ "ok": true, "token": token })).into_response()
    } else {
        state.auth.record_failure(&source);
        (StatusCode::UNAUTHORIZED, "账号或密码错误").into_response()
    }
}

async fn logout(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(t) = bearer(&headers) {
        state.auth.revoke(&t);
    }
    Json(json!({ "ok": true })).into_response()
}

// ---------------------------------------------------------------------------
// Monitoring
// ---------------------------------------------------------------------------

async fn metrics(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let m = state.collector.lock().await.collect();
    Json(json!({ "ok": true, "data": m })).into_response()
}

async fn procs(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let data = crate::procs::web_snapshot(20).await;
    Json(json!({ "ok": true, "data": data })).into_response()
}

// ---------------------------------------------------------------------------
// Capability dispatch (docker / nginx / mysql) — same JSON protocol as relays
// ---------------------------------------------------------------------------

async fn dispatch(
    state: &Shared,
    headers: &header::HeaderMap,
    body: Value,
    f: impl std::future::Future<Output = anyhow::Result<Value>>,
) -> Response {
    if let Some(r) = require_auth(state, headers) {
        return r;
    }
    let _ = body; // body already parsed by caller
    match f.await {
        Ok(data) => Json(json!({ "ok": true, "data": data })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn docker_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::docker::web_dispatch(&body);
    dispatch(&state, &headers, body.clone(), fut).await
}

async fn nginx_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::nginx::web_dispatch(&body);
    dispatch(&state, &headers, body.clone(), fut).await
}

async fn mysql_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::mysql::web_dispatch(&body);
    dispatch(&state, &headers, body.clone(), fut).await
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

async fn get_settings(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let s = state.settings.lock().unwrap().clone();
    Json(json!({
        "ok": true,
        "data": { "enabled": s.enabled, "port": s.port, "username": s.username, "password": s.password }
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct SettingsReq {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn put_settings(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<SettingsReq>,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let mut needs_restart = false;
    let saved = {
        let mut s = state.settings.lock().unwrap();
        if let Some(p) = req.port {
            if !(1..=65535).contains(&p) {
                return (StatusCode::BAD_REQUEST, "端口需为 1-65535").into_response();
            }
            if p != s.port {
                s.port = p;
                needs_restart = true;
            }
        }
        if let Some(pw) = req.password {
            let pw = pw.trim();
            if pw.len() < 6 || pw.len() > 128 {
                return (StatusCode::BAD_REQUEST, "密码长度需为 6-128").into_response();
            }
            s.password = pw.to_string();
        }
        if let Some(un) = req.username {
            let un = un.trim();
            if un.len() < 2
                || un.len() > 32
                || !un
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return (StatusCode::BAD_REQUEST, "账号需为 2-32 位字母/数字/_/-").into_response();
            }
            s.username = un.to_string();
        }
        if let Some(en) = req.enabled {
            if en != s.enabled {
                s.enabled = en;
                needs_restart = true;
            }
        }
        s.clone()
    };
    if let Err(e) = settings::save(&saved) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("保存失败：{e}")).into_response();
    }
    Json(json!({ "ok": true, "needs_restart": needs_restart })).into_response()
}

// ---------------------------------------------------------------------------
// Terminal (PTY over WebSocket)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct WsAuth {
    #[serde(default)]
    token: String,
}

async fn terminal_ws(
    State(state): State<Shared>,
    Query(q): Query<WsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    // WebSocket upgrades can't carry an Authorization header from the browser,
    // so the token comes as a query param.
    if !state.auth.valid(&q.token) {
        return (StatusCode::UNAUTHORIZED, "未授权").into_response();
    }
    ws.on_upgrade(handle_terminal)
}

async fn handle_terminal(socket: WebSocket) {
    if let Err(e) = crate::terminal::run_web_pty(socket).await {
        tracing::debug!("web terminal ended: {e}");
    }
}

// ---------------------------------------------------------------------------
// WeChat bind/login (proxied to the backend via this agent's token)
// ---------------------------------------------------------------------------

/// Call a backend wx endpoint with the agent token in the JSON body. Returns
/// the parsed `data` object on `{ok:true}`.
async fn backend_call(state: &Shared, path: &str, extra: Value) -> anyhow::Result<Value> {
    let mut body = serde_json::Map::new();
    body.insert(
        "agent_token".into(),
        Value::String(state.agent_token.clone()),
    );
    if let Value::Object(m) = extra {
        for (k, v) in m {
            body.insert(k, v);
        }
    }
    let url = format!("{}{}", state.cfg.backend_url, path);
    let resp = state
        .http
        .post(&url)
        .json(&Value::Object(body))
        .send()
        .await?;
    let v: Value = resp.json().await?;
    if v.get("ok").and_then(|b| b.as_bool()) == Some(true) {
        Ok(v.get("data").cloned().unwrap_or(Value::Null))
    } else {
        anyhow::bail!(v
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("backend error")
            .to_string())
    }
}

fn err_msg(e: impl std::fmt::Display) -> Response {
    Json(json!({ "ok": false, "error": e.to_string() })).into_response()
}

/// POST /api/wx/login/start — PUBLIC (pre-auth login page). Calls the backend
/// to mint a login ticket, then renders the QR payload to an inline SVG so the
/// browser needs no QR JS library.
async fn wx_login_start(State(state): State<Shared>) -> Response {
    match backend_call(&state, "/agent/wx/login/start", json!({})).await {
        Ok(d) => {
            let payload = d.get("payload").and_then(|p| p.as_str()).unwrap_or("");
            let ticket = d.get("ticket").and_then(|t| t.as_str()).unwrap_or("");
            let svg = super::qr::svg(payload, 220).unwrap_or_default();
            Json(json!({ "ticket": ticket, "payload": payload, "svg": svg })).into_response()
        }
        Err(e) => err_msg(e),
    }
}

/// GET /api/wx/login/poll?ticket= — PUBLIC. On confirmation, mint a local
/// session token (this is the actual login).
async fn wx_login_poll(State(state): State<Shared>, Query(q): Query<PollQuery>) -> Response {
    match backend_call(
        &state,
        "/agent/wx/login/poll",
        json!({ "ticket": q.ticket }),
    )
    .await
    {
        Ok(d) => {
            let status = d
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("pending");
            if status == "confirmed" {
                let token = state.auth.issue();
                Json(json!({ "status": "confirmed", "token": token })).into_response()
            } else {
                Json(json!({ "status": status })).into_response()
            }
        }
        Err(e) => err_msg(e),
    }
}

#[derive(serde::Deserialize)]
struct PollQuery {
    #[serde(default)]
    ticket: String,
}

// ---------------------------------------------------------------------------
// Static UI
// ---------------------------------------------------------------------------

async fn index_page() -> Html<&'static str> {
    Html(include_str!("ui/index.html"))
}
