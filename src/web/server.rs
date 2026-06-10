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

use super::auth::{password_matches, proof_matches, AuthState};
use super::branding;
use super::settings::{self, WebSettings};
use crate::config::PanelConfig;
use crate::metrics::Collector;
use include_dir::{include_dir, Dir};

/// Web-console UI assets (css + js modules), embedded at compile time so the
/// binary stays self-contained. `index.html` is served separately (templated
/// with branding); everything else is served verbatim from here under `/ui/`.
static UI_ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/web/ui");

/// Shared web-console state.
pub struct WebState {
    auth: AuthState,
    settings: std::sync::Mutex<WebSettings>,
    /// Reused metrics collector (CPU% needs a persistent handle across reads).
    collector: Mutex<Collector>,
}

type Shared = Arc<WebState>;

/// Start the web console in a background task (no-op when disabled). Returns
/// immediately; the server runs for the process lifetime.
pub fn spawn(cfg: PanelConfig) {
    let s = settings::load_or_init(cfg.web_enabled, cfg.web_port);
    if !s.enabled {
        tracing::info!("web console disabled; not starting");
        return;
    }
    let port = s.port;
    let state: Shared = Arc::new(WebState {
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
        .route("/ui/*path", get(ui_asset))
        .route("/api/login/challenge", get(login_challenge))
        .route("/api/login", post(login))
        // Authenticated API.
        .route("/api/logout", post(logout))
        .route("/api/info", get(agent_info))
        .route("/api/metrics", get(metrics))
        .route("/api/procs", get(procs))
        .route("/api/settings", get(get_settings).post(put_settings))
        .route("/api/branding", get(get_branding).post(put_branding))
        .route("/api/docker", post(docker_op))
        .route("/api/nginx", post(nginx_op))
        .route("/api/mysql", post(mysql_op))
        .route("/api/terminal", get(terminal_ws))
        .route("/api/container/terminal", get(container_terminal_ws))
        .route("/api/files/list", post(files_list))
        .route("/api/files/mkdir", post(files_mkdir))
        .route("/api/files/delete", post(files_delete))
        .route("/api/files/download", get(files_download))
        .route("/api/files/upload", post(files_upload))
        .route("/api/nginx/static-upload", post(nginx_static_upload))
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
    /// Challenge-response: the nonce from `/api/login/challenge` and the proof
    /// `sha256_hex(nonce + ":" + password)`. The cleartext password is never
    /// sent (keeps it off the plaintext-HTTP wire). `password` is accepted as a
    /// legacy fallback only when no nonce/proof is supplied.
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    proof: String,
    #[serde(default)]
    password: String,
}

/// GET /api/login/challenge — PUBLIC. Mint a one-time login nonce for the
/// challenge-response flow.
async fn login_challenge(State(state): State<Shared>) -> Response {
    let nonce = state.auth.issue_challenge();
    Json(json!({ "nonce": nonce })).into_response()
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
        (s.username.clone(), s.password_plain())
    };
    // Account name must match (case-sensitive), then verify the password —
    // preferring the challenge-response proof, falling back to a direct compare
    // only if the client didn't use the challenge flow.
    let user_ok = req.username == exp_user;
    let pw_ok = if !req.proof.is_empty() {
        // The nonce must be valid + single-use, then the proof must match.
        state.auth.consume_challenge(&req.nonce) && proof_matches(&req.nonce, &exp_pw, &req.proof)
    } else {
        password_matches(&exp_pw, &req.password)
    };
    if user_ok && pw_ok {
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

/// Basic agent identity (version + hostname) for the console footer/topbar.
async fn agent_info(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let hostname = sysinfo::System::host_name().unwrap_or_default();
    Json(json!({
        "ok": true,
        "data": {
            "version": env!("CARGO_PKG_VERSION"),
            "hostname": hostname,
        }
    }))
    .into_response()
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
        "data": { "enabled": s.enabled, "port": s.port, "username": s.username, "password": s.password_plain() }
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
            // Only treat it as a change when it differs from the current
            // plaintext (the settings form pre-fills the current password). A
            // user-chosen password is stored ENCRYPTED; the auto-generated
            // default stays plaintext until the user replaces it.
            if pw != s.password_plain() {
                s.set_user_password(pw);
            }
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

/// WS query for a container terminal: token + container ref.
#[derive(serde::Deserialize)]
struct ContainerWsAuth {
    #[serde(default)]
    token: String,
    #[serde(default)]
    container: String,
}

async fn container_terminal_ws(
    State(state): State<Shared>,
    Query(q): Query<ContainerWsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    if !state.auth.valid(&q.token) {
        return (StatusCode::UNAUTHORIZED, "未授权").into_response();
    }
    let container = q.container.clone();
    if container.is_empty() {
        return (StatusCode::BAD_REQUEST, "缺少容器").into_response();
    }
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = crate::terminal::run_web_container_exec(socket, &container).await {
            tracing::debug!("web container terminal ended: {e}");
        }
    })
}

// ---------------------------------------------------------------------------
// File transfer (host + container) — plain HTTP request/response.
// ---------------------------------------------------------------------------

/// Body for list/mkdir/delete: a path, optionally scoped to a container.
#[derive(serde::Deserialize)]
struct FileOpReq {
    #[serde(default)]
    path: String,
    /// When set, the operation targets this container's filesystem.
    #[serde(default)]
    container: Option<String>,
}

fn ctn_ref(req: &FileOpReq) -> Option<&str> {
    req.container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

async fn files_list(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let res = match ctn_ref(&req) {
        Some(c) => crate::file::web_ctn_list(c, &req.path).await,
        None => crate::file::web_host_list(&req.path).await,
    };
    match res {
        Ok(data) => Json(json!({ "ok": true, "data": data })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn files_mkdir(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let res = match ctn_ref(&req) {
        Some(c) => crate::file::web_ctn_mkdir(c, &req.path).await,
        None => crate::file::web_host_mkdir(&req.path).await,
    };
    match res {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn files_delete(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let res = match ctn_ref(&req) {
        Some(c) => crate::file::web_ctn_delete(c, &req.path).await,
        None => crate::file::web_host_delete(&req.path).await,
    };
    match res {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

/// Download query: token (browser can't set Authorization on a direct link),
/// path, optional container.
#[derive(serde::Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    token: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    container: Option<String>,
}

async fn files_download(State(state): State<Shared>, Query(q): Query<DownloadQuery>) -> Response {
    if !state.auth.valid(&q.token) {
        return (StatusCode::UNAUTHORIZED, "未授权").into_response();
    }
    let ctn = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let res = match ctn {
        Some(c) => crate::file::web_ctn_read(c, &q.path).await,
        None => crate::file::web_host_read(&q.path).await,
    };
    match res {
        Ok((name, bytes)) => {
            let disp = format!("attachment; filename=\"{}\"", sanitize_filename(&name));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                bytes,
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Strip characters that could break the Content-Disposition header / path.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '"' || c == '\\' || c == '\n' || c == '\r' {
                '_'
            } else {
                c
            }
        })
        .take(255)
        .collect()
}

/// Upload: multipart-free — the path/container come as query params and the raw
/// file bytes are the request body (kept simple; the UI sends one file at a
/// time). Caps the body at 512 MiB to bound memory.
#[derive(serde::Deserialize)]
struct UploadQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    container: Option<String>,
}

async fn files_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<UploadQuery>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    if body.len() as u64 > 512 * 1024 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "文件过大（上限 512MiB）").into_response();
    }
    let ctn = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let res = match ctn {
        Some(c) => crate::file::web_ctn_write(c, &q.path, &body).await,
        None => crate::file::web_host_write(&q.path, &body).await,
    };
    match res {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

/// Static-site upload: extract an uploaded ZIP, or write a single file, into a
/// managed static webroot. Query params:
///   root  — the static site's webroot subdirectory name (validated agent-side)
///   mode  — "zip" (body is a .zip to extract) | "file" (body is one file)
///   rel   — for mode=file: the file's relative path within the webroot
///   clear — "1" to wipe the webroot first (fresh upload)
/// Body is the raw bytes (capped at 512 MiB), mirroring files_upload.
#[derive(serde::Deserialize)]
struct StaticUploadQuery {
    root: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    rel: Option<String>,
    #[serde(default)]
    clear: Option<String>,
}

async fn nginx_static_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<StaticUploadQuery>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    if body.len() as u64 > 512 * 1024 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "文件过大（上限 512MiB）").into_response();
    }
    let mode = q.mode.as_deref().unwrap_or("zip");
    let clear = q.clear.as_deref() == Some("1");
    let res = crate::nginx::web_static_upload(&q.root, mode, q.rel.as_deref(), clear, &body).await;
    match res {
        Ok(n) => Json(json!({ "ok": true, "files": n })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Static UI
// ---------------------------------------------------------------------------

async fn index_page() -> Html<String> {
    let b = branding::load();
    Html(branding::render_index(include_str!("ui/index.html"), &b))
}

/// Serve an embedded UI asset (css/js) under `/ui/...`. These are non-secret
/// front-end modules; no auth required (same posture as the index page).
async fn ui_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    match UI_ASSETS.get_file(&path) {
        Some(f) => (
            [(header::CONTENT_TYPE, asset_content_type(&path))],
            f.contents().to_vec(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn asset_content_type(path: &str) -> &'static str {
    if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

// ---------------------------------------------------------------------------
// Branding (panel name / logo / accent / default theme) — public GET so the
// login page can render branded; authenticated POST to update.
// ---------------------------------------------------------------------------

async fn get_branding() -> Response {
    let b = branding::load();
    Json(json!({ "ok": true, "data": b })).into_response()
}

#[derive(serde::Deserialize)]
struct BrandingReq {
    #[serde(default)]
    panel_name: Option<String>,
    #[serde(default)]
    logo: Option<String>,
    #[serde(default)]
    accent: Option<String>,
    #[serde(default)]
    theme_default: Option<String>,
}

async fn put_branding(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<BrandingReq>,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let b = match branding::validate(req.panel_name, req.logo, req.accent, req.theme_default) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    if let Err(e) = branding::save(&b) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("保存失败：{e}")).into_response();
    }
    Json(json!({ "ok": true, "data": b })).into_response()
}
