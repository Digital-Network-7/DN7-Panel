//! Monitoring endpoints: host metrics, process snapshot, panel identity.
use super::super::*;

pub(crate) async fn metrics(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    // `collect()` does blocking syscalls (stat of every mount via disks.refresh,
    // and a sync UdpSocket bind/connect for the local-IP probe). A stalled mount
    // (NFS, dead device) would otherwise block this tokio worker for all other
    // requests on it. Run the blocking work off the async poll with
    // `block_in_place` (multi-thread runtime), keeping the &mut borrow valid.
    let mut guard = state.collector.lock().await;
    let m = tokio::task::block_in_place(|| guard.collect());
    drop(guard);
    Json(json!({ "ok": true, "data": m })).into_response()
}

pub(crate) async fn metrics_history(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<HistoryQuery>,
) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let data = crate::infra::metrics::history_series(&q.range, &q.metric);
    Json(json!({ "ok": true, "data": data })).into_response()
}

/// Query for the dashboard history view: which metric + which time window.
#[derive(serde::Deserialize)]
pub(crate) struct HistoryQuery {
    #[serde(default)]
    metric: String,
    #[serde(default)]
    range: String,
}

/// POST /api/restart — restart the panel process so settings (e.g. a changed
/// port) take effect. The panel simply exits; the supervisor respawns it and
/// the fresh process re-reads `web.json`. Super-admin only (host-level blast
/// radius). The actual process exit lives in `platform` (the web layer must not
/// touch `std::process`).
pub(crate) async fn restart_panel(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    audit::record(
        &actor_name(&state, &headers),
        "settings.restart",
        "",
        true,
        "",
    );
    crate::platform::panel::request_restart();
    Json(json!({ "ok": true, "data": { "restarting": true } })).into_response()
}

/// Basic panel identity (version + hostname) for the console footer/topbar.
pub(crate) async fn panel_info(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
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
