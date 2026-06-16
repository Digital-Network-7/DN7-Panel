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

pub(crate) async fn procs(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let data = crate::infra::support::procs::web_snapshot(20).await;
    Json(json!({ "ok": true, "data": data })).into_response()
}

/// Basic panel identity (version + hostname) for the console footer/topbar.
pub(crate) async fn panel_info(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
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
