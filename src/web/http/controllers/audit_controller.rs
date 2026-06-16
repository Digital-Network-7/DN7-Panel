//! Audit log API (Owner only) (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Audit log (Owner only)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct LogsQuery {
    #[serde(default)]
    limit: Option<usize>,
}

/// GET /api/logs — the audit log, newest first. Super-admin (Owner) only.
pub(crate) async fn logs_list(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let entries = audit::read(q.limit.unwrap_or(500));
    Json(json!({ "ok": true, "data": { "entries": entries } })).into_response()
}

/// POST /api/logs/clear — erase the audit log. Owner only.
pub(crate) async fn logs_clear(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    let actor = match require_super(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(e) = audit::clear() {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(&actor.username, "logs.clear", "", true, "");
    Json(json!({ "ok": true })).into_response()
}
