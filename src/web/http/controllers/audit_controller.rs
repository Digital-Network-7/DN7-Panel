//! Audit log API (Owner only) (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Audit log (Owner only)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct LogsQuery {
    /// Entries to skip (post-filter) — the page offset.
    #[serde(default)]
    offset: Option<usize>,
    /// Max entries to return (page size; export requests a large window).
    #[serde(default)]
    limit: Option<usize>,
    /// "ok" | "fail" — anything else (or absent) means both.
    #[serde(default)]
    result: Option<String>,
    /// Action group filter (e.g. "auth", "docker").
    #[serde(default)]
    module: Option<String>,
    /// Inclusive unix-second lower bound (client sends the day start in the
    /// configured display timezone).
    #[serde(default)]
    from_ts: Option<i64>,
    /// Inclusive unix-second upper bound (client sends the day end).
    #[serde(default)]
    to_ts: Option<i64>,
    /// Free-text substring over the raw fields.
    #[serde(default)]
    q: Option<String>,
}

/// GET /api/logs — a filtered, paginated page of the audit log, newest first.
/// Super-admin (Owner) only. Returns `{ entries, total, modules }` so the UI
/// can drive real (server-side) pagination.
pub(crate) async fn logs_list(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let filter = audit::Query {
        ok: match q.result.as_deref() {
            Some("ok") => Some(true),
            Some("fail") => Some(false),
            _ => None,
        },
        module: q.module.filter(|s| !s.is_empty()),
        from_ts: q.from_ts,
        to_ts: q.to_ts,
        text: q.q.filter(|s| !s.trim().is_empty()),
    };
    let page: audit::Page = audit::query(&filter, q.offset.unwrap_or(0), q.limit.unwrap_or(50));
    Json(json!({ "ok": true, "data": {
        "entries": page.entries,
        "total": page.total,
        "modules": page.modules,
    }}))
    .into_response()
}
