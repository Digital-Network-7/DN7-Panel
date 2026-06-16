//! Self-update API (GitHub + dn7.cn) (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Self-update (GitHub + dn7.cn)
// ---------------------------------------------------------------------------

/// GET /api/update/status — live phase/progress + current version (polled by
/// the UI during a download). Auth required.
pub(crate) async fn update_status(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    Json(json!({
        "ok": true,
        "data": {
            "phase": crate::platform::update::phase_str(),
            "progress": crate::platform::update::progress(),
            "done_bytes": crate::platform::update::done_bytes(),
            "total_bytes": crate::platform::update::total_bytes(),
            "in_progress": crate::platform::update::in_progress(),
            "current": env!("CARGO_PKG_VERSION"),
        }
    }))
    .into_response()
}

pub(crate) async fn update_config_get(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let st = crate::platform::update::UpdateState::load();
    Json(json!({ "ok": true, "data": st })).into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct UpdateConfigReq {
    #[serde(default)]
    auto: Option<bool>,
    /// "github" (preview channel) | "dn7" (default mirror)
    #[serde(default)]
    source_pref: Option<String>,
}

pub(crate) async fn update_config_put(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<UpdateConfigReq>,
) -> Response {
    // Changing the update channel / auto-update toggle steers what binary the
    // host will run — super-admin only (matches the apply blast radius).
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let mut st = crate::platform::update::UpdateState::load();
    if let Some(a) = req.auto {
        st.auto = a;
    }
    if let Some(p) = req.source_pref {
        // Legacy "auto" maps to the default mirror; otherwise github/dn7 only.
        let p = if p == "auto" { "dn7".to_string() } else { p };
        if !matches!(p.as_str(), "github" | "dn7") {
            return api_err(StatusCode::BAD_REQUEST, "update.source_invalid");
        }
        st.source_pref = p;
    }
    if let Err(e) = st.save() {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    Json(json!({ "ok": true, "data": st })).into_response()
}

/// POST /api/update/check — probe both sources + report whether a newer build
/// is available. Auth required.
pub(crate) async fn update_check(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let res = crate::platform::update::check(&state.cfg).await;
    Json(json!({ "ok": true, "data": res })).into_response()
}

/// GET /api/update/changelog — release notes for every version newer than the
/// running one (newest first), from whichever source is reachable. Auth req.
pub(crate) async fn update_changelog(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let res = crate::platform::update::changelog(&state.cfg).await;
    Json(json!({ "ok": true, "data": res })).into_response()
}

/// POST /api/update/apply — start a self-update in the background (download →
/// verify → atomic swap → exit for restart). Returns immediately; the UI polls
/// /api/update/status. Auth required.
pub(crate) async fn update_apply(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    // Replacing the running root binary is the highest-blast-radius op — super
    // only (the signature + anti-rollback gates still apply on top).
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    if crate::platform::update::in_progress() {
        return Json(
            json!({ "ok": true, "data": { "started": false, "reason": "already in progress" } }),
        )
        .into_response();
    }
    let cfg = state.cfg.clone();
    tokio::spawn(async move {
        crate::platform::update::run_self_update(&cfg).await;
    });
    audit::record(&actor_name(&state, &headers), "update.apply", "", true, "");
    Json(json!({ "ok": true, "data": { "started": true } })).into_response()
}
