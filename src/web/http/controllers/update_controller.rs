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
    let acct = match require_super(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let mut st = crate::platform::update::UpdateState::load();
    // Normalise the requested source (if any) up-front so we can both validate
    // it and detect a real change against the stored value.
    let new_pref = match req.source_pref {
        Some(p) => {
            // Legacy "auto" maps to the default mirror; otherwise github/dn7 only.
            let p = if p == "auto" { "dn7".to_string() } else { p };
            if !matches!(p.as_str(), "github" | "dn7") {
                return api_err(StatusCode::BAD_REQUEST, "update.source_invalid");
            }
            Some(p)
        }
        None => None,
    };
    // Enabling auto-update or switching the source lets a session steer which
    // binary the host will run (auto-update applies with no further step-up) —
    // so require a fresh step-up for those, exactly like `update_apply`. Turning
    // auto OFF or a no-op re-save stays session-only.
    let enables_auto = req.auto == Some(true);
    let changes_source = new_pref.as_ref().is_some_and(|p| *p != st.source_pref);
    if enables_auto || changes_source {
        if let Some(r) = require_stepup(&state, &headers, &acct.username) {
            return r;
        }
    }
    if let Some(a) = req.auto {
        st.auto = a;
    }
    if let Some(p) = new_pref {
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
    // only (the signature + anti-rollback gates still apply on top), and it
    // additionally requires a fresh step-up re-auth so a stolen session can't
    // push a new binary on its own.
    let acct = match require_super(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(r) = require_stepup(&state, &headers, &acct.username) {
        return r;
    }
    // Claim the single in-progress slot HERE, atomically, before spawning. Two
    // concurrent requests would both pass a plain `in_progress()` check and both
    // spawn + audit success even though the engine admits only one — so the CAS
    // (via the RAII guard) is the gate. The loser gets 409 with no success audit;
    // the winner hands the guard to the spawned runner, which releases it on
    // every failure path (its Drop) or lets the process exit on success.
    let guard = match crate::platform::update::try_begin_guard() {
        Some(g) => g,
        None => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "ok": true,
                    "data": { "started": false, "reason": "already in progress" }
                })),
            )
                .into_response();
        }
    };
    let cfg = state.cfg.clone();
    tokio::spawn(async move {
        crate::platform::update::run_self_update_owned(&cfg, guard).await;
    });
    // Durable: the self-update replaces the root binary and the process may
    // exec/exit right after, so the record must be on disk before we return.
    audit::record_durable(&actor_name(&state, &headers), "update.apply", "", true, "").await;
    Json(json!({ "ok": true, "data": { "started": true } })).into_response()
}
