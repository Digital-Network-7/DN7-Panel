//! Branding API (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Branding (panel name / logo / accent / default theme) — public GET so the
// login page can render branded; authenticated POST to update.
// ---------------------------------------------------------------------------

pub(crate) async fn get_branding() -> Response {
    let b = branding::load();
    Json(json!({ "ok": true, "data": b })).into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct BrandingReq {
    #[serde(default)]
    panel_name: Option<String>,
    #[serde(default)]
    logo: Option<String>,
    #[serde(default)]
    accent: Option<String>,
    #[serde(default)]
    theme_default: Option<String>,
}

pub(crate) async fn put_branding(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<BrandingReq>,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let b = match branding::validate(req.panel_name, req.logo, req.accent, req.theme_default) {
        Ok(b) => b,
        Err(e) => return api_err(StatusCode::BAD_REQUEST, &e),
    };
    if let Err(e) = branding::save(&b) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(
        &actor_name(&state, &headers),
        "branding.update",
        "",
        true,
        "",
    );
    Json(json!({ "ok": true, "data": b })).into_response()
}
