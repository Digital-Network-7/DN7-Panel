//! Static UI asset serving (index page + embedded /ui/* assets) (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Static UI
// ---------------------------------------------------------------------------

pub(crate) async fn index_page() -> Html<String> {
    let b = branding::load();
    Html(branding::render_index(
        include_str!("../../ui/index.html"),
        &b,
    ))
}

/// Serve an embedded UI asset (css/js) under `/ui/...`. These are non-secret
/// front-end modules; no auth required (same posture as the index page).
pub(crate) async fn ui_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    match UI_ASSETS.get_file(&path) {
        Some(f) => (
            [(header::CONTENT_TYPE, asset_content_type(&path))],
            f.contents().to_vec(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub(crate) fn asset_content_type(path: &str) -> &'static str {
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
