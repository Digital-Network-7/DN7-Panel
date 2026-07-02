//! Static UI asset serving (index page + embedded /ui/* assets) (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Static UI
// ---------------------------------------------------------------------------

pub(crate) async fn index_page() -> Response {
    let b = branding::load();
    let (lang, tz) = crate::web::settings::load()
        .map(|s| (s.language, s.timezone))
        .unwrap_or_default();
    // The rewritten shell embeds live branding/language/timezone — never cache
    // it (the embedded /ui assets below carry the revalidation story instead).
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(branding::render_index(
            include_str!("../../ui/index.html"),
            &b,
            &lang,
            &tz,
        )),
    )
        .into_response()
}

/// Serve an embedded UI asset (css/js) under `/ui/...`. These are non-secret
/// front-end modules; no auth required (same posture as the index page).
/// Assets are compile-time static, so each gets a strong content-hash ETag +
/// `Cache-Control: no-cache`: clients revalidate every visit but re-download
/// only when a self-update actually changed the file (304 otherwise).
pub(crate) async fn ui_asset(
    headers: header::HeaderMap,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response {
    match UI_ASSETS.get_file(&path) {
        Some(f) => {
            let etag = asset_etag(&path, f.contents());
            if if_none_match(&headers, &etag) {
                return (
                    StatusCode::NOT_MODIFIED,
                    [
                        (header::ETAG, etag),
                        (header::CACHE_CONTROL, "no-cache".to_string()),
                    ],
                )
                    .into_response();
            }
            (
                [
                    (header::CONTENT_TYPE, asset_content_type(&path).to_string()),
                    (header::ETAG, etag),
                    (header::CACHE_CONTROL, "no-cache".to_string()),
                ],
                f.contents().to_vec(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Strong ETag for an embedded asset: FNV-1a 64 over the (compile-time static)
/// contents plus the length. Cheap, deterministic, and changes with the binary.
///
/// `UI_ASSETS` is compile-time static, so a given `path` always resolves to the
/// same bytes for the life of the process — memoize path → ETag so revalidation
/// (and every hit) skips re-hashing the whole body. The cache is bounded by the
/// finite set of embedded assets.
fn asset_etag(path: &str, bytes: &[u8]) -> String {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    if let Some(etag) = map.get(path) {
        return etag.clone();
    }
    let etag = hash_etag(bytes);
    map.insert(path.to_string(), etag.clone());
    etag
}

/// The raw content-hash ETag (FNV-1a 64 over the bytes + length). Separated from
/// the memoizing wrapper so it stays trivially unit-testable.
fn hash_etag(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("\"{:016x}-{:x}\"", h, bytes.len())
}

/// Whether the request's `If-None-Match` matches `etag`. A `W/` prefix on the
/// client's copy still matches (revalidation only cares about content identity).
fn if_none_match(headers: &header::HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .map(|t| t.trim().trim_start_matches("W/"))
                .any(|t| t == etag || t == "*")
        })
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

#[cfg(test)]
mod tests {
    use super::{asset_etag, hash_etag, if_none_match};
    use axum::http::header;

    // The revalidation contract: the ETag is strong (quoted, content-derived)
    // and If-None-Match matches it through list syntax, weak prefixes, and `*`
    // — while different contents never collide on the trivial cases.
    #[test]
    fn etag_matches_through_if_none_match_forms() {
        let tag = hash_etag(b"body{color:red}");
        assert!(
            tag.starts_with('"') && tag.ends_with('"'),
            "strong + quoted"
        );
        assert_ne!(tag, hash_etag(b"body{color:blue}"));

        let mut h = header::HeaderMap::new();
        h.insert(header::IF_NONE_MATCH, tag.parse().unwrap());
        assert!(if_none_match(&h, &tag));

        // List form + weak prefix still revalidate; a stale tag does not.
        let list = format!("\"stale\", W/{tag}");
        h.insert(header::IF_NONE_MATCH, list.parse().unwrap());
        assert!(if_none_match(&h, &tag));
        h.insert(header::IF_NONE_MATCH, "\"stale\"".parse().unwrap());
        assert!(!if_none_match(&h, &tag));
        h.insert(header::IF_NONE_MATCH, "*".parse().unwrap());
        assert!(if_none_match(&h, &tag));
        assert!(!if_none_match(&header::HeaderMap::new(), &tag));
    }

    // The memoizing wrapper returns the raw content hash and is stable across
    // repeat lookups (the second call is served from the path→ETag cache).
    #[test]
    fn asset_etag_is_memoized_and_matches_hash() {
        let body = b"console.log(1)";
        let first = asset_etag("js/x.js", body);
        assert_eq!(first, hash_etag(body));
        assert_eq!(first, asset_etag("js/x.js", body));
    }
}
