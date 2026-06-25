//! [M3] Static file serving + asset cache headers + gzip.
//!
//! This is the in-process replacement for nginx's `root` + `try_files` +
//! `gzip` + `expires` for upload-mode static sites. The route table hands us a
//! [`StaticRoot`] (an already-validated absolute document root) and the
//! request; we map the URI path onto the root *safely*, pick the file (with
//! directory-index fallback), and stream it back with the right caching and
//! (optionally) gzip headers.
//!
//! Safety is the whole game here: a static root is operator-controlled but the
//! request path is attacker-controlled, so we percent-decode, reject any `..`
//! or absolute/rooted segment, join onto the root, and then re-verify the
//! resolved path is still under the root before opening anything.

use std::path::{Component, Path, PathBuf};

use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::{header, HeaderValue, StatusCode};
use hyper::body::Incoming;
use std::io::Write as _;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::io::ReaderStream;

use super::config::{StaticRoot, Tuning};
use super::response::{self, Resp};

/// Asset extensions that get a long `Cache-Control`/`Expires` when the site has
/// `cache_assets` on (mirrors the nginx `location ~* \.(...)$ { expires 7d; }`
/// asset block confgen emits).
const ASSET_EXTS: &[&str] = &[
    "css", "js", "jpg", "jpeg", "png", "gif", "ico", "svg", "webp", "avif", "woff", "woff2", "ttf",
    "otf", "eot", "mp4", "webm", "mp3", "map",
];

/// One week, the asset cache lifetime (`expires 7d`).
const ASSET_MAX_AGE: u64 = 604_800;

/// Upper bound on a file we'll buffer-and-gzip in memory. gzip needs the whole
/// input, so a compressible file is read fully before compressing; without a cap
/// a flood of requests for a large compressible file would exhaust RAM. Above
/// the cap we stream the file uncompressed (still correct, just not compressed).
const GZIP_MAX_BUFFER: u64 = 1024 * 1024; // 1 MiB

/// Serve `req` from the static `root`. `tuning` carries gzip settings.
pub(crate) async fn handle(req: &hyper::Request<Incoming>, root: &StaticRoot, tuning: &Tuning) -> Resp {
    // Only GET/HEAD can yield a body; everything else is a method error so we
    // never accidentally serve a file for a PUT/DELETE/etc.
    let method = req.method();
    let head_only = method == http::Method::HEAD;
    if !head_only && method != http::Method::GET {
        let mut r = response::status(StatusCode::METHOD_NOT_ALLOWED);
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return r;
    }

    // Resolve the on-disk path safely; a traversal attempt is a hard 403.
    let path = req.uri().path();
    let resolved = match resolve_path(&root.root, path) {
        Some(p) => p,
        // Traversal attempt or a hidden-file request: 404, never revealing
        // whether the target exists or that a guard rejected it.
        None => return response::status(StatusCode::NOT_FOUND),
    };

    // try_files: a plain file is served directly; a directory falls back to its
    // index document; anything else is a 404.
    let file_path = match pick_file(&resolved).await {
        Some(p) => p,
        None => return response::status(StatusCode::NOT_FOUND),
    };

    // Symlink containment: canonicalize the resolved file and the document root,
    // and require the real path to stay under the real root. A symlink inside the
    // root that points outside it is refused (404) — we do NOT follow symlinks
    // out of the document root.
    match (
        tokio::fs::canonicalize(&file_path).await,
        tokio::fs::canonicalize(&root.root).await,
    ) {
        (Ok(real), Ok(root_real)) if real.starts_with(&root_real) => {}
        _ => return response::status(StatusCode::NOT_FOUND),
    }

    serve_file(req, &file_path, root, tuning, head_only).await
}

/// Percent-decode the request path, reject traversal, and join it onto `root`,
/// re-verifying the result stays under `root`. Returns `None` for any path that
/// would escape the root (the caller turns that into a 403).
fn resolve_path(root: &Path, req_path: &str) -> Option<PathBuf> {
    // Strip the leading `/` and percent-decode each segment. We decode before
    // splitting so an encoded slash (`%2f`) becomes a real separator and is
    // subjected to the same `..` rejection as a literal one.
    let decoded = percent_decode(req_path.trim_start_matches('/'))?;

    let mut out = root.to_path_buf();
    for raw in decoded.split('/') {
        if raw.is_empty() || raw == "." {
            // `//` and `/./` are no-ops, like a filesystem.
            continue;
        }
        if raw == ".." {
            // Refuse the whole request rather than clamping at the root: a `..`
            // in a static path is never legitimate and clamping silently could
            // surprise. (nginx similarly 400s on `..` in normalised URIs.)
            return None;
        }
        // Never serve hidden files/dirs (.env, .git/config, .htpasswd, …): reject
        // any segment beginning with a dot. ("." and ".." are handled above.)
        if raw.starts_with('.') {
            return None;
        }
        // A decoded NUL or embedded separator-bearing component is bogus.
        if raw.contains('\0') {
            return None;
        }
        out.push(raw);
    }

    // Final guard: re-verify the assembled path is still lexically under root.
    // We never pushed a `..` or rooted segment, but confirm the prefix anyway as
    // a belt-and-braces check, and ensure no `ParentDir` slipped through (a
    // decoded segment is pushed verbatim, so a literal `..` would be caught
    // above, but a path that *equals* root with no extra component is fine).
    if !out.starts_with(root) {
        return None;
    }
    if out.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    Some(out)
}

/// Minimal percent-decoder (`%XX`). Returns `None` on a malformed escape or
/// non-UTF-8 result. We avoid pulling in the `percent-encoding` crate (not in
/// the dependency set) for this one use.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                // Need exactly two hex digits after the percent.
                let hi = bytes.get(i + 1).copied().and_then(hex_val)?;
                let lo = bytes.get(i + 2).copied().and_then(hex_val)?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// A single hex digit's value, or `None` if it isn't one.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `try_files` resolution: if `resolved` is a regular file, serve it; if it's a
/// directory, try `index.html` then `index.htm`; otherwise `None` (404).
async fn pick_file(resolved: &Path) -> Option<PathBuf> {
    let meta = tokio::fs::metadata(resolved).await.ok()?;
    if meta.is_file() {
        return Some(resolved.to_path_buf());
    }
    if meta.is_dir() {
        for index in ["index.html", "index.htm"] {
            let candidate = resolved.join(index);
            if let Ok(m) = tokio::fs::metadata(&candidate).await {
                if m.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Open `file_path` and build the 200 (or 304) response with the right MIME,
/// length, last-modified, caching and gzip headers.
async fn serve_file(
    req: &hyper::Request<Incoming>,
    file_path: &Path,
    root: &StaticRoot,
    tuning: &Tuning,
    head_only: bool,
) -> Resp {
    let meta = match tokio::fs::metadata(file_path).await {
        Ok(m) => m,
        Err(_) => return response::status(StatusCode::NOT_FOUND),
    };
    let len = meta.len();

    // Last-Modified + a cheap ETag from (mtime, size). Both feed conditional
    // requests so a warm client can be answered with a bodyless 304.
    let mtime = meta.modified().ok();
    let last_modified = mtime.and_then(httpdate_from);
    let etag = mtime.and_then(|m| etag_from(m, len));

    // Conditional GET: a matching `If-None-Match` (preferred) or a
    // `If-Modified-Since` that is >= our mtime means the client is up to date.
    if not_modified(req.headers(), etag.as_deref(), mtime) {
        let mut r = response::status(StatusCode::NOT_MODIFIED);
        attach_validators(r.headers_mut(), last_modified.as_deref(), etag.as_deref());
        attach_cache(r.headers_mut(), file_path, root);
        return r;
    }

    let mime = mime_guess::from_path(file_path).first_or_octet_stream();
    let content_type = mime.essence_str().to_string();

    // A byte-range request (identity only — gzip and Range are mutually
    // exclusive, like nginx). Parse it up front so it gates gzip too.
    let range = parse_range(req.headers(), len);
    if matches!(range, RangeReq::Unsatisfiable) {
        let mut r = response::status(StatusCode::RANGE_NOT_SATISFIABLE);
        if let Ok(v) = HeaderValue::from_str(&format!("bytes */{len}")) {
            r.headers_mut().insert(header::CONTENT_RANGE, v);
        }
        return r;
    }
    let ranged = matches!(range, RangeReq::Satisfiable(_, _));

    // Decide gzip eligibility: globally enabled, within the in-memory buffer
    // cap, big enough, a compressible type, the client advertised gzip, and NOT a
    // range request. nginx applies the same gate.
    let wants_gzip = tuning.gzip
        && !ranged
        && len >= tuning.gzip_min_length as u64
        && len <= GZIP_MAX_BUFFER
        && is_compressible(&content_type)
        && accepts_gzip(req.headers());

    let mut builder = http::Response::builder().status(StatusCode::OK);
    {
        let headers = builder.headers_mut().expect("fresh builder has headers");
        if let Ok(ct) = HeaderValue::from_str(&full_content_type(&content_type)) {
            headers.insert(header::CONTENT_TYPE, ct);
        }
        attach_validators(headers, last_modified.as_deref(), etag.as_deref());
        attach_cache(headers, file_path, root);
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }

    // Satisfiable byte range: 206 with the seeked, length-limited slice.
    if let RangeReq::Satisfiable(start, end) = range {
        return serve_range(builder, file_path, start, end, len, head_only).await;
    }

    if wants_gzip && head_only {
        // HEAD on a gzip-eligible file: advertise that a GET would be gzipped,
        // but don't read+compress the whole file just to discard the body. The
        // compressed length is unknown without compressing, so omit it (a HEAD
        // Content-Length is optional and a wrong one would be worse).
        let headers = builder.headers_mut().expect("builder has headers");
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        return builder.body(response::empty()).expect("response builds");
    }
    if wants_gzip {
        // The compressible types are text/json/svg/js — small enough to buffer,
        // and gzip needs the whole input anyway. Read it, compress, send a
        // fully-buffered body with the compressed length. (HEAD handled above.)
        match tokio::fs::read(file_path).await {
            Ok(raw) => match gzip(&raw, tuning.gzip_comp_level) {
                Some(compressed) => {
                    let clen = compressed.len();
                    let headers = builder.headers_mut().expect("builder has headers");
                    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                    headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(clen));
                    return builder
                        .body(response::full(Bytes::from(compressed)))
                        .expect("response builds");
                }
                None => { /* fall through to the uncompressed path on encoder error */ }
            },
            Err(_) => return response::status(StatusCode::NOT_FOUND),
        }
    }

    // Uncompressed: advertise the on-disk length and stream the file so a large
    // download never buffers the whole body in memory.
    {
        let headers = builder.headers_mut().expect("builder has headers");
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    }

    if head_only {
        return builder.body(response::empty()).expect("response builds");
    }

    match tokio::fs::File::open(file_path).await {
        Ok(file) => {
            // ReaderStream yields `Bytes` chunks; boxed() maps its io error into
            // the shared ResBody error type.
            // ReaderStream yields `Result<Bytes, io::Error>`; wrap each chunk as
            // a data frame so it satisfies `http_body::Body`. `futures` (0.3) is
            // already a dependency and re-exports the stream combinators.
            use futures::TryStreamExt as _;
            let stream = ReaderStream::new(file).map_ok(hyper::body::Frame::data);
            let body = response::boxed(http_body_util::StreamBody::new(stream));
            builder.body(body).expect("response builds")
        }
        Err(_) => response::status(StatusCode::NOT_FOUND),
    }
}

/// The parsed `Range` request state for a file of `len` bytes.
enum RangeReq {
    /// No (usable) Range header — serve the whole file.
    None,
    /// A single satisfiable byte range `[start, end]` (inclusive).
    Satisfiable(u64, u64),
    /// A Range header that can't be satisfied → 416.
    Unsatisfiable,
}

/// Parse a single-range `Range: bytes=...` header against a file of `len` bytes.
/// Supports `bytes=start-end`, `bytes=start-` (to EOF), and `bytes=-suffix`
/// (last N bytes). A multi-range or malformed header degrades to a full 200
/// (`None`) — the common, safe behaviour; we don't emit multipart/byteranges.
fn parse_range(headers: &http::HeaderMap, len: u64) -> RangeReq {
    let raw = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(r) => r.trim(),
        None => return RangeReq::None,
    };
    let spec = match raw.strip_prefix("bytes=") {
        Some(s) => s.trim(),
        None => return RangeReq::None, // only `bytes` units
    };
    // Single range only; a comma means multipart → fall back to full.
    if spec.contains(',') {
        return RangeReq::None;
    }
    let (a, b) = match spec.split_once('-') {
        Some(p) => p,
        None => return RangeReq::None,
    };
    let (a, b) = (a.trim(), b.trim());

    if len == 0 {
        return RangeReq::Unsatisfiable;
    }
    let (start, end) = if a.is_empty() {
        // `-N`: the last N bytes.
        let n: u64 = match b.parse() {
            Ok(n) if n > 0 => n,
            _ => return RangeReq::Unsatisfiable,
        };
        let n = n.min(len);
        (len - n, len - 1)
    } else {
        let start: u64 = match a.parse() {
            Ok(s) => s,
            Err(_) => return RangeReq::None,
        };
        let end: u64 = if b.is_empty() {
            len - 1
        } else {
            match b.parse() {
                Ok(e) => e,
                Err(_) => return RangeReq::None,
            }
        };
        (start, end.min(len - 1))
    };

    if start > end || start >= len {
        return RangeReq::Unsatisfiable;
    }
    RangeReq::Satisfiable(start, end)
}

/// Serve a satisfiable byte range as `206 Partial Content`: seek to `start` and
/// stream exactly `end - start + 1` bytes, never buffering the whole file.
async fn serve_range(
    mut builder: http::response::Builder,
    file_path: &Path,
    start: u64,
    end: u64,
    len: u64,
    head_only: bool,
) -> Resp {
    let part = end - start + 1;
    builder = builder.status(StatusCode::PARTIAL_CONTENT);
    {
        let headers = builder.headers_mut().expect("builder has headers");
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{end}/{len}")) {
            headers.insert(header::CONTENT_RANGE, v);
        }
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(part));
    }
    if head_only {
        return builder.body(response::empty()).expect("response builds");
    }
    let mut file = match tokio::fs::File::open(file_path).await {
        Ok(f) => f,
        Err(_) => return response::status(StatusCode::NOT_FOUND),
    };
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return response::status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    use futures::TryStreamExt as _;
    let stream = ReaderStream::new(file.take(part)).map_ok(hyper::body::Frame::data);
    let body = response::boxed(http_body_util::StreamBody::new(stream));
    builder.body(body).expect("response builds")
}

/// gzip `data` at the configured level. `None` only on the (practically
/// impossible) in-memory encoder failure, letting the caller fall back to an
/// uncompressed response.
fn gzip(data: &[u8], level: u8) -> Option<Vec<u8>> {
    // flate2 accepts 0..=9; clamp so a stray config value can't panic the encoder.
    let level = (level as u32).min(9);
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(level));
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

/// Whether the content type is worth compressing (text + the structured text
/// formats nginx's default `gzip_types` covers, minus the C-backed ones).
fn is_compressible(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || matches!(
            content_type,
            "application/javascript"
                | "application/json"
                | "image/svg+xml"
                | "application/xml"
                | "application/rss+xml"
                | "application/atom+xml"
        )
}

/// Whether the client's `Accept-Encoding` lists gzip (a coarse contains-check;
/// a `gzip;q=0` opt-out is rare enough that nginx-parity isn't worth the parse).
fn accepts_gzip(headers: &http::HeaderMap) -> bool {
    headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|t| t.trim().split(';').next().unwrap_or("").trim())
                .any(|enc| enc.eq_ignore_ascii_case("gzip"))
        })
        .unwrap_or(false)
}

/// Append `; charset=utf-8` to text-ish types so browsers decode them right,
/// matching nginx's `charset utf-8` for text and the structured text formats.
fn full_content_type(ct: &str) -> String {
    let needs_charset = ct.starts_with("text/")
        || matches!(
            ct,
            "application/javascript" | "application/json" | "image/svg+xml" | "application/xml"
        );
    if needs_charset {
        format!("{ct}; charset=utf-8")
    } else {
        ct.to_string()
    }
}

/// Attach `Last-Modified`/`ETag` validators when we have them.
fn attach_validators(headers: &mut http::HeaderMap, last_modified: Option<&str>, etag: Option<&str>) {
    if let Some(lm) = last_modified {
        if let Ok(v) = HeaderValue::from_str(lm) {
            headers.insert(header::LAST_MODIFIED, v);
        }
    }
    if let Some(tag) = etag {
        if let Ok(v) = HeaderValue::from_str(tag) {
            headers.insert(header::ETAG, v);
        }
    }
}

/// Attach long asset caching when the site opted in and the file is an asset.
fn attach_cache(headers: &mut http::HeaderMap, file_path: &Path, root: &StaticRoot) {
    if !root.cache_assets {
        return;
    }
    let is_asset = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            let e = e.to_ascii_lowercase();
            ASSET_EXTS.contains(&e.as_str())
        })
        .unwrap_or(false);
    if !is_asset {
        return;
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=604800"),
    );
    // Absolute `Expires` for HTTP/1.0 caches, one week out from now.
    if let Some(expires) = httpdate_from(std::time::SystemTime::now() + std::time::Duration::from_secs(ASSET_MAX_AGE)) {
        if let Ok(v) = HeaderValue::from_str(&expires) {
            headers.insert(header::EXPIRES, v);
        }
    }
}

/// Decide a conditional request: honour `If-None-Match` against our ETag when
/// present, else `If-Modified-Since` against our mtime (second precision).
fn not_modified(
    headers: &http::HeaderMap,
    etag: Option<&str>,
    mtime: Option<std::time::SystemTime>,
) -> bool {
    if let (Some(inm), Some(tag)) = (
        headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()),
        etag,
    ) {
        // Match any of the comma-separated client tags (ignoring a weak prefix).
        return inm.split(',').any(|t| {
            let t = t.trim();
            let t = t.strip_prefix("W/").unwrap_or(t);
            t == "*" || t == tag
        });
    }
    if let (Some(ims), Some(mt)) = (
        headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok()),
        mtime,
    ) {
        if let (Some(since), Some(modified)) = (parse_http_date(ims), epoch_secs(mt)) {
            // Not modified if our mtime is at or before the client's copy time.
            return modified <= since;
        }
    }
    false
}

/// Whole seconds since the Unix epoch for a `SystemTime`.
fn epoch_secs(t: std::time::SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// A weak-ish strong ETag derived from mtime + size: `"<mtime_secs>-<len>"`.
fn etag_from(mtime: std::time::SystemTime, len: u64) -> Option<String> {
    epoch_secs(mtime).map(|secs| format!("\"{secs:x}-{len:x}\""))
}

/// Format a `SystemTime` as an RFC 1123 HTTP date (the only format we emit).
fn httpdate_from(t: std::time::SystemTime) -> Option<String> {
    let secs = epoch_secs(t)?;
    Some(format_http_date(secs))
}

// --- Minimal RFC 1123 HTTP-date formatting/parsing -------------------------
//
// We don't pull in the `httpdate` crate (not in the dependency set); the format
// is fixed (`Sun, 06 Nov 1994 08:49:37 GMT`) and a few lines of civil-date math
// covers both directions. All times are UTC/GMT.

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format whole epoch seconds as `Wdy, DD Mon YYYY HH:MM:SS GMT`.
fn format_http_date(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 1970-01-01 was a Thursday (index 4).
    let weekday = ((days + 4) % 7) as usize;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        day,
        MONTHS[(month - 1) as usize],
        year,
        hh,
        mm,
        ss
    )
}

/// Convert days-since-epoch into a civil (year, month, day). Howard Hinnant's
/// days_from_civil inverse — exact for all dates we'll see.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Inverse of [`civil_from_days`]: civil date → days since epoch.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse an HTTP date (RFC 1123 / RFC 850 / asctime) into epoch seconds. We only
/// need it for `If-Modified-Since`, so a tolerant token parser suffices.
fn parse_http_date(s: &str) -> Option<u64> {
    let s = s.trim();
    // Drop the leading weekday token (`Sun,` or `Sunday,` or `Sun`).
    let rest = s.split_once([' ', ',']).map(|(_, r)| r.trim()).unwrap_or(s);
    let toks: Vec<&str> = rest.split_whitespace().collect();

    // Two shapes: "DD Mon YYYY HH:MM:SS GMT" (1123/850) and
    // "Mon DD HH:MM:SS YYYY" (asctime).
    let (day, month, year, time) = if toks.len() >= 4 && toks[0].parse::<i64>().is_ok() {
        // RFC 1123: 06 Nov 1994 08:49:37 GMT  (850 uses a 2-digit year)
        let day = toks[0].parse::<i64>().ok()?;
        let month = month_index(toks[1])?;
        let mut year = toks[2].parse::<i64>().ok()?;
        if year < 100 {
            // RFC 850 two-digit year: pivot like nginx (>=70 → 1900s).
            year += if year >= 70 { 1900 } else { 2000 };
        }
        (day, month, year, toks[3])
    } else if toks.len() >= 4 {
        // asctime: Nov  6 08:49:37 1994
        let month = month_index(toks[0])?;
        let day = toks[1].parse::<i64>().ok()?;
        let year = toks[3].parse::<i64>().ok()?;
        (day, month, year, toks[2])
    } else {
        return None;
    };

    let mut hms = time.split(':');
    let hh: u64 = hms.next()?.parse().ok()?;
    let mm: u64 = hms.next()?.parse().ok()?;
    let ss: u64 = hms.next().unwrap_or("0").parse().ok()?;

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// 1-based month number for a three-letter English month abbreviation.
fn month_index(m: &str) -> Option<i64> {
    MONTHS
        .iter()
        .position(|name| name.eq_ignore_ascii_case(m))
        .map(|i| i as i64 + 1)
}
