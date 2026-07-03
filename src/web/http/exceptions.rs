//! Error → HTTP response mapping (≈ Laravel `app/Exceptions/Handler`).
//!
//! The single place the web boundary turns a status + stable code (and the
//! transitional `ERR_CODE:` capability channel) into the wire shape
//! `{ ok:false, code, error }` the client localizes via `err.<code>`.
use super::*;

/// Build a stable, localizable error response: `{ ok:false, code, error }`.
/// `code` is a machine-stable identifier the client maps to a translated
/// message (`err.<code>`); `error` carries the same code as a neutral fallback
/// for non-localized consumers / logs.
pub(crate) fn api_err(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(json!({ "ok": false, "code": code, "error": code })),
    )
        .into_response()
}

/// Like `api_err`, but keep a human detail string (e.g. an underlying IO error)
/// in `error` while `code` still drives localization on the client.
pub(crate) fn api_err_detail(
    status: StatusCode,
    code: &str,
    detail: impl std::fmt::Display,
) -> Response {
    (
        status,
        Json(json!({ "ok": false, "code": code, "error": detail.to_string() })),
    )
        .into_response()
}

/// Build the JSON body for a capability-op failure. Fixed validation errors
/// from the docker/website modules carry a stable code as `ERR_CODE:<code>`
/// in their message; split it into a `code` field the client localizes
/// (`err.<code>`). Dynamic/operational errors pass through as plain text.
pub(crate) fn op_err_body(e: anyhow::Error) -> Value {
    let s = e.to_string();
    match s.strip_prefix("ERR_CODE:") {
        // `ERR_CODE:<code>` optionally followed by `\x1f`-separated positional
        // args (`ERR_CODE:docker.port_in_use\x1f8080\x1ftcp`). The client localizes
        // `err.<code>` and substitutes {0},{1},… so a coded message can still name
        // the offending port/IP/etc.
        Some(rest) => {
            let mut parts = rest.split('\u{1f}');
            let code = parts.next().unwrap_or("");
            let args: Vec<&str> = parts.collect();
            json!({ "ok": false, "code": code, "args": args, "error": code })
        }
        None => json!({ "ok": false, "error": s }),
    }
}
