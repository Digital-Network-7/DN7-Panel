//! Shared response body type + small constructors, so every edge handler
//! returns the same `Response<ResBody>` and the listener can serve them without
//! per-handler body-type juggling.

use bytes::Bytes;
use http::{header, HeaderValue, Response, StatusCode};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full};

/// The unified response body every edge handler produces. An *unsync* boxed body
/// erases the concrete body type (full buffer, streamed proxy response, file
/// stream, rate-throttled stream) so the listener's service has one return type.
/// `Send` (not `Sync`) is enough — each connection is served on one task — and
/// it lets a throttle body hold a `tokio::time::Sleep` (which isn't `Sync`).
pub(crate) type ResBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// The unified response type used across the edge handlers.
pub(crate) type Resp = Response<ResBody>;

/// Box any `Bytes`-yielding body into [`ResBody`], mapping its error into
/// `std::io::Error` (proxy/file streams already use io errors).
pub(crate) fn boxed<B>(body: B) -> ResBody
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    body.map_err(|e| std::io::Error::other(e.into()))
        .boxed_unsync()
}

/// A fully-buffered body from anything `Bytes`-convertible.
pub(crate) fn full<T: Into<Bytes>>(chunk: T) -> ResBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// An empty body.
pub(crate) fn empty() -> ResBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// A bare status response with an empty body.
pub(crate) fn status(code: StatusCode) -> Resp {
    Response::builder()
        .status(code)
        .body(empty())
        .expect("static response builds")
}

/// A `text/plain` response.
pub(crate) fn text<T: Into<Bytes>>(code: StatusCode, body: T) -> Resp {
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(body))
        .expect("static response builds")
}

/// An `text/html` response.
pub(crate) fn html<T: Into<Bytes>>(code: StatusCode, body: T) -> Resp {
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full(body))
        .expect("static response builds")
}

/// A 301 redirect to `location`.
pub(crate) fn redirect(location: &str) -> Resp {
    let mut r = status(StatusCode::MOVED_PERMANENTLY);
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

/// The Basic-Auth 401 challenge for `realm`.
pub(crate) fn auth_challenge(realm: &str) -> Resp {
    let mut r = text(StatusCode::UNAUTHORIZED, "401 Authorization Required");
    // Quote-escape the realm so a crafted access-list name can't break the header.
    let safe = realm.replace('"', "");
    if let Ok(v) = HeaderValue::from_str(&format!("Basic realm=\"{safe}\"")) {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    r
}
