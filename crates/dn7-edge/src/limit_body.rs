//! A cumulative-size request-body wrapper — the streaming half of nginx's
//! `client_max_body_size`. The proxy already rejects an oversized upload early
//! via the declared `Content-Length` (a fast path, before it dials the
//! upstream), but a chunked / HTTP-2 body carries no length up front: its size
//! is only known as the frames arrive. Without this a client could stream an
//! unbounded body past the cap by simply omitting `Content-Length`.
//!
//! So we wrap the request body the proxy forwards and ACCUMULATE the byte count
//! across every `poll_frame`. Once the running total exceeds the route's limit
//! the body fails, which aborts the upstream request — the proxy surfaces that
//! as a 502/413 rather than relaying the oversized payload. A body that stays
//! under the cap is never touched (the counter just adds up), so legitimate
//! large-but-bounded uploads are unaffected.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;

use super::timeout_body::{BoxError, ProxyReqBody};

/// Wrap a request body with a cumulative byte cap.
pub(crate) struct LimitBody {
    inner: ProxyReqBody,
    /// The per-route `client_max_body_size` in bytes (always > 0 here — the
    /// unlimited case skips the wrapper entirely).
    limit: u64,
    /// Bytes seen so far across every data frame.
    seen: u64,
}

impl LimitBody {
    fn new(inner: ProxyReqBody, limit: u64) -> Self {
        LimitBody {
            inner,
            limit,
            seen: 0,
        }
    }
}

impl Body for LimitBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // `LimitBody` is `Unpin` (UnsyncBoxBody + plain counters), so a plain
        // `&mut` is fine.
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    // Saturating so a pathological length can't wrap the counter
                    // back under the limit.
                    this.seen = this.seen.saturating_add(data.len() as u64);
                    if this.seen > this.limit {
                        // Over the cap — fail the body so the proxy aborts the
                        // upstream request instead of streaming the rest through.
                        return Poll::Ready(Some(Err(
                            "request body exceeds client_max_body_size".into()
                        )));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Wrap `body` so it fails once its cumulative size exceeds `limit` bytes. A
/// `limit` of 0 means "unlimited" and leaves the body untouched (no wrapper, no
/// counter).
pub(crate) fn limit(body: ProxyReqBody, limit: u64) -> ProxyReqBody {
    if limit == 0 {
        return body;
    }
    LimitBody::new(body, limit).boxed_unsync()
}
