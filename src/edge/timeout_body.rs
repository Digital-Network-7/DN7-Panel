//! An inactivity-timeout request-body wrapper — the in-process equivalent of
//! nginx's `client_body_timeout`. It wraps the body the proxy reads from the
//! client so that if no progress (data/trailers/EOF) is made within the window,
//! the body errors out, tearing down a trickle/slowloris upload that would
//! otherwise hold a connection open indefinitely. A body that keeps making
//! progress is never interrupted (the timer resets on every frame), so large
//! legitimate uploads are unaffected.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::BodyExt;

/// Boxed error type carried by the proxied request body.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The proxied request-body type: an unsync boxed body (the pooled client only
/// needs `Send`, not `Sync`, so `UnsyncBoxBody` lets us wrap `tokio::time::Sleep`
/// which isn't `Sync`).
pub(crate) type ProxyReqBody = UnsyncBoxBody<Bytes, BoxError>;

/// Wrap a request body with an inactivity deadline.
pub(crate) struct TimeoutBody {
    inner: ProxyReqBody,
    timeout: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl TimeoutBody {
    fn new(inner: ProxyReqBody, timeout: Duration) -> Self {
        let sleep = Box::pin(tokio::time::sleep(timeout));
        TimeoutBody {
            inner,
            timeout,
            sleep,
        }
    }
}

impl Body for TimeoutBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // `TimeoutBody` is `Unpin` (UnsyncBoxBody + Pin<Box<Sleep>> + Duration),
        // so we can take a plain `&mut`.
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(v) => {
                // Progress made — reset the inactivity deadline.
                let next = tokio::time::Instant::now() + this.timeout;
                this.sleep.as_mut().reset(next);
                Poll::Ready(v)
            }
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Some(Err("request body inactivity timeout".into()))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Adapt an inbound `Incoming` request body into the proxied [`ProxyReqBody`],
/// applying the inactivity timeout only when the request actually carries a body
/// (`with_timeout == true`) so a bodyless GET doesn't pay for a timer.
pub(crate) fn prepare(body: hyper::body::Incoming, timeout: Duration, with_timeout: bool) -> ProxyReqBody {
    let boxed: ProxyReqBody = body
        .map_err(|e| Box::new(e) as BoxError)
        .boxed_unsync();
    if with_timeout {
        TimeoutBody::new(boxed, timeout).boxed_unsync()
    } else {
        boxed
    }
}
