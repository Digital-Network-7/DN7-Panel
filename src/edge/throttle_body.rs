//! A per-connection download throttle — the in-process equivalent of nginx's
//! `limit_rate`. Wraps a response body and paces its output to `bytes_per_sec`
//! with a byte token bucket: each poll releases as many bytes as the bucket
//! allows (splitting a chunk when needed) and sleeps for the deficit, so a
//! throttled transfer never blocks the server task.
//!
//! It holds a `tokio::time::Sleep` (which isn't `Sync`) — the reason the edge's
//! [`ResBody`] is an *unsync* boxed body (`Send` is enough; each connection is
//! served on one task).
use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::time::Instant;

use super::response::{boxed, ResBody};

struct ThrottleBody {
    inner: ResBody,
    rate: f64,                                   // bytes/sec
    allowance: f64,                              // byte tokens available
    last: Instant,                               // last refill
    sleep: Option<Pin<Box<tokio::time::Sleep>>>, // armed while waiting for tokens
    pending: Option<Bytes>,                      // a data chunk being metered out
}

impl ThrottleBody {
    /// Refill the bucket by `elapsed × rate`, capped at one second of burst.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.allowance = (self.allowance + elapsed * self.rate).min(self.rate);
        self.last = now;
    }
}

impl Body for ThrottleBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        // `ThrottleBody` is `Unpin` (UnsyncBoxBody + Pin<Box<…>> + plain fields).
        let this = self.get_mut();
        loop {
            // Wait out an armed sleep, then refill the bucket.
            if let Some(sl) = this.sleep.as_mut() {
                ready!(sl.as_mut().poll(cx));
                this.sleep = None;
                this.refill();
            }

            // Meter out a pending data chunk (fields accessed disjointly so the
            // refill's `&mut self` doesn't overlap the chunk borrow).
            if this.pending.is_some() {
                this.refill();
                let avail = this.allowance.floor() as usize;
                let len = this.pending.as_ref().map_or(0, Bytes::len);
                if avail >= len {
                    this.allowance -= len as f64;
                    let out = this.pending.take().expect("pending checked above");
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                // Release in slices of up to one second of bandwidth (the bucket
                // ceiling) so a drained bucket doesn't dribble out a byte at a
                // time; sleep until that many tokens accrue.
                let want = len.min(this.rate as usize).max(1);
                if avail >= want {
                    this.allowance -= want as f64;
                    let out = this
                        .pending
                        .as_mut()
                        .expect("pending checked")
                        .split_to(want);
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                let wait = ((want as f64 - this.allowance) / this.rate).max(0.001);
                this.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_secs_f64(wait))));
                continue;
            }

            // No pending chunk — pull the next frame from the inner body.
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => return Poll::Ready(None),
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                Some(Ok(frame)) => match frame.into_data() {
                    // A data frame: meter it on the next loop iteration.
                    Ok(data) => {
                        if !data.is_empty() {
                            this.pending = Some(data);
                        }
                    }
                    // Trailers / non-data frame: pass straight through.
                    Err(non_data) => return Poll::Ready(Some(Ok(non_data))),
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_none() && self.sleep.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Wrap `body` so it streams at no more than `bytes_per_sec`. A rate of 0 leaves
/// the body untouched (no throttle, no allocation).
pub(crate) fn throttle(body: ResBody, bytes_per_sec: u64) -> ResBody {
    if bytes_per_sec == 0 {
        return body;
    }
    boxed(ThrottleBody {
        inner: body,
        rate: bytes_per_sec as f64,
        allowance: bytes_per_sec as f64, // start with one second of burst
        last: Instant::now(),
        sleep: None,
        pending: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    fn body_of(data: &[u8]) -> ResBody {
        Full::new(Bytes::copy_from_slice(data))
            .map_err(|never| match never {})
            .boxed_unsync()
    }

    #[tokio::test]
    async fn throttle_preserves_all_bytes() {
        // Rate above the body size → released from the initial burst in one go.
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let got = throttle(body_of(&data), 1_000_000)
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(got.as_ref(), data.as_slice());
    }

    #[tokio::test]
    async fn throttle_splits_across_a_sleep_without_losing_bytes() {
        // The body exceeds the 1s burst (50000 B), so the tail is metered out
        // across a brief sleep (~0.2s) — exercises the split/reassemble path and
        // proves every byte survives, in order.
        let data: Vec<u8> = (0..60_000u32).map(|i| i as u8).collect();
        let start = std::time::Instant::now();
        let got = throttle(body_of(&data), 50_000)
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(got.as_ref(), data.as_slice(), "no bytes lost or reordered");
        assert!(
            start.elapsed() >= Duration::from_millis(100),
            "it actually paced"
        );
    }
}
