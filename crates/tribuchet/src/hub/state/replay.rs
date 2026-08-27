//! Buffered per-build event replay for dedupe subscribers.

use std::mem;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc};
use tonic::Status;

const SUB_STALL: Duration = Duration::from_mins(1);

use super::{EventTx, MAX_REPLAY_BYTES, SUB_CHANNEL_SLACK};
use crate::proto::{AttachEvent, attach_event};

/// Buffered event log of one in-flight build; late identical submissions
/// (dedupe) replay the buffer and then follow live. The buffer holds the
/// compressed output chunks too, capped at MAX_REPLAY_BYTES.
#[derive(Default)]
pub(in crate::hub) struct Replay {
    inner: Mutex<ReplayInner>,
}

#[derive(Default)]
struct ReplayInner {
    events: Vec<AttachEvent>,
    bytes: usize,
    /// Buffer cap hit: the backlog is incomplete, so late dedupe
    /// subscribers must error instead of getting a truncated stream.
    overflowed: bool,
    subs: Vec<EventTx>,
    done: bool,
}

fn event_size(ev: &attach_event::Event) -> usize {
    match ev {
        attach_event::Event::Log(d) => d.len(),
        attach_event::Event::Output(o) => o.zstd_nar_chunk.len(),
        attach_event::Event::OutputRestart(p)
        | attach_event::Event::AddedPath(p)
        | attach_event::Event::Dispatched(p) => p.len(),
        attach_event::Event::Error(e) => e.len(),
        attach_event::Event::ExitCode(_) => 0,
    }
    .saturating_add(64)
}

impl Replay {
    pub(in crate::hub) async fn publish(&self, ev: attach_event::Event) {
        let sz = event_size(&ev);
        let ev = AttachEvent { event: Some(ev) };
        let mut inner = self.inner.lock().await;
        for tx in mem::take(&mut inner.subs) {
            match tokio::time::timeout(SUB_STALL, tx.send(Ok(ev.clone()))).await {
                Ok(Ok(())) => inner.subs.push(tx),
                Ok(Err(_)) => {}
                Err(_) => tracing::warn!("dropping attach subscriber that stalled"),
            }
        }
        if inner.overflowed {
            return;
        }
        if inner.bytes + sz > MAX_REPLAY_BYTES {
            tracing::warn!("replay buffer cap reached; late dedupe subscribers will be rejected");
            inner.overflowed = true;
            inner.events.clear();
            inner.bytes = 0;
            return;
        }
        inner.bytes += sz;
        inner.events.push(ev);
    }

    pub(in crate::hub) async fn subscribe(&self) -> mpsc::Receiver<Result<AttachEvent, Status>> {
        let mut inner = self.inner.lock().await;
        if inner.overflowed {
            let (tx, rx) = mpsc::channel(1);
            let _ = tx.try_send(Err(Status::resource_exhausted(
                "build output exceeded the replay buffer; retry after it finishes",
            )));
            return rx;
        }
        // Enough capacity for the whole backlog plus live slack (and
        // one error slot), so the snapshot below cannot drop events.
        let (tx, rx) = mpsc::channel(inner.events.len() + SUB_CHANNEL_SLACK);
        for ev in &inner.events {
            let _ = tx.try_send(Ok(ev.clone()));
        }
        if inner.done {
            // Finished without a verdict in the backlog (e.g. the job
            // was dropped as abandoned between the dedupe lookup and
            // this subscribe): an error beats a silently empty stream.
            let concluded = inner.events.iter().any(|e| {
                matches!(
                    e.event,
                    Some(attach_event::Event::ExitCode(_) | attach_event::Event::Error(_))
                )
            });
            if !concluded {
                let _ = tx.try_send(Err(Status::unavailable(
                    "build is no longer in flight; resubmit",
                )));
            }
        } else {
            inner.subs.push(tx);
        }
        rx
    }

    /// Close all subscriber streams.
    pub(in crate::hub) async fn finish(&self) {
        let mut inner = self.inner.lock().await;
        inner.done = true;
        inner.subs.clear();
    }

    /// Any attach client still listening? Subscribers whose stream was
    /// dropped count as gone even before publish() prunes them.
    pub(in crate::hub) async fn has_subscribers(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.subs.iter().any(|tx| !tx.is_closed())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn slow_subscriber_paces_publish() {
        let replay = Arc::new(Replay::default());
        let mut rx = replay.subscribe().await;
        let n = SUB_CHANNEL_SLACK + 10;
        let publisher = {
            let replay = replay.clone();
            tokio::spawn(async move {
                for _ in 0..n {
                    replay
                        .publish(attach_event::Event::Log(b"x".to_vec()))
                        .await;
                }
            })
        };
        for _ in 0..n {
            tokio::time::sleep(Duration::from_millis(10)).await;
            rx.recv().await.unwrap().unwrap();
        }
        publisher.await.unwrap();
        assert!(replay.has_subscribers().await);
    }
}
