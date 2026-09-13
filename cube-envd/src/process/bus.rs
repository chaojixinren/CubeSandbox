// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-process output bus: one publisher (the pipe/pty pump, plus the
//! supervisor for control events) and one subscription per attached stream
//! (`process.Process/Start`, each `process.Process/Connect`).
//!
//! Policy
//! ------
//! * **Slow is not dead.** A subscriber that is behind applies backpressure:
//!   the pump stops reading the child's pipe, the pipe fills, and the child
//!   blocks in `write`. Nothing is dropped, so a slow consumer still receives
//!   every byte.
//! * **Only a stalled subscriber is evicted.** A subscriber that is *waiting*
//!   and has made no progress for [`DEFAULT_EVICT_AFTER`] is disconnected with
//!   `resource_exhausted`, so a client that stays connected but never reads
//!   cannot pin the pump — the failure mode upstream
//!   [e2b-dev/runtime#3292](https://github.com/e2b-dev/runtime/issues/3292)
//!   reports for a blocking fan-out.
//! * **Terminal events are guaranteed.** Every queue keeps one slot reserved
//!   for its terminal frame through a resident `OwnedPermit`, so `End` is
//!   delivered even when every data slot is full, and the frame order (data
//!   before `End`) is preserved.
//! * **Control events are best-effort.** `DeadlineExceeded` only *hints* that
//!   the process was killed by its deadline; the stream trailer is decided
//!   out-of-band from `EndEvent.killed_by`, so a dropped hint cannot
//!   misreport the stream as a normal exit.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::process::engine::PumpEvent;

/// Subscriber-queue capacity: data slots plus the reserved terminal slot.
pub(crate) const SUBSCRIBER_QUEUE_CAPACITY: usize = 24;
/// Per-connection response queue: data slots plus the reserved terminal slot.
pub(crate) const BODY_QUEUE_CAPACITY: usize = 8;
/// No progress for this long while waiting means the subscriber is stalled.
pub(crate) const DEFAULT_EVICT_AFTER: Duration = Duration::from_secs(300);
/// Attachments allowed per process, including its `Start` subscription.
pub(crate) const MAX_SUBSCRIBERS_PER_PROCESS: usize = 8;
/// Attachments allowed in this envd process, across all processes.
pub(crate) const MAX_SUBSCRIBERS_GLOBAL: usize = 64;

static GLOBAL_SUBSCRIBERS: AtomicUsize = AtomicUsize::new(0);

/// Why a subscription stopped receiving events.
#[derive(Debug, PartialEq, Eq)]
pub enum BusError {
    /// Evicted after making no progress while waiting.
    Evicted,
    /// The publisher is gone and no further events will arrive.
    Closed,
    /// This process (or this envd) already holds as many attachments as allowed.
    TooManySubscribers,
}

/// A bounded queue with one slot permanently reserved for its terminal frame.
///
/// The reservation is a resident `OwnedPermit`: it is held out of
/// `capacity()`, so a data `reserve()` can never take the terminal slot, and
/// the terminal frame can always be queued without blocking. That is what
/// makes "`End` is delivered even when the queue is full" enforceable rather
/// than a convention.
#[derive(Debug)]
pub struct TerminalChannel<T> {
    tx: mpsc::Sender<T>,
    /// Consumed once, when the terminal frame is sent. `Mutex` so that a
    /// `&self` reached through `Arc<Subscriber>` can consume it; the critical
    /// section is synchronous and never held across an await.
    terminal: Mutex<Option<mpsc::OwnedPermit<T>>>,
}

impl<T> TerminalChannel<T> {
    /// Create the channel together with its receiver.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<T>) {
        assert!(
            capacity >= 2,
            "a terminal slot needs at least one data slot"
        );
        let (tx, rx) = mpsc::channel(capacity);
        let permit = tx
            .clone()
            .try_reserve_owned()
            .expect("a fresh channel has room for the reserved slot");
        (
            Self {
                tx,
                terminal: Mutex::new(Some(permit)),
            },
            rx,
        )
    }

    /// Wait for a data slot. `reserve` never reports "full" — it waits until a
    /// slot frees up, and only fails once the receiver is gone.
    pub async fn reserve_data(&self) -> Result<mpsc::Permit<'_, T>, BusError> {
        self.tx.reserve().await.map_err(|_| BusError::Closed)
    }

    /// Queue the terminal frame in its reserved slot. Never blocks.
    pub fn send_terminal(&self, value: T) -> bool {
        match lock(&self.terminal).take() {
            Some(permit) => {
                permit.send(value);
                true
            }
            // Only reachable when a terminal frame was already sent; a
            // duplicate is best effort.
            None => self.tx.try_send(value).is_ok(),
        }
    }

    /// Best-effort, non-blocking send, used for control hints.
    pub fn try_send_control(&self, value: T) -> bool {
        self.tx.try_send(value).is_ok()
    }

    /// Resolves once the receiver is gone, i.e. the client disconnected.
    pub async fn closed(&self) {
        self.tx.closed().await
    }
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    q: TerminalChannel<PumpEvent>,
    /// Set *before* a publisher starts waiting and cleared once a send
    /// succeeds. The reaper evicts a subscriber whose marker is older than
    /// `evict_after`; because the marker is set before the wait, a subscriber
    /// that never returns from `reserve_data` is still visible to it.
    stalled_since: Mutex<Option<Instant>>,
    /// Eviction latch: set by the reaper, awaited by the publisher and by the
    /// connection driving this subscription.
    evicted: watch::Sender<bool>,
}

/// One attachment's view of the bus. Dropping it detaches immediately.
#[derive(Debug)]
pub struct Subscription {
    bus: Weak<OutputBus>,
    id: u64,
    rx: mpsc::Receiver<PumpEvent>,
    evicted: watch::Receiver<bool>,
    /// Terminal-event cache owned by the process table. A subscription that
    /// ends without a terminal event (the bus disappeared first) can still
    /// report the real exit instead of an internal error.
    terminal: Option<Arc<Mutex<Option<PumpEvent>>>>,
    /// Counted against [`MAX_SUBSCRIBERS_GLOBAL`]; false for cached one-shots.
    counted: bool,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(bus) = self.bus.upgrade() {
            bus.detach(self.id);
        }
        if self.counted {
            GLOBAL_SUBSCRIBERS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// The per-process output bus handle stored on the process entry.
#[derive(Debug)]
pub struct OutputBus {
    subscribers: Mutex<Vec<Arc<Subscriber>>>,
    next_id: AtomicU64,
    evict_after: Duration,
    max_subscribers: usize,
}

impl OutputBus {
    /// Create a bus plus the subscription reserved for the first attachment.
    pub fn new() -> (Arc<Self>, Subscription) {
        Self::with_limits(
            SUBSCRIBER_QUEUE_CAPACITY,
            DEFAULT_EVICT_AFTER,
            MAX_SUBSCRIBERS_PER_PROCESS,
        )
    }

    /// Same as [`OutputBus::new`] with explicit limits, so tests can drive
    /// overflow and eviction deterministically.
    pub(crate) fn with_limits(
        capacity: usize,
        evict_after: Duration,
        max_subscribers: usize,
    ) -> (Arc<Self>, Subscription) {
        let bus = Arc::new(Self {
            subscribers: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            evict_after,
            max_subscribers,
        });
        let subscription = bus
            .attach(capacity)
            .expect("the first attachment is always within the limit");
        bus.spawn_reaper();
        (bus, subscription)
    }

    fn attach(self: &Arc<Self>, capacity: usize) -> Result<Subscription, BusError> {
        if lock(&self.subscribers).len() >= self.max_subscribers {
            return Err(BusError::TooManySubscribers);
        }
        if GLOBAL_SUBSCRIBERS.fetch_add(1, Ordering::AcqRel) >= MAX_SUBSCRIBERS_GLOBAL {
            GLOBAL_SUBSCRIBERS.fetch_sub(1, Ordering::AcqRel);
            return Err(BusError::TooManySubscribers);
        }
        let (q, rx) = TerminalChannel::new(capacity);
        let (evicted_tx, evicted_rx) = watch::channel(false);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        lock(&self.subscribers).push(Arc::new(Subscriber {
            id,
            q,
            stalled_since: Mutex::new(None),
            evicted: evicted_tx,
        }));
        Ok(Subscription {
            bus: Arc::downgrade(self),
            id,
            rx,
            evicted: evicted_rx,
            terminal: None,
            counted: true,
        })
    }

    /// Attach another subscription (a later `Connect`).
    pub fn subscribe(self: &Arc<Self>) -> Result<Subscription, BusError> {
        self.attach(SUBSCRIBER_QUEUE_CAPACITY)
    }

    /// A subscription that yields exactly one cached event and then closes.
    /// Used when a `Connect` arrives after the process terminated.
    pub fn subscription_from_event(event: PumpEvent) -> Subscription {
        let (q, rx) = TerminalChannel::new(2);
        let _ = q.send_terminal(event);
        let (evicted_tx, evicted_rx) = watch::channel(false);
        drop(evicted_tx);
        Subscription {
            bus: Weak::new(),
            id: 0,
            rx,
            evicted: evicted_rx,
            terminal: None,
            counted: false,
        }
    }

    /// How many attachments are currently attached.
    pub fn subscriber_count(&self) -> usize {
        lock(&self.subscribers).len()
    }

    /// Publish a data event, waiting for room in every live subscriber. The
    /// wait is interruptible by eviction, and a subscriber that is behind is
    /// what backpressures the child.
    pub async fn publish_data(&self, event: PumpEvent) {
        for subscriber in self.snapshot() {
            let mut evicted = subscriber.evicted.subscribe();
            if *evicted.borrow() {
                continue;
            }
            // Mark the stall *before* waiting. A genuinely stuck subscriber
            // never returns from `reserve_data`, so this marker is the only
            // thing the reaper can act on.
            if lock(&subscriber.stalled_since).is_none() {
                *lock(&subscriber.stalled_since) = Some(Instant::now());
            }
            let sent = tokio::select! {
                biased;
                _ = evicted.changed() => false,
                permit = subscriber.q.reserve_data() => match permit {
                    Ok(permit) => {
                        permit.send(event.clone());
                        true
                    }
                    Err(_) => false,
                },
            };
            if sent {
                *lock(&subscriber.stalled_since) = None;
            }
        }
    }

    /// Publish the terminal event. Guaranteed and non-blocking: every queue
    /// holds a slot reserved for it.
    pub fn publish_terminal(&self, event: PumpEvent) -> bool {
        let subscribers = self.snapshot();
        if subscribers.is_empty() {
            return false;
        }
        for subscriber in &subscribers {
            if !subscriber.q.send_terminal(event.clone()) {
                tracing::warn!("process output bus: terminal frame dropped for a subscriber");
            }
        }
        true
    }

    /// Publish a best-effort control event (`DeadlineExceeded`). Never blocks,
    /// never evicts, and may be dropped when a subscriber is behind.
    pub fn publish_control(&self, event: PumpEvent) -> bool {
        let subscribers = self.snapshot();
        if subscribers.is_empty() {
            return false;
        }
        for subscriber in &subscribers {
            subscriber.q.try_send_control(event.clone());
        }
        true
    }

    /// Disconnect every subscriber whose wait has made no progress for
    /// `evict_after`. Called by the per-bus reaper task.
    fn evict_stalled(&self) {
        let now = Instant::now();
        let stalled: Vec<u64> = self
            .snapshot()
            .iter()
            .filter(|subscriber| {
                lock(&subscriber.stalled_since)
                    .is_some_and(|since| now.duration_since(since) >= self.evict_after)
            })
            .map(|subscriber| subscriber.id)
            .collect();
        for id in stalled {
            if let Some(subscriber) = self.take(id) {
                tracing::info!(
                    "process output bus: evicting subscriber {id} after {:?} without progress",
                    self.evict_after
                );
                // Wakes the publisher's wait and the connection's driver. The
                // connection reports `resource_exhausted` on its own terminal
                // slot, because it owns the encoding.
                let _ = subscriber.evicted.send(true);
            }
        }
    }

    fn spawn_reaper(self: &Arc<Self>) {
        // Buses are built inside the runtime in production; sync unit tests
        // construct them without one, and there is nothing to reap there.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let bus = Arc::downgrade(self);
        let tick = (self.evict_after / 10).clamp(Duration::from_millis(5), Duration::from_secs(1));
        handle.spawn(async move {
            let mut interval = tokio::time::interval(tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match bus.upgrade() {
                    Some(bus) => bus.evict_stalled(),
                    None => return,
                }
            }
        });
    }

    fn snapshot(&self) -> Vec<Arc<Subscriber>> {
        lock(&self.subscribers).clone()
    }

    fn take(&self, id: u64) -> Option<Arc<Subscriber>> {
        let mut guard = lock(&self.subscribers);
        let index = guard.iter().position(|subscriber| subscriber.id == id)?;
        Some(guard.remove(index))
    }

    fn detach(&self, id: u64) {
        lock(&self.subscribers).retain(|subscriber| subscriber.id != id);
    }
}

impl Subscription {
    /// Whether the eviction latch has been set.
    pub fn is_evicted(&self) -> bool {
        *self.evicted.borrow()
    }

    /// The eviction latch, for a driver that must also abandon a blocked send.
    pub fn eviction(&self) -> watch::Receiver<bool> {
        self.evicted.clone()
    }

    /// Attach the process table's terminal cache to this subscription.
    pub fn watch_terminal_cache(&mut self, cache: Arc<Mutex<Option<PumpEvent>>>) {
        self.terminal = Some(cache);
    }

    /// The cached terminal event, if the process already published one.
    pub fn terminal_event(&self) -> Option<PumpEvent> {
        self.terminal.as_ref().and_then(|cache| lock(cache).clone())
    }

    /// Receive the next event. Cancel-safe: dropping the future loses nothing.
    pub async fn recv(&mut self) -> Result<PumpEvent, BusError> {
        match self.rx.recv().await {
            Some(event) => Ok(event),
            None if self.is_evicted() => Err(BusError::Evicted),
            None => Err(BusError::Closed),
        }
    }
}

/// Create the per-connection response queue (data slots plus a terminal slot).
pub fn body_channel() -> (TerminalChannel<bytes::Bytes>, mpsc::Receiver<bytes::Bytes>) {
    TerminalChannel::new(BODY_QUEUE_CAPACITY)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> PumpEvent {
        PumpEvent::DeadlineExceeded
    }

    /// Fast limits so stall and eviction paths run in milliseconds.
    fn bus_with(capacity: usize, evict_after: Duration) -> (Arc<OutputBus>, Subscription) {
        OutputBus::with_limits(capacity, evict_after, MAX_SUBSCRIBERS_PER_PROCESS)
    }

    #[tokio::test]
    async fn publish_data_reaches_every_subscriber() {
        let (bus, mut first) = OutputBus::new();
        let mut second = bus.subscribe().unwrap();
        assert_eq!(bus.subscriber_count(), 2);
        bus.publish_data(event()).await;
        assert!(first.recv().await.is_ok());
        assert!(second.recv().await.is_ok());
    }

    #[tokio::test]
    async fn dropping_a_subscription_detaches_it_immediately() {
        let (bus, first) = OutputBus::new();
        let second = bus.subscribe().unwrap();
        assert_eq!(bus.subscriber_count(), 2);
        drop(second);
        assert_eq!(bus.subscriber_count(), 1);
        drop(first);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn closed_bus_reports_closed() {
        let (bus, mut subscription) = OutputBus::new();
        drop(bus);
        assert!(matches!(subscription.recv().await, Err(BusError::Closed)));
    }

    #[tokio::test]
    async fn cached_event_subscription_yields_once_then_closes() {
        let mut subscription = OutputBus::subscription_from_event(event());
        assert!(subscription.recv().await.is_ok());
        assert!(matches!(subscription.recv().await, Err(BusError::Closed)));
    }

    #[tokio::test]
    async fn data_never_consumes_the_reserved_terminal_slot() {
        let (bus, mut subscription) = bus_with(2, Duration::from_secs(60));
        // Two data events: one fills the only data slot, the other waits.
        let sender = tokio::spawn({
            let bus = Arc::clone(&bus);
            async move {
                bus.publish_data(event()).await;
                bus.publish_data(event()).await;
            }
        });
        // The terminal frame fits anyway: its slot was never a data slot.
        assert!(bus.publish_terminal(event()));
        assert!(subscription.recv().await.is_ok(), "data event");
        assert!(subscription.recv().await.is_ok(), "terminal event");
        sender.abort();
    }

    #[tokio::test]
    async fn slow_subscriber_is_backpressured_not_dropped() {
        let (bus, mut subscription) = bus_with(2, Duration::from_secs(60));
        let publisher = tokio::spawn({
            let bus = Arc::clone(&bus);
            async move {
                for _ in 0..5 {
                    bus.publish_data(event()).await;
                }
            }
        });
        // The publisher can only get one event ahead of this reader.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!publisher.is_finished(), "publisher must wait for room");
        for _ in 0..5 {
            assert!(subscription.recv().await.is_ok());
        }
        tokio::time::timeout(Duration::from_secs(1), publisher)
            .await
            .expect("publisher resumed once the subscriber drained")
            .unwrap();
    }

    #[tokio::test]
    async fn stalled_but_connected_subscriber_is_evicted() {
        // Capacity 2 with one reserved ⇒ one data slot. The subscriber never
        // reads, so the second publish waits and must be broken by the reaper.
        let (bus, subscription) = bus_with(2, Duration::from_millis(60));
        let publisher = tokio::spawn({
            let bus = Arc::clone(&bus);
            async move {
                bus.publish_data(event()).await;
                bus.publish_data(event()).await;
                "published"
            }
        });
        let outcome = tokio::time::timeout(Duration::from_secs(2), publisher)
            .await
            .expect("a stalled subscriber must not pin the publisher forever")
            .unwrap();
        assert_eq!(outcome, "published");
        assert_eq!(bus.subscriber_count(), 0, "the stalled subscriber is gone");
        assert!(subscription.is_evicted());
    }

    #[tokio::test]
    async fn eviction_does_not_touch_an_idle_subscriber() {
        // Nothing was ever published, so nothing is waiting: passing the clock
        // must not evict a subscriber that is simply idle.
        let (bus, subscription) = bus_with(2, Duration::from_millis(30));
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(bus.subscriber_count(), 1);
        assert!(!subscription.is_evicted());
    }

    #[tokio::test]
    async fn eviction_is_per_subscriber() {
        let (bus, slow) = bus_with(2, Duration::from_millis(60));
        let mut fast = bus.subscribe().unwrap();
        let publisher = tokio::spawn({
            let bus = Arc::clone(&bus);
            async move {
                for _ in 0..8 {
                    bus.publish_data(event()).await;
                }
            }
        });
        // Only the fast subscriber drains; the slow one stalls and is evicted.
        for _ in 0..8 {
            if fast.recv().await.is_err() {
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(2), publisher)
            .await
            .expect("publisher resumes after evicting only the stalled subscriber")
            .unwrap();
        assert!(slow.is_evicted());
        assert!(!fast.is_evicted());
    }

    #[tokio::test]
    async fn publishing_without_subscribers_is_a_no_op() {
        let (bus, first) = OutputBus::new();
        drop(first);
        bus.publish_data(event()).await;
        assert!(!bus.publish_terminal(event()));
        assert!(!bus.publish_control(event()));
    }

    #[tokio::test]
    async fn subscription_limit_is_enforced_per_process() {
        let (bus, _first) =
            OutputBus::with_limits(SUBSCRIBER_QUEUE_CAPACITY, Duration::from_secs(60), 2);
        let _second = bus.subscribe().unwrap();
        assert_eq!(bus.subscribe().unwrap_err(), BusError::TooManySubscribers);
    }

    #[tokio::test]
    async fn terminal_frame_always_fits() {
        let (q, mut body) = body_channel();
        for _ in 0..(BODY_QUEUE_CAPACITY - 1) {
            let permit = q.reserve_data().await.unwrap();
            permit.send(bytes::Bytes::from_static(b"data"));
        }
        assert!(q.send_terminal(bytes::Bytes::from_static(b"end")));
        for _ in 0..BODY_QUEUE_CAPACITY {
            assert!(body.try_recv().is_ok());
        }
        assert!(body.try_recv().is_err());
    }

    // The global counter is process-wide, so an absolute assertion would race
    // with the rest of the suite. Its accounting is exercised implicitly: a
    // missed decrement would exhaust the global limit and fail unrelated tests.
}
