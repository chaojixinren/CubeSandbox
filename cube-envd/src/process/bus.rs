// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-process output bus: one publisher (the pipe/pty pump, plus the
//! supervisor for control events) and one subscription per attached stream
//! (`process.Process/Start`, each `process.Process/Connect`).
//!
//! Contract
//! --------
//! * Exactly one data publisher per process (the pipe pump). A subscriber that
//!   falls behind is reported through [`BusError::Lagged`] and must decide its
//!   own fate (today: end the stream with `resource_exhausted`).
//! * Dropping a [`Subscription`] detaches it immediately, without waiting for
//!   the next publish and without affecting the publisher or other subscribers.
//! * A subscription created before the pump task starts never misses an early
//!   event (see `SpawnedProcess::initial`), matching the old broadcast contract.
//!
//! Scope
//! -----
//! Structure only: capacity and overflow policy are unchanged (bounded queue,
//! overflow reported as a `Lagged` error). The eviction latch a later commit
//! needs is already carried here so the policy change stays local to this
//! module.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{mpsc, watch};

use crate::process::engine::PumpEvent;

/// Historical ring capacity, kept verbatim while the overflow policy is
/// unchanged.
pub(crate) const BUS_CAPACITY: usize = 64;

/// The per-process output bus handle stored on the process entry.
#[derive(Debug)]
pub struct OutputBus {
    subscribers: Mutex<Vec<Arc<Subscriber>>>,
    next_id: AtomicU64,
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    tx: mpsc::Sender<PumpEvent>,
    /// Events dropped because this subscriber's queue was full. Mirrors the
    /// broadcast ring's `Lagged` report; read once by the next `recv`.
    /// Shared with the subscription so both sides see the same counter.
    lagged: Arc<AtomicU64>,
    /// Eviction latch writer. Nothing sets it yet; the policy commit's reaper
    /// does, and carrying it now keeps the subscription plumbing stable.
    #[allow(dead_code, reason = "set by the reaper in the policy commit")]
    evicted: watch::Sender<bool>,
}

/// One attachment's view of the bus. Dropping it detaches immediately.
#[derive(Debug)]
pub struct Subscription {
    bus: Weak<OutputBus>,
    id: u64,
    rx: mpsc::Receiver<PumpEvent>,
    lagged: Arc<AtomicU64>,
    evicted: watch::Receiver<bool>,
}

/// Why a subscription stopped receiving events.
#[derive(Debug, PartialEq, Eq)]
pub enum BusError {
    /// The subscriber fell behind and missed this many events.
    Lagged(u64),
    /// The subscriber was evicted because it made no progress.
    Evicted,
    /// The publisher is gone and no further events will arrive.
    Closed,
}

/// Result of publishing one event.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// At least one subscription was attached. Delivery itself is per
    /// subscriber best effort: a subscriber whose queue is full has the event
    /// dropped for it and is told on its next `recv` (`BusError::Lagged`).
    Published,
    /// Nobody is attached; the caller may skip encoding work.
    NoSubscribers,
}

impl OutputBus {
    /// Create a bus plus the subscription reserved for the first attachment.
    /// The subscription is created before the pump starts so the earliest
    /// events cannot be missed.
    pub fn new() -> (Arc<Self>, Subscription) {
        Self::with_capacity(BUS_CAPACITY)
    }

    /// Same as [`OutputBus::new`] with an explicit capacity. Used by tests that
    /// need the queue to overflow deterministically.
    pub(crate) fn with_capacity(capacity: usize) -> (Arc<Self>, Subscription) {
        let bus = Arc::new(Self {
            subscribers: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        });
        let subscription = bus.attach(capacity);
        (bus, subscription)
    }

    fn attach(self: &Arc<Self>, capacity: usize) -> Subscription {
        let (tx, rx) = mpsc::channel(capacity);
        let (evicted_tx, evicted_rx) = watch::channel(false);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let lagged = Arc::new(AtomicU64::new(0));
        let subscriber = Arc::new(Subscriber {
            id,
            tx,
            lagged: Arc::clone(&lagged),
            evicted: evicted_tx,
        });
        lock(&self.subscribers).push(subscriber);
        Subscription {
            bus: Arc::downgrade(self),
            id,
            rx,
            lagged,
            evicted: evicted_rx,
        }
    }

    /// Attach another subscriber (a later `Connect`).
    pub fn subscribe(self: &Arc<Self>) -> Subscription {
        self.attach(BUS_CAPACITY)
    }

    /// A subscription that yields exactly one cached event and then closes.
    /// Used when a `Connect` arrives after the process terminated and only the
    /// terminal cache remains.
    pub fn subscription_from_event(event: PumpEvent) -> Subscription {
        let (tx, rx) = mpsc::channel(1);
        // Cannot block or fail: the channel is fresh and we keep the receiver.
        let _ = tx.try_send(event);
        let (evicted_tx, evicted_rx) = watch::channel(false);
        drop(evicted_tx);
        Subscription {
            bus: Weak::new(),
            id: 0,
            rx,
            lagged: Arc::new(AtomicU64::new(0)),
            evicted: evicted_rx,
        }
    }

    /// How many attachments are currently attached.
    pub fn subscriber_count(&self) -> usize {
        lock(&self.subscribers).len()
    }

    /// Publish one event to every attached subscriber. Non-blocking by
    /// contract: a subscriber whose queue is full has the event dropped for it
    /// and is told on its next `recv` (`BusError::Lagged`), mirroring the
    /// broadcast ring's overflow report.
    pub fn publish(&self, event: PumpEvent) -> PublishOutcome {
        let subscribers = self.snapshot();
        if subscribers.is_empty() {
            return PublishOutcome::NoSubscribers;
        }
        let mut closed = Vec::new();
        for subscriber in &subscribers {
            match subscriber.tx.try_send(event.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    subscriber.lagged.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => closed.push(subscriber.id),
            }
        }
        for id in closed {
            self.detach(id);
        }
        PublishOutcome::Published
    }

    fn snapshot(&self) -> Vec<Arc<Subscriber>> {
        lock(&self.subscribers).clone()
    }

    fn detach(&self, id: u64) {
        lock(&self.subscribers).retain(|subscriber| subscriber.id != id);
    }
}

impl Subscription {
    /// Detach this subscription. Called by `Drop`; also usable explicitly.
    pub fn detach(&self) {
        if let Some(bus) = self.bus.upgrade() {
            bus.detach(self.id);
        }
    }

    /// Whether the eviction latch has been set (set by the policy commit).
    pub fn is_evicted(&self) -> bool {
        *self.evicted.borrow()
    }

    /// Receive the next event. Cancel-safe: dropping the future loses nothing.
    pub async fn recv(&mut self) -> Result<PumpEvent, BusError> {
        let dropped = self.lagged.swap(0, Ordering::Acquire);
        if dropped > 0 {
            return Err(BusError::Lagged(dropped));
        }
        match self.rx.recv().await {
            Some(event) => Ok(event),
            None if self.is_evicted() => Err(BusError::Evicted),
            None => Err(BusError::Closed),
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.detach();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A transport event selected by the stream driver; service-specific payloads
/// and error policy stay opaque to the bus.
pub(crate) enum Delivery {
    Event(Result<PumpEvent, BusError>),
    Disconnected,
    Keepalive,
    Deadline,
}

/// Select the next subscription event, keepalive tick, deadline or client
/// disconnect without waiting for HTTP queue capacity. Returning
/// [`Delivery::Disconnected`] lets the caller immediately drop its
/// subscription and other attachment resources.
pub(crate) async fn next_delivery(
    events: &mut Subscription,
    output: &mpsc::Sender<bytes::Bytes>,
    keepalive: &mut tokio::time::Interval,
    deadline: impl std::future::Future<Output = ()>,
    deadline_enabled: bool,
) -> Delivery {
    tokio::select! {
        _ = output.closed() => Delivery::Disconnected,
        event = events.recv() => Delivery::Event(event),
        _ = keepalive.tick() => Delivery::Keepalive,
        _ = deadline, if deadline_enabled => Delivery::Deadline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> PumpEvent {
        PumpEvent::DeadlineExceeded
    }

    #[tokio::test]
    async fn publish_reaches_every_subscriber() {
        let (bus, mut first) = OutputBus::new();
        let mut second = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        assert_eq!(bus.publish(event()), PublishOutcome::Published);
        assert!(first.recv().await.is_ok());
        assert!(second.recv().await.is_ok());
    }

    #[tokio::test]
    async fn publish_without_subscribers_reports_it() {
        let (bus, first) = OutputBus::new();
        drop(first);
        assert_eq!(bus.publish(event()), PublishOutcome::NoSubscribers);
    }

    #[tokio::test]
    async fn slow_subscriber_is_told_it_lagged_and_keeps_reading() {
        let (bus, mut slow) = OutputBus::new();
        for _ in 0..(BUS_CAPACITY + 3) {
            bus.publish(event());
        }
        // The queue holds BUS_CAPACITY events; the overflow is reported once.
        assert!(matches!(slow.recv().await, Err(BusError::Lagged(3))));
        // Events that did fit are still delivered after the lag report.
        assert!(slow.recv().await.is_ok());
    }

    #[tokio::test]
    async fn dropping_a_subscription_detaches_it_immediately() {
        let (bus, first) = OutputBus::new();
        let second = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        drop(second);
        // No publish in between: detaching must not wait for one.
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
    async fn next_delivery_reports_disconnect_when_the_body_is_gone() {
        let (_bus, mut subscription) = OutputBus::new();
        let (tx, rx) = mpsc::channel::<bytes::Bytes>(4);
        drop(rx);
        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(60));
        let delivery = next_delivery(
            &mut subscription,
            &tx,
            &mut keepalive,
            std::future::pending::<()>(),
            false,
        )
        .await;
        assert!(matches!(delivery, Delivery::Disconnected));
    }

    #[tokio::test]
    async fn delivery_reports_lag_then_delivers_then_closes() {
        // Capacity 1 so the second publish overflows, like the broadcast ring did.
        let (bus, mut events) = OutputBus::with_capacity(1);
        let (output, _body) = mpsc::channel::<bytes::Bytes>(4);
        let mut interval = quiet_interval();
        assert_eq!(bus.publish(event()), PublishOutcome::Published);
        assert_eq!(bus.publish(event()), PublishOutcome::Published);
        assert!(matches!(
            next_delivery(
                &mut events,
                &output,
                &mut interval,
                std::future::pending(),
                true
            )
            .await,
            Delivery::Event(Err(BusError::Lagged(1)))
        ));
        assert!(matches!(
            next_delivery(
                &mut events,
                &output,
                &mut interval,
                std::future::pending(),
                true
            )
            .await,
            Delivery::Event(Ok(_))
        ));
        drop(bus);
        assert!(matches!(
            next_delivery(
                &mut events,
                &output,
                &mut interval,
                std::future::pending(),
                true
            )
            .await,
            Delivery::Event(Err(BusError::Closed))
        ));
    }

    #[tokio::test]
    async fn body_disconnect_wakes_idle_driver_and_releases_subscription() {
        let (bus, events) = OutputBus::new();
        let (output, body) = mpsc::channel::<bytes::Bytes>(4);
        let driver = tokio::spawn(async move {
            let mut events = events;
            let mut interval = quiet_interval();
            assert!(matches!(
                next_delivery(
                    &mut events,
                    &output,
                    &mut interval,
                    std::future::pending(),
                    true
                )
                .await,
                Delivery::Disconnected
            ));
        });
        drop(body);
        tokio::time::timeout(std::time::Duration::from_secs(1), driver)
            .await
            .expect("idle attachment retained after body drop")
            .unwrap();
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn delivery_preserves_keepalive_and_deadline_gating() {
        let (bus, mut events) = OutputBus::new();
        let (output, _body) = mpsc::channel::<bytes::Bytes>(4);
        // An interval's initial tick is ready without waiting on wall-clock time.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        assert!(matches!(
            next_delivery(
                &mut events,
                &output,
                &mut interval,
                std::future::pending(),
                true
            )
            .await,
            Delivery::Keepalive
        ));
        interval.reset();
        assert!(matches!(
            next_delivery(
                &mut events,
                &output,
                &mut interval,
                std::future::ready(()),
                true
            )
            .await,
            Delivery::Deadline
        ));
        bus.publish(event());
        assert!(matches!(
            next_delivery(
                &mut events,
                &output,
                &mut interval,
                std::future::ready(()),
                false
            )
            .await,
            Delivery::Event(Ok(_))
        ));
    }

    fn quiet_interval() -> tokio::time::Interval {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.reset();
        interval
    }
}
