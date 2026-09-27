//! Cross-transport state for the stock eMule TCP/UDP connection test.
//!
//! The tester first opens an eD2k TCP connection and sends `OP_PORTTEST 0x12`.
//! That connection stays associated until a client-UDP `OP_PORTTEST 0x12`
//! arrives; the UDP path then wakes the associated TCP session, which sends the
//! one-byte result `'1'`. This registry carries only a random-free generation
//! id, never a socket or unbounded queue.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::broadcast;

const PORT_TEST_EVENT_CAPACITY: usize = 8;

struct PortTestInner {
    next_id: AtomicU64,
    active_id: AtomicU64,
    events: broadcast::Sender<u64>,
}

/// Cloneable bridge shared by the TCP listener and client-UDP ingress.
#[derive(Clone)]
pub struct PortTestRegistry {
    inner: Arc<PortTestInner>,
}

impl Default for PortTestRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PortTestRegistry {
    #[must_use]
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(PORT_TEST_EVENT_CAPACITY);
        Self {
            inner: Arc::new(PortTestInner {
                next_id: AtomicU64::new(1),
                active_id: AtomicU64::new(0),
                events,
            }),
        }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<u64> {
        self.inner.events.subscribe()
    }

    /// Mark one TCP session as the connection awaiting the UDP half of the
    /// test. A newer test supersedes an abandoned older one.
    pub(crate) fn arm(&self) -> PortTestRegistration {
        let mut id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.active_id.store(id, Ordering::Release);
        PortTestRegistration {
            registry: self.clone(),
            id,
        }
    }

    /// Complete the UDP half and wake the currently associated TCP session.
    /// Returns false when no live TCP test connection is armed.
    pub fn acknowledge_udp_probe(&self) -> bool {
        let id = self.inner.active_id.swap(0, Ordering::AcqRel);
        if id == 0 {
            return false;
        }
        let _ = self.inner.events.send(id);
        true
    }
}

/// RAII ownership of one armed TCP port-test association.
pub(crate) struct PortTestRegistration {
    registry: PortTestRegistry,
    id: u64,
}

impl PortTestRegistration {
    #[must_use]
    pub(crate) fn matches(&self, id: u64) -> bool {
        self.id == id
    }
}

impl Drop for PortTestRegistration {
    fn drop(&mut self) {
        let _ = self.registry.inner.active_id.compare_exchange(
            self.id,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_probe_wakes_only_the_current_tcp_registration_once() {
        let registry = PortTestRegistry::new();
        let mut events = registry.subscribe();
        assert!(!registry.acknowledge_udp_probe());

        let stale = registry.arm();
        let current = registry.arm();
        assert!(registry.acknowledge_udp_probe());
        let id = events.recv().await.unwrap();
        assert!(!stale.matches(id));
        assert!(current.matches(id));
        assert!(!registry.acknowledge_udp_probe());
    }

    #[test]
    fn dropping_registration_disarms_only_its_generation() {
        let registry = PortTestRegistry::new();
        let stale = registry.arm();
        let current = registry.arm();
        drop(stale);
        assert!(registry.acknowledge_udp_probe());
        drop(current);
        assert!(!registry.acknowledge_udp_probe());
    }
}
