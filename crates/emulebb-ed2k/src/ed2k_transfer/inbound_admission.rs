//! Inbound-accept admission cap (eMule `CListenSocket::OnAccept` ->
//! `TooManySockets()`): the eD2k TCP listener admits a new inbound peer
//! connection only while the live inbound count is under the concurrent
//! connection cap (`thePrefs.GetMaxConnections()`), and frees the slot on every
//! handler exit path via an RAII guard.
//!
//! Kept in its own module so the connection-admission logic stays within the
//! per-file budget; it operates directly on the parent `Ed2kTransferRuntime`
//! state (a child module sees the parent's private fields).

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use super::Ed2kTransferRuntime;

/// RAII guard for one admitted inbound (accepted) eD2k peer connection. Held by
/// the listener's per-connection handler task; its `Drop` decrements the live
/// inbound-connection counter so the admission slot is freed on EVERY handler
/// exit path (normal return, `?` error, or panic), mirroring the master where a
/// closed client socket no longer counts toward `GetOpenSockets()`.
#[derive(Debug)]
pub struct Ed2kInboundConnectionGuard {
    inbound_connections: Arc<AtomicUsize>,
}

impl Drop for Ed2kInboundConnectionGuard {
    fn drop(&mut self) {
        // Saturating: never wrap below zero even under an unexpected double-drop.
        let mut current = self.inbound_connections.load(Ordering::Acquire);
        while current > 0 {
            match self.inbound_connections.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

impl Ed2kTransferRuntime {
    /// Concurrent-connection cap (eMule `thePrefs.GetMaxConnections()`) read
    /// live from the shared coordinator config, so a preference update applies to
    /// the inbound-accept admission gate too. 0 means unlimited.
    fn concurrent_connection_cap(&self) -> usize {
        self.download_coordinator
            .lock()
            .expect("download coordinator mutex poisoned")
            .config()
            .max_connections
    }

    /// Try to admit one inbound (accepted) eD2k peer connection, mirroring the
    /// master `CListenSocket::OnAccept` -> `TooManySockets()` gate: an inbound
    /// connection is refused once the live inbound count is at/over the
    /// concurrent-connection cap (eMule `GetMaxConnections()`). On success an
    /// [`Ed2kInboundConnectionGuard`] is returned whose `Drop` decrements the
    /// counter, so EVERY handler exit path (return, `?`, panic) releases the
    /// slot. `None` means the listener must close the just-accepted socket.
    #[must_use]
    pub fn try_admit_inbound_connection(&self) -> Option<Ed2kInboundConnectionGuard> {
        let cap = self.concurrent_connection_cap();
        let mut current = self.inbound_connections.load(Ordering::Acquire);
        loop {
            if cap != 0 && current >= cap {
                return None;
            }
            match self.inbound_connections.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Ed2kInboundConnectionGuard {
                        inbound_connections: Arc::clone(&self.inbound_connections),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Live count of inbound eD2k peer connections currently being handled,
    /// exposed for diagnostics / tests.
    #[must_use]
    pub fn inbound_connection_count(&self) -> usize {
        self.inbound_connections.load(Ordering::Acquire)
    }
}
