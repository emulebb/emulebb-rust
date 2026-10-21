//! Outbound source-connection admission and lifetime ownership.

use std::{sync::Arc, time::Instant};

use super::{
    Ed2kConnectionBudgetDecision, Ed2kConnectionBudgetDenyReason, Ed2kDownloadCoordinator,
    Ed2kTransferRuntime,
};

/// Linear permit for one admitted outbound source connection.
///
/// The permit is moved into the connection worker. Dropping that worker releases
/// the coordinator slot on every exit path, including cancellation and panic.
#[derive(Debug)]
pub struct Ed2kSourceConnectionPermit {
    coordinator: Arc<parking_lot::Mutex<Ed2kDownloadCoordinator>>,
}

impl Drop for Ed2kSourceConnectionPermit {
    fn drop(&mut self) {
        self.coordinator.lock().release_connection();
    }
}

/// Result of one outbound source-connection admission decision.
#[derive(Debug)]
#[must_use]
pub enum Ed2kSourceConnectionAdmission {
    /// The caller owns a permit that must live for the connection worker.
    Admitted {
        decision: Ed2kConnectionBudgetDecision,
        permit: Ed2kSourceConnectionPermit,
    },
    /// The current coordinator limits rejected the connection.
    Denied {
        decision: Ed2kConnectionBudgetDecision,
    },
}

impl Ed2kSourceConnectionAdmission {
    /// Returns the diagnostic snapshot produced by this admission attempt.
    pub fn decision(&self) -> Ed2kConnectionBudgetDecision {
        match self {
            Self::Admitted { decision, .. } | Self::Denied { decision } => *decision,
        }
    }
}

impl Ed2kTransferRuntime {
    /// Tries to reserve one outbound source-connection slot.
    ///
    /// An admitted result carries the only release authority for the slot. The
    /// caller must move that permit into the connection worker rather than
    /// manually pairing acquire/release calls.
    pub fn try_admit_source_connection(&self) -> Ed2kSourceConnectionAdmission {
        let mut coordinator = self.download_coordinator.lock();
        let config = coordinator.config();
        let active_before = coordinator.active_connections();
        let admitted = coordinator.try_acquire_connection(Instant::now());
        let deny_reason = if admitted {
            None
        } else if config.max_connections != 0 && active_before >= config.max_connections {
            Some(Ed2kConnectionBudgetDenyReason::ConcurrentCap)
        } else {
            Some(Ed2kConnectionBudgetDenyReason::WindowCap)
        };
        let decision = Ed2kConnectionBudgetDecision {
            admitted,
            active_connections: coordinator.active_connections(),
            connection_cap: config.max_connections,
            deny_reason,
        };
        drop(coordinator);

        if admitted {
            Ed2kSourceConnectionAdmission::Admitted {
                decision,
                permit: Ed2kSourceConnectionPermit {
                    coordinator: Arc::clone(&self.download_coordinator),
                },
            }
        } else {
            Ed2kSourceConnectionAdmission::Denied { decision }
        }
    }
}
