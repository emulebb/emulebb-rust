//! Initial REST network-status projections used while runtime state is absent
//! or a network start operation is still queued.

use crate::{NetworkStatus, kad_status_from_running};

pub(super) fn ed2k_stopped_status() -> NetworkStatus {
    NetworkStatus {
        running: false,
        connected: false,
        peer_count: 0,
        firewalled: None,
        bootstrapping: None,
        bootstrap_progress: None,
        contact_count: None,
        lan_mode: None,
        users: None,
        files: None,
        indexed_sources: None,
        indexed_keywords: None,
        operation_queued: None,
        already_running: None,
    }
}

pub(super) fn ed2k_starting_status() -> NetworkStatus {
    NetworkStatus {
        running: true,
        connected: false,
        peer_count: 0,
        firewalled: None,
        bootstrapping: Some(true),
        bootstrap_progress: Some(0),
        contact_count: None,
        lan_mode: None,
        users: None,
        files: None,
        indexed_sources: None,
        indexed_keywords: None,
        operation_queued: Some(true),
        already_running: None,
    }
}

pub(super) fn kad_starting_status(manual_running: bool) -> NetworkStatus {
    let mut status = kad_status_from_running(manual_running);
    if manual_running {
        status.operation_queued = Some(true);
    }
    status
}
