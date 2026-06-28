use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Path-free snapshot of the queued ED2K shared-catalog advertisement worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed2kPublishDiagnostics {
    pub phase: String,
    pub running: bool,
    pub dirty: bool,
    pub queued_count: usize,
    pub entries_sent: usize,
    pub total_entries: usize,
    pub next_cursor: usize,
    pub wrapped: bool,
    pub skipped_duplicate_batch: bool,
    pub not_connected_count: usize,
    pub no_network_count: usize,
    pub failure_count: usize,
    pub last_error: Option<String>,
    pub last_attempt_at_ms: i64,
    pub last_success_at_ms: i64,
    pub updated_at_ms: i64,
}

impl Default for Ed2kPublishDiagnostics {
    fn default() -> Self {
        Self {
            phase: "idle".to_string(),
            running: false,
            dirty: false,
            queued_count: 0,
            entries_sent: 0,
            total_entries: 0,
            next_cursor: 0,
            wrapped: false,
            skipped_duplicate_batch: false,
            not_connected_count: 0,
            no_network_count: 0,
            failure_count: 0,
            last_error: None,
            last_attempt_at_ms: 0,
            last_success_at_ms: 0,
            updated_at_ms: 0,
        }
    }
}

pub(crate) type SharedEd2kPublishDiagnostics = Arc<Mutex<Ed2kPublishDiagnostics>>;

pub(crate) fn new_shared() -> SharedEd2kPublishDiagnostics {
    Arc::new(Mutex::new(Ed2kPublishDiagnostics::default()))
}

pub(crate) fn snapshot(diagnostics: &SharedEd2kPublishDiagnostics) -> Ed2kPublishDiagnostics {
    match diagnostics.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

pub(crate) fn record(
    diagnostics: &SharedEd2kPublishDiagnostics,
    update: impl FnOnce(&mut Ed2kPublishDiagnostics),
) {
    let mut guard = match diagnostics.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    update(&mut guard);
    guard.updated_at_ms = Utc::now().timestamp_millis();
}
