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
    pub published_entries: usize,
    pub pending_entries: usize,
    pub next_cursor: usize,
    pub wrapped: bool,
    pub skipped_duplicate_batch: bool,
    pub session_pump_active: bool,
    pub not_connected_count: usize,
    pub no_network_count: usize,
    pub failure_count: usize,
    pub last_error: Option<String>,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub updated_at: Option<i64>,
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
            published_entries: 0,
            pending_entries: 0,
            next_cursor: 0,
            wrapped: false,
            skipped_duplicate_batch: false,
            session_pump_active: false,
            not_connected_count: 0,
            no_network_count: 0,
            failure_count: 0,
            last_error: None,
            last_attempt_at: None,
            last_success_at: None,
            updated_at: None,
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
    guard.updated_at = Some(Utc::now().timestamp());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_diagnostic_calendar_times_are_nullable_seconds_including_epoch_zero() {
        let ed2k = new_shared();
        let initial = serde_json::to_value(snapshot(&ed2k)).unwrap();
        assert!(initial["lastAttemptAt"].is_null());
        assert!(initial["lastSuccessAt"].is_null());
        assert!(initial["updatedAt"].is_null());
        let before = Utc::now().timestamp();
        record(&ed2k, |value| {
            value.last_attempt_at = Some(0);
            value.last_success_at = Some(0);
        });
        let current = serde_json::to_value(snapshot(&ed2k)).unwrap();
        assert_eq!(current["lastAttemptAt"], 0);
        assert_eq!(current["lastSuccessAt"], 0);
        assert!(
            (before..=Utc::now().timestamp()).contains(&current["updatedAt"].as_i64().unwrap())
        );
        let kad = crate::kad_publish_diagnostics::new_shared();
        assert!(serde_json::to_value(crate::kad_publish_diagnostics::snapshot(&kad)).unwrap()["updatedAt"].is_null());
        crate::kad_publish_diagnostics::record(&kad, |_| {});
        let time = crate::kad_publish_diagnostics::snapshot(&kad)
            .updated_at
            .unwrap();
        assert!((before..=Utc::now().timestamp()).contains(&time));
    }
}
