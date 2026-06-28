use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Path-free snapshot of the latest Kad shared-file publish loop state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KadPublishDiagnostics {
    pub phase: String,
    pub running: bool,
    pub bootstrapped: bool,
    pub gate_allowed: bool,
    pub gate_block_reason: String,
    pub item_count: usize,
    pub inspected_count: usize,
    pub attempted_files: usize,
    pub file_budget: usize,
    pub in_flight_count: usize,
    pub in_flight_budget: usize,
    pub active_keyword_publishes: usize,
    pub active_source_publishes: usize,
    pub active_notes_publishes: usize,
    pub available_search_permits: usize,
    pub keyword_budget: usize,
    pub source_budget: usize,
    pub notes_budget: usize,
    pub budget_exhausted: bool,
    pub keyword_due_count: usize,
    pub source_due_count: usize,
    pub notes_due_count: usize,
    pub keyword_attempted: usize,
    pub source_attempted: usize,
    pub notes_attempted: usize,
    pub keyword_skipped_by_budget: usize,
    pub source_skipped_by_budget: usize,
    pub notes_skipped_by_budget: usize,
    pub keyword_published: usize,
    pub source_published: usize,
    pub notes_published: usize,
    pub completed_count: usize,
    pub failed_count: usize,
    pub timed_out_count: usize,
    pub busy_count: usize,
    pub keyword_published_total: usize,
    pub source_published_total: usize,
    pub notes_published_total: usize,
    pub keyword_failed: usize,
    pub source_failed: usize,
    pub notes_failed: usize,
    pub keyword_contacts_considered_total: u32,
    pub source_contacts_considered_total: u32,
    pub notes_contacts_considered_total: u32,
    pub keyword_attempted_contacts_total: u32,
    pub source_attempted_contacts_total: u32,
    pub notes_attempted_contacts_total: u32,
    pub keyword_acked_contacts_total: u32,
    pub source_acked_contacts_total: u32,
    pub notes_acked_contacts_total: u32,
    pub keyword_contact_timeouts_total: u32,
    pub source_contact_timeouts_total: u32,
    pub notes_contact_timeouts_total: u32,
    pub keyword_acked_contacts: u32,
    pub source_acked_contacts: u32,
    pub notes_acked_contacts: u32,
    pub tick_secs: u64,
    pub updated_at_ms: i64,
}

impl Default for KadPublishDiagnostics {
    fn default() -> Self {
        Self {
            phase: "idle".to_string(),
            running: false,
            bootstrapped: false,
            gate_allowed: false,
            gate_block_reason: String::new(),
            item_count: 0,
            inspected_count: 0,
            attempted_files: 0,
            file_budget: 0,
            in_flight_count: 0,
            in_flight_budget: 0,
            active_keyword_publishes: 0,
            active_source_publishes: 0,
            active_notes_publishes: 0,
            available_search_permits: 0,
            keyword_budget: 0,
            source_budget: 0,
            notes_budget: 0,
            budget_exhausted: false,
            keyword_due_count: 0,
            source_due_count: 0,
            notes_due_count: 0,
            keyword_attempted: 0,
            source_attempted: 0,
            notes_attempted: 0,
            keyword_skipped_by_budget: 0,
            source_skipped_by_budget: 0,
            notes_skipped_by_budget: 0,
            keyword_published: 0,
            source_published: 0,
            notes_published: 0,
            completed_count: 0,
            failed_count: 0,
            timed_out_count: 0,
            busy_count: 0,
            keyword_published_total: 0,
            source_published_total: 0,
            notes_published_total: 0,
            keyword_failed: 0,
            source_failed: 0,
            notes_failed: 0,
            keyword_contacts_considered_total: 0,
            source_contacts_considered_total: 0,
            notes_contacts_considered_total: 0,
            keyword_attempted_contacts_total: 0,
            source_attempted_contacts_total: 0,
            notes_attempted_contacts_total: 0,
            keyword_acked_contacts_total: 0,
            source_acked_contacts_total: 0,
            notes_acked_contacts_total: 0,
            keyword_contact_timeouts_total: 0,
            source_contact_timeouts_total: 0,
            notes_contact_timeouts_total: 0,
            keyword_acked_contacts: 0,
            source_acked_contacts: 0,
            notes_acked_contacts: 0,
            tick_secs: 0,
            updated_at_ms: 0,
        }
    }
}

pub(crate) type SharedKadPublishDiagnostics = Arc<Mutex<KadPublishDiagnostics>>;

pub(crate) fn new_shared() -> SharedKadPublishDiagnostics {
    Arc::new(Mutex::new(KadPublishDiagnostics::default()))
}

pub(crate) fn snapshot(diagnostics: &SharedKadPublishDiagnostics) -> KadPublishDiagnostics {
    match diagnostics.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

pub(crate) fn record(
    diagnostics: &SharedKadPublishDiagnostics,
    update: impl FnOnce(&mut KadPublishDiagnostics),
) {
    let mut guard = match diagnostics.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    update(&mut guard);
    guard.updated_at_ms = Utc::now().timestamp_millis();
}
