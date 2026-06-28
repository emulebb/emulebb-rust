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
    pub budget_exhausted: bool,
    pub keyword_due_count: usize,
    pub source_due_count: usize,
    pub notes_due_count: usize,
    pub keyword_published: usize,
    pub source_published: usize,
    pub notes_published: usize,
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
            budget_exhausted: false,
            keyword_due_count: 0,
            source_due_count: 0,
            notes_due_count: 0,
            keyword_published: 0,
            source_published: 0,
            notes_published: 0,
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
