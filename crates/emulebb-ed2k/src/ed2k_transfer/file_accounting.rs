//! Process-owned per-hash upload counters, independent of serving eligibility.

use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::MetadataFileUploadTotals;
use parking_lot::Mutex;
use std::{fmt, sync::Arc};

use super::{Ed2kSharedEntry, Ed2kTransferRuntime, credit_ledger::ParkedCreditLedger};

/// One scalar accounting snapshot. Session totals end with this runtime;
/// lifetime watermarks include captured events awaiting their SQLite checkpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ed2kFileUploadStatistics {
    pub session_uploaded_bytes: u64,
    pub session_upload_requests: u64,
    pub session_accepted_uploads: u64,
    pub lifetime: MetadataFileUploadTotals,
}

impl Ed2kFileUploadStatistics {
    pub(super) fn observe(&mut self, totals: MetadataFileUploadTotals) {
        self.lifetime.uploaded_bytes = self.lifetime.uploaded_bytes.max(totals.uploaded_bytes);
        self.lifetime.upload_requests = self.lifetime.upload_requests.max(totals.upload_requests);
        self.lifetime.accepted_sessions = self
            .lifetime
            .accepted_sessions
            .max(totals.accepted_sessions);
        self.lifetime.last_requested_at_s = self
            .lifetime
            .last_requested_at_s
            .max(totals.last_requested_at_s);
        self.lifetime.last_uploaded_at_s = self
            .lifetime
            .last_uploaded_at_s
            .max(totals.last_uploaded_at_s);
    }

    pub(super) fn note_bytes(&mut self, bytes: u64, at_s: i64) {
        self.session_uploaded_bytes = self.session_uploaded_bytes.saturating_add(bytes);
        self.lifetime.uploaded_bytes = self.lifetime.uploaded_bytes.saturating_add(bytes);
        self.lifetime.last_uploaded_at_s = self.lifetime.last_uploaded_at_s.max(Some(at_s));
    }

    pub(super) fn note_accept(&mut self) {
        self.session_accepted_uploads = self.session_accepted_uploads.saturating_add(1);
        self.lifetime.accepted_sessions = self.lifetime.accepted_sessions.saturating_add(1);
    }
}

/// A projection handle to the existing accounting ledger. It owns no second
/// counter map and keeps debug output independent of library/credit contents.
#[derive(Clone)]
pub(super) struct SharedFileAccounting(pub(super) Arc<Mutex<ParkedCreditLedger>>);

impl fmt::Debug for SharedFileAccounting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedFileAccounting")
    }
}

pub(super) fn entry_totals(entry: &Ed2kSharedEntry) -> MetadataFileUploadTotals {
    MetadataFileUploadTotals {
        uploaded_bytes: entry.all_time_uploaded_bytes,
        upload_requests: entry.publish.all_time_request_count,
        accepted_sessions: entry.publish.all_time_accept_count,
        last_requested_at_s: entry.publish.last_upload_requested_at_s,
        last_uploaded_at_s: None,
    }
}

impl SharedFileAccounting {
    pub(super) fn project(&self, entry: &mut Ed2kSharedEntry) {
        if entry.compatibility_hint {
            return;
        }
        let Ok(hash) = entry.parsed_hash() else {
            return;
        };
        let stats =
            {
                let mut owner = self.0.lock();
                let stats = owner.file_statistics.entry(hash.0).or_insert_with(|| {
                    Ed2kFileUploadStatistics {
                        lifetime: entry_totals(entry),
                        ..Default::default()
                    }
                });
                stats.observe(entry_totals(entry));
                *stats
            };
        entry.all_time_uploaded_bytes = stats.lifetime.uploaded_bytes;
        entry.publish.all_time_request_count = stats.lifetime.upload_requests;
        entry.publish.all_time_accept_count = stats.lifetime.accepted_sessions;
        entry.publish.session_uploaded_bytes = stats.session_uploaded_bytes;
        entry.publish.session_request_count = stats.session_upload_requests;
        entry.publish.session_accept_count = stats.session_accepted_uploads;
        entry.publish.last_upload_requested_at_s = entry
            .publish
            .last_upload_requested_at_s
            .max(stats.lifetime.last_requested_at_s);
    }
}

impl Ed2kTransferRuntime {
    /// Read process-owned observations without filesystem or SQLite work.
    /// Public views merge their committed metadata observation with
    /// `observe_file_upload_statistics`, including facts absent from serving rows.
    pub fn file_upload_statistics(&self, hash: &Ed2kHash) -> Option<Ed2kFileUploadStatistics> {
        self.parked_credit
            .lock()
            .file_statistics
            .get(&hash.0)
            .copied()
    }

    /// Merge one committed metadata observation with newer captured events.
    pub fn observe_file_upload_statistics(
        &self,
        hash: &Ed2kHash,
        totals: MetadataFileUploadTotals,
    ) -> Ed2kFileUploadStatistics {
        let mut owner = self.parked_credit.lock();
        let stats = owner.file_statistics.entry(hash.0).or_default();
        stats.observe(totals);
        *stats
    }
}
