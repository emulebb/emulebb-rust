//! In-memory parking of peer-credit and file upload-accounting deltas.
//!
//! The upload hot path used to commit TWO SQLite transactions per served
//! 180 K fragment (`add_peer_credit_delta` + `add_file_all_time_uploaded`),
//! and the download flush one more per accepted block — each commit a WAL
//! fsync under `synchronous = FULL`, all through the global connection mutex
//! REST reads also use. eMule keeps these counters in memory (`CClientCredits`
//! / `CKnownFile`) and persists clients.met / known.met on coarse timers and
//! shutdown, never per fragment, so batching here is parity-faithful.
//!
//! Deltas are parked in [`ParkedCreditLedger`] and flushed to SQLite in ONE
//! transaction when an add finds the flush interval elapsed (fire-and-forget
//! on the blocking pool), and synchronously at upload-session release. Reads
//! that feed queue scoring go through the read-through accessors below, so
//! scores always see persisted + parked totals and never lag the parking.
//!
//! The `credit_flush_gate` serializes every drain-and-commit with the credit
//! writes that must observe a settled ledger: the secure-ident verify wipe
//! (parked pre-bind credit must be committed BEFORE the wipe so it is wiped
//! with the rest, eMule `CClientCredits::Verified` anti-theft) and the
//! absolute totals seed. Without the gate an in-flight background flush could
//! re-commit pre-wipe deltas after the wipe.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{MetadataFileUploadDelta, MetadataStore};
use parking_lot::Mutex;

use super::Ed2kTransferRuntime;

/// How long parked deltas may age before an add spawns a background flush.
/// The crash-loss window for these best-effort counters — eMule's own loss
/// window is its clients.met/known.met save timer, measured in minutes.
const PARKED_CREDIT_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Parked per-peer deltas: user hash -> (uploaded, downloaded).
type ParkedPeerDeltas = HashMap<[u8; 16], (u64, u64)>;
/// Parked file-byte and accepted-session deltas keyed by lowercase hex hash.
type ParkedFileDeltas = HashMap<String, ParkedFileCounters>;

#[derive(Debug, Clone, Copy, Default)]
struct ParkedFileCounters {
    uploaded_bytes: u64,
    accepted_sessions: u64,
    last_uploaded_at_s: Option<i64>,
}

#[derive(Debug)]
pub(super) struct ParkedCreditLedger {
    /// Peer user hash -> (uploaded delta, downloaded delta) not yet in SQLite.
    peers: ParkedPeerDeltas,
    /// File hash -> byte and accepted-session deltas not yet in SQLite.
    files: ParkedFileDeltas,
    pub(super) file_statistics: HashMap<[u8; 16], super::file_accounting::Ed2kFileUploadStatistics>,
    last_flush_started: Instant,
}

impl ParkedCreditLedger {
    pub(super) fn new() -> Self {
        Self {
            peers: HashMap::new(),
            files: HashMap::new(),
            file_statistics: HashMap::new(),
            last_flush_started: Instant::now(),
        }
    }

    fn is_empty(&self) -> bool {
        self.peers.is_empty() && self.files.is_empty()
    }

    /// Move every parked delta out for a flush, resetting the interval clock.
    fn drain(&mut self) -> (ParkedPeerDeltas, ParkedFileDeltas) {
        self.last_flush_started = Instant::now();
        (
            std::mem::take(&mut self.peers),
            std::mem::take(&mut self.files),
        )
    }

    /// Merge a failed flush's deltas back so they are retried, never lost.
    fn restore(&mut self, peers: ParkedPeerDeltas, files: ParkedFileDeltas) {
        for (user_hash, (uploaded, downloaded)) in peers {
            let slot = self.peers.entry(user_hash).or_insert((0, 0));
            slot.0 = slot.0.saturating_add(uploaded);
            slot.1 = slot.1.saturating_add(downloaded);
        }
        for (file_hash, delta) in files {
            let slot = self.files.entry(file_hash).or_default();
            slot.uploaded_bytes = slot.uploaded_bytes.saturating_add(delta.uploaded_bytes);
            slot.accepted_sessions = slot
                .accepted_sessions
                .saturating_add(delta.accepted_sessions);
            slot.last_uploaded_at_s = slot.last_uploaded_at_s.max(delta.last_uploaded_at_s);
        }
    }
}

/// Drain the ledger and commit everything in one transaction, restoring the
/// drained deltas on failure. Runs on the blocking pool; the flush gate is
/// held across drain+commit so credit writes that need a settled ledger
/// (secure-ident wipe, absolute seed) can serialize against it.
fn flush_parked_credit_blocking(runtime_parts: &ParkedCreditFlushParts) {
    let _gate = runtime_parts.flush_gate.lock();
    let (peers, files) = {
        let mut ledger = runtime_parts.ledger.lock();
        if ledger.is_empty() {
            return;
        }
        ledger.drain()
    };
    let peer_rows: Vec<(String, u64, u64)> = peers
        .iter()
        .map(|(user_hash, (uploaded, downloaded))| (hex::encode(user_hash), *uploaded, *downloaded))
        .collect();
    let file_rows: Vec<MetadataFileUploadDelta> = files
        .iter()
        .map(|(file_hash, delta)| MetadataFileUploadDelta {
            file_hash: file_hash.clone(),
            uploaded_bytes: delta.uploaded_bytes,
            accepted_sessions: delta.accepted_sessions,
            last_uploaded_at_s: delta.last_uploaded_at_s,
        })
        .collect();
    if let Err(error) = runtime_parts
        .metadata
        .apply_credit_deltas(&peer_rows, &file_rows)
    {
        tracing::warn!("failed to flush parked credit deltas, re-parking: {error:#}");
        runtime_parts.ledger.lock().restore(peers, files);
    }
}

/// The runtime pieces a flush needs, cloneable into blocking-pool tasks.
struct ParkedCreditFlushParts {
    ledger: std::sync::Arc<Mutex<ParkedCreditLedger>>,
    flush_gate: std::sync::Arc<Mutex<()>>,
    metadata: MetadataStore,
}

impl Ed2kTransferRuntime {
    fn parked_credit_flush_parts(&self) -> ParkedCreditFlushParts {
        ParkedCreditFlushParts {
            ledger: std::sync::Arc::clone(&self.parked_credit),
            flush_gate: std::sync::Arc::clone(&self.credit_flush_gate),
            metadata: self.metadata.clone(),
        }
    }

    /// Park a peer-credit delta; spawns a background flush when the interval
    /// elapsed. Replaces the per-fragment/per-block SQLite commit.
    pub(crate) fn add_peer_credit_delta(
        &self,
        user_hash: [u8; 16],
        uploaded_delta: u64,
        downloaded_delta: u64,
    ) -> anyhow::Result<()> {
        if uploaded_delta == 0 && downloaded_delta == 0 {
            return Ok(());
        }
        let flush_due = {
            let mut ledger = self.parked_credit.lock();
            let slot = ledger.peers.entry(user_hash).or_insert((0, 0));
            slot.0 = slot.0.saturating_add(uploaded_delta);
            slot.1 = slot.1.saturating_add(downloaded_delta);
            ledger.last_flush_started.elapsed() >= PARKED_CREDIT_FLUSH_INTERVAL
        };
        if flush_due {
            self.spawn_parked_credit_flush();
        }
        Ok(())
    }

    /// Park a file all-time-uploaded delta (the SQL half of the counter; the
    /// in-memory catalog demand counter keeps its own RUST-PAR-025 parking)
    /// and feed the shared-catalog demand counter exactly as before.
    pub(crate) fn add_file_all_time_uploaded(
        &self,
        file_hash: &Ed2kHash,
        delta: u64,
    ) -> anyhow::Result<()> {
        if delta == 0 {
            return Ok(());
        }
        let flush_due = {
            let mut ledger = self.parked_credit.lock();
            let slot = ledger.files.entry(file_hash.to_string()).or_default();
            slot.uploaded_bytes = slot.uploaded_bytes.saturating_add(delta);
            let at = super::upload::unix_time_s();
            slot.last_uploaded_at_s = slot.last_uploaded_at_s.max(Some(at));
            ledger
                .file_statistics
                .entry(file_hash.0)
                .or_default()
                .note_bytes(delta, at);
            ledger.last_flush_started.elapsed() >= PARKED_CREDIT_FLUSH_INTERVAL
        };
        self.try_publish_file_accounting(file_hash);
        if flush_due {
            self.spawn_parked_credit_flush();
        }
        Ok(())
    }

    /// Park a single accepted-stint event with the existing file-byte batch.
    pub(super) fn park_file_upload_accept(&self, file_hash: &Ed2kHash) {
        let flush_due = {
            let mut ledger = self.parked_credit.lock();
            let slot = ledger.files.entry(file_hash.to_string()).or_default();
            slot.accepted_sessions = slot.accepted_sessions.saturating_add(1);
            ledger
                .file_statistics
                .entry(file_hash.0)
                .or_default()
                .note_accept();
            ledger.last_flush_started.elapsed() >= PARKED_CREDIT_FLUSH_INTERVAL
        };
        if flush_due {
            self.spawn_parked_credit_flush();
        }
    }

    /// Read-through: parked (not yet flushed) deltas for one peer.
    pub(super) fn parked_peer_credit_delta(&self, user_hash: [u8; 16]) -> (u64, u64) {
        self.parked_credit
            .lock()
            .peers
            .get(&user_hash)
            .copied()
            .unwrap_or((0, 0))
    }

    /// Read-through: parked (not yet flushed) uploaded bytes for one file.
    pub(super) fn parked_file_all_time_uploaded(&self, file_hash: &Ed2kHash) -> u64 {
        self.parked_credit
            .lock()
            .files
            .get(&file_hash.to_string())
            .map_or(0, |delta| delta.uploaded_bytes)
    }

    /// Commit any parked pre-bind deltas for this peer and discard them from
    /// the ledger, under the flush gate, so a following credit wipe or
    /// absolute seed observes a settled row (no background flush can re-add
    /// them afterwards). Runs synchronous SQL like the caller it serves.
    pub(super) fn settle_parked_peer_credit(&self, user_hash: [u8; 16]) -> anyhow::Result<()> {
        let _gate = self.credit_flush_gate.lock();
        let parked = self.parked_credit.lock().peers.remove(&user_hash);
        if let Some((uploaded, downloaded)) = parked
            && let Err(error) = self
                .metadata
                .apply_credit_deltas(&[(hex::encode(user_hash), uploaded, downloaded)], &[])
        {
            // WHY: a failed settlement must retain its deltas, merging any
            // additions parked while SQL ran instead of overwriting them.
            self.parked_credit.lock().restore(
                HashMap::from([(user_hash, (uploaded, downloaded))]),
                HashMap::new(),
            );
            return Err(error);
        }
        Ok(())
    }

    /// Drop parked deltas for one peer WITHOUT committing them — for the
    /// absolute totals seed, which would otherwise double-count them on the
    /// next flush.
    pub(super) fn discard_parked_peer_credit(&self, user_hash: [u8; 16]) {
        let _gate = self.credit_flush_gate.lock();
        self.parked_credit.lock().peers.remove(&user_hash);
    }

    /// Fire-and-forget background flush of the whole ledger.
    fn spawn_parked_credit_flush(&self) {
        let parts = self.parked_credit_flush_parts();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || flush_parked_credit_blocking(&parts));
        } else {
            flush_parked_credit_blocking(&parts);
        }
    }

    /// Flush every parked delta and wait for the commit — upload-session
    /// release and tests use this so the tail is durable, mirroring the
    /// catalog counter's release-time flush.
    pub(crate) async fn flush_parked_credit(&self) {
        let parts = self.parked_credit_flush_parts();
        let flush = tokio::task::spawn_blocking(move || flush_parked_credit_blocking(&parts));
        if let Err(error) = flush.await {
            tracing::warn!("parked credit flush task panicked: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_transfer::Ed2kTransferRuntime;
    use crate::paths::unique_test_dir;

    #[test]
    fn failed_peer_settlement_preserves_credit_until_exactly_once_retry_and_reopen() {
        let root = unique_test_dir("ed2k-credit-settlement-failure");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let user = [0x7Cu8; 16];
        runtime.record_peer_credit_totals(user, 100, 200).unwrap();
        runtime.add_peer_credit_delta(user, 1000, 2000).unwrap();
        let database = rusqlite::Connection::open(root.join("metadata.sqlite")).unwrap();
        let stored_row = || {
            database
                .query_row(
                    "SELECT uploaded_bytes, downloaded_bytes, first_seen_at_ms, last_seen_at_ms
                     FROM peers WHERE user_hash = ?1",
                    [user.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .unwrap()
        };
        let before = stored_row();
        database
            .execute_batch(
                "CREATE TRIGGER synthetic_peer_settlement_failure BEFORE INSERT ON peers
             BEGIN SELECT RAISE(ABORT, 'synthetic peer settlement failure'); END;",
            )
            .unwrap();

        let error = runtime.settle_parked_peer_credit(user).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message == "synthetic peer settlement failure"
        ));
        assert_eq!(
            stored_row(),
            before,
            "failed SQL leaves the durable row unchanged"
        );
        assert_eq!(runtime.parked_peer_credit_delta(user), (1000, 2000));
        let visible = runtime.peer_credit_by_hash(user).unwrap().unwrap();
        assert_eq!(
            (visible.uploaded_bytes, visible.downloaded_bytes),
            (1100, 2200)
        );

        // A later add must survive alongside the failed settlement's deltas.
        runtime.add_peer_credit_delta(user, 7, 11).unwrap();
        database
            .execute_batch("DROP TRIGGER synthetic_peer_settlement_failure")
            .unwrap();
        runtime.settle_parked_peer_credit(user).unwrap();
        assert_eq!(runtime.parked_peer_credit_delta(user), (0, 0));
        assert_eq!((stored_row().0, stored_row().1), (1107, 2211));
        runtime.settle_parked_peer_credit(user).unwrap();
        assert_eq!((stored_row().0, stored_row().1), (1107, 2211));
        drop(database);
        drop(runtime);

        let reopened = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let stored = reopened.peer_credit_by_hash(user).unwrap().unwrap();
        assert_eq!(
            (stored.uploaded_bytes, stored.downloaded_bytes),
            (1107, 2211)
        );
        assert_eq!(reopened.parked_peer_credit_delta(user), (0, 0));
    }

    #[test]
    fn failed_settlement_restore_merges_additions_parked_during_sql_with_saturation() {
        let runtime =
            Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-credit-settlement-merge"))
                .unwrap();
        let user = [0x8Du8; 16];
        let other = [0x9Eu8; 16];
        runtime
            .add_peer_credit_delta(user, u64::MAX - 3, 20)
            .unwrap();
        // Model the controlled interleaving while settlement owns the flush
        // gate: SQL has the removed bucket, and producers can still park adds.
        let _gate = runtime.credit_flush_gate.lock();
        let removed = runtime.parked_credit.lock().peers.remove(&user).unwrap();
        runtime.add_peer_credit_delta(user, 10, 30).unwrap();
        runtime.add_peer_credit_delta(other, 7, 11).unwrap();
        runtime
            .parked_credit
            .lock()
            .restore(HashMap::from([(user, removed)]), HashMap::new());
        assert_eq!(runtime.parked_peer_credit_delta(user), (u64::MAX, 50));
        assert_eq!(runtime.parked_peer_credit_delta(other), (7, 11));
    }

    #[tokio::test]
    async fn parked_credit_is_read_through_and_flushes_durably() {
        let root = unique_test_dir("ed2k-credit-ledger");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let user = [0x5Au8; 16];
        runtime.add_peer_credit_delta(user, 1000, 2000).unwrap();

        // Parked but not yet committed: the raw SQL row does not exist, while
        // the read-through accessor already sees the accrued deltas.
        assert_eq!(
            runtime
                .metadata
                .peer_credit_by_hash(&hex::encode(user))
                .unwrap(),
            None,
            "parked deltas must not commit per add"
        );
        let credit = runtime.peer_credit_by_hash(user).unwrap().unwrap();
        assert_eq!(
            (credit.uploaded_bytes, credit.downloaded_bytes),
            (1000, 2000)
        );

        // The explicit flush commits everything in one transaction.
        runtime.flush_parked_credit().await;
        let stored = runtime
            .metadata
            .peer_credit_by_hash(&hex::encode(user))
            .unwrap()
            .unwrap();
        assert_eq!(
            (stored.uploaded_bytes, stored.downloaded_bytes),
            (1000, 2000)
        );
        // The ledger is drained: read-through equals the stored row.
        let credit = runtime.peer_credit_by_hash(user).unwrap().unwrap();
        assert_eq!(
            (credit.uploaded_bytes, credit.downloaded_bytes),
            (1000, 2000)
        );
    }

    #[tokio::test]
    async fn secure_ident_wipe_covers_parked_prebind_credit() {
        // Anti-theft (eMule CClientCredits::Verified): credit accrued before
        // the first key bind is wiped. Parked-but-unflushed deltas must be
        // settled into the row BEFORE the wipe so they are wiped too, never
        // resurrected by a later ledger flush.
        let root = unique_test_dir("ed2k-credit-ledger-wipe");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let user = [0x6Bu8; 16];
        runtime.add_peer_credit_delta(user, 4000, 8000).unwrap();

        let wiped = runtime
            .record_verified_secure_ident(user, &[9u8; 80])
            .unwrap();
        assert!(wiped, "pre-bind parked credit must be wiped");
        runtime.flush_parked_credit().await;
        let stored = runtime
            .metadata
            .peer_credit_by_hash(&hex::encode(user))
            .unwrap()
            .unwrap();
        assert_eq!(
            (stored.uploaded_bytes, stored.downloaded_bytes),
            (1, 1),
            "no parked delta may survive the wipe"
        );
    }
}
