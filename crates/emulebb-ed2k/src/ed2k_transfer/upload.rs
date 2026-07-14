//! Runtime-facing upload queue methods.

use std::{
    sync::atomic::Ordering,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::MetadataPeerCredit;

use crate::config::Ed2kUploadQueueRuntimeConfig;

use super::{
    Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadQueueCapacitySnapshot,
    Ed2kUploadQueueSnapshotEntry, Ed2kUploadRangeAdmission, Ed2kUploadSessionHandle,
    Ed2kUploadSessionStatus, Ed2kUploadThrottleReservation,
    upload_queue::{DEFAULT_CREDIT_SCORE_PERMILLE, credit_score_permille, upload_priority_score},
    upload_queue_config_from_policy, upload_queue_policy_from_config,
};

impl Ed2kTransferRuntime {
    /// Apply inbound uploader queue policy to the live runtime.
    pub async fn apply_upload_queue_policy(&self, policy: &Ed2kUploadQueueRuntimeConfig) {
        self.upload_queue
            .lock()
            .await
            .configure(upload_queue_config_from_policy(policy));
    }

    /// Return the currently active inbound uploader queue policy.
    pub async fn upload_queue_policy_snapshot(&self) -> Ed2kUploadQueueRuntimeConfig {
        upload_queue_policy_from_config(self.upload_queue.lock().await.config())
    }

    /// Return the current rate-aware upload slot capacity state.
    pub async fn upload_queue_capacity_snapshot(&self) -> Ed2kUploadQueueCapacitySnapshot {
        self.upload_queue
            .lock()
            .await
            .capacity_snapshot(Instant::now())
    }

    /// Override inbound uploader queue policy for controlled scenarios and tests.
    #[cfg(test)]
    pub(crate) async fn configure_upload_queue(&self, config: super::Ed2kUploadQueueConfig) {
        self.upload_queue.lock().await.configure(config);
    }

    /// Admit or refresh one inbound uploader session and return the queue-visible state.
    pub(crate) async fn begin_upload_session(
        &self,
        peer: Ed2kUploadPeerIdentity,
        file_hash: &Ed2kHash,
    ) -> (Ed2kUploadSessionHandle, Ed2kUploadSessionStatus) {
        self.begin_upload_session_at(peer, file_hash, Instant::now())
            .await
    }

    /// Records a peer (re)starting an upload session for a file, returning the
    /// repeat count when the same `(peer, file)` restarted within the churn window
    /// (MFC repeat_file_request parity). `peer_key` is the peer user-hash hex when
    /// known, else its IP -- matching the master PeerBehaviorKey fallback. Bounded
    /// and window-pruned so it cannot grow without bound.
    pub(crate) fn record_upload_file_churn(&self, peer_key: &str, file_hash: &str) -> Option<u32> {
        const MAX_ENTRIES: usize = 4096;
        let window = std::time::Duration::from_secs(super::diag_bad_peer::REPEAT_FILE_WINDOW_SECS);
        let now = Instant::now();
        let mut ledger = self.upload_file_churn.lock().unwrap();
        ledger.retain(|_, (_, first)| now.duration_since(*first) < window);
        let key = (peer_key.to_string(), file_hash.to_string());
        if !ledger.contains_key(&key) && ledger.len() >= MAX_ENTRIES {
            return None;
        }
        let entry = ledger.entry(key).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        (entry.0 > 1).then_some(entry.0)
    }

    pub(crate) async fn begin_upload_session_at(
        &self,
        peer: Ed2kUploadPeerIdentity,
        file_hash: &Ed2kHash,
        now: Instant,
    ) -> (Ed2kUploadSessionHandle, Ed2kUploadSessionStatus) {
        let connection_id = self
            .next_upload_connection_id
            .fetch_add(1, Ordering::Relaxed);
        let credit_score_permille = self.peer_credit_score_permille(&peer);
        // MFC repeat_file_request parity: surface a peer that keeps (re)starting an
        // upload session for the same file (same-file churn, e.g. dropping and
        // reconnecting). Observe-only; the session proceeds regardless.
        {
            let peer_key = match peer.user_hash {
                Some(hash) => hex::encode(hash),
                None => peer.ip.to_string(),
            };
            let file_hex = file_hash.to_string();
            if let Some(repeat) = self.record_upload_file_churn(&peer_key, &file_hex) {
                super::diag_bad_peer::repeat_file_request(
                    &format!("{}:{}", peer.ip, peer.tcp_port),
                    peer.user_hash,
                    &file_hex,
                    repeat,
                );
            }
        }
        let handle = Ed2kUploadSessionHandle::new(peer, file_hash.to_string(), connection_id);
        let all_time_upload_ratio_permille = self.file_all_time_upload_ratio_permille(file_hash);
        let file_size = self.shared_file_size(file_hash);
        // Resolve an auto-upload-priority file's dynamic tier from its live queue
        // depth (oracle GetQueuedCount, KnownFile.cpp:1382-1387). Read the count
        // in a short lock, released before the blocking manifest read.
        let queued_count = self
            .upload_queue
            .lock()
            .await
            .upload_client_count_for_file(&file_hash.to_string());
        let file_priority_score = self.file_priority_score(file_hash, queued_count);
        let status = self.upload_queue.lock().await.begin_session(
            handle.key().clone(),
            connection_id,
            now,
            file_priority_score,
            credit_score_permille,
            all_time_upload_ratio_permille,
            file_size,
        );
        (handle, status)
    }

    /// Purge upload-queue waiters whose requested file is no longer shared
    /// (master `FindBestClientInQueue` waiting-list walk, UploadQueue.cpp:223
    /// `!GetFileByID(client->GetUploadFileID())`). Driven from the upload
    /// maintenance tick. A file is still shared when a servable catalog entry
    /// exists for its hash (`is_servable`, the same gate the reask/serve path
    /// consults); a bare compatibility hint is not servable and never keeps a
    /// waiter alive. Returns the number of purged waiters.
    pub(crate) async fn purge_unshared_upload_waiters(&self) -> usize {
        let shared_file_hashes = self.servable_shared_file_hashes().await;
        self.upload_queue
            .lock()
            .await
            .purge_waiters_for_unshared_files(&shared_file_hashes)
    }

    async fn servable_shared_file_hashes(
        &self,
    ) -> std::sync::Arc<std::collections::HashSet<String>> {
        loop {
            let generation = self
                .shared_catalog_generation
                .load(std::sync::atomic::Ordering::Acquire);
            if let Some(hashes) = {
                let cache = self.servable_shared_hash_cache.lock().unwrap();
                (cache.generation == generation)
                    .then(|| cache.hashes.as_ref().map(std::sync::Arc::clone))
                    .flatten()
            } {
                return hashes;
            }

            let hashes = {
                let catalog = self.shared_catalog.read().await;
                catalog
                    .iter()
                    .filter(|entry| entry.is_servable())
                    .map(|entry| entry.file_hash.to_ascii_lowercase())
                    .collect::<std::collections::HashSet<_>>()
            };
            let current_generation = self
                .shared_catalog_generation
                .load(std::sync::atomic::Ordering::Acquire);
            if current_generation != generation {
                continue;
            }
            let hashes = std::sync::Arc::new(hashes);
            let mut cache = self.servable_shared_hash_cache.lock().unwrap();
            if cache.generation == current_generation
                && let Some(cached) = cache.hashes.as_ref()
            {
                return std::sync::Arc::clone(cached);
            }
            cache.generation = current_generation;
            cache.hashes = Some(std::sync::Arc::clone(&hashes));
            return hashes;
        }
    }

    /// Poll the current queue-visible state for one upload session.
    pub(crate) async fn poll_upload_session(
        &self,
        handle: &Ed2kUploadSessionHandle,
        refresh_activity: bool,
    ) -> Ed2kUploadSessionStatus {
        self.poll_upload_session_at(handle, refresh_activity, Instant::now())
            .await
    }

    pub(crate) async fn poll_upload_session_at(
        &self,
        handle: &Ed2kUploadSessionHandle,
        refresh_activity: bool,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.upload_queue
            .lock()
            .await
            .poll_session(handle, now, refresh_activity)
    }

    /// Mark a part request as activity and return whether the peer may receive data.
    pub(crate) async fn note_upload_request_parts(
        &self,
        handle: &Ed2kUploadSessionHandle,
    ) -> Ed2kUploadSessionStatus {
        self.upload_queue
            .lock()
            .await
            .note_request_parts(handle, Instant::now())
    }

    /// RUST-PAR-021 GAP4: a cooled queued peer that sends a valid OP_REQUESTPARTS
    /// block request clears its retry/slow/no-request upload cooldown once per
    /// window (oracle ClearUploadRetryCooldown via AddReqBlock). Returns whether a
    /// cooldown was cleared.
    pub(crate) async fn note_queued_upload_block_request(
        &self,
        peer: &Ed2kUploadPeerIdentity,
    ) -> bool {
        self.upload_queue
            .lock()
            .await
            .note_queued_block_request(peer, Instant::now())
    }

    pub(crate) async fn note_upload_range_request(
        &self,
        handle: &Ed2kUploadSessionHandle,
        start: u64,
        end: u64,
    ) -> (Ed2kUploadSessionStatus, Ed2kUploadRangeAdmission) {
        self.note_upload_range_request_at(handle, start, end, Instant::now())
            .await
    }

    pub(crate) async fn note_upload_range_request_at(
        &self,
        handle: &Ed2kUploadSessionHandle,
        start: u64,
        end: u64,
        now: Instant,
    ) -> (Ed2kUploadSessionStatus, Ed2kUploadRangeAdmission) {
        self.upload_queue
            .lock()
            .await
            .note_requested_range(handle, start, end, now)
    }

    pub(crate) async fn note_upload_range_served(
        &self,
        handle: &Ed2kUploadSessionHandle,
        start: u64,
        end: u64,
    ) -> Ed2kUploadSessionStatus {
        self.note_upload_range_served_at(handle, start, end, Instant::now())
            .await
    }

    pub(crate) async fn note_upload_range_served_at(
        &self,
        handle: &Ed2kUploadSessionHandle,
        start: u64,
        end: u64,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.upload_queue
            .lock()
            .await
            .note_served_range(handle, start, end, now)
    }

    /// Record one inbound OP_REQUESTPARTS demand signal for a shared file.
    pub(crate) async fn note_file_upload_request(&self, file_hash: &Ed2kHash) {
        let now = unix_time_ms();
        let _ = self
            .metadata
            .add_file_upload_request(&file_hash.to_string(), now);
        self.update_shared_publish_stats(file_hash, |entry| {
            entry.publish.session_request_count =
                entry.publish.session_request_count.saturating_add(1);
            entry.publish.all_time_request_count =
                entry.publish.all_time_request_count.saturating_add(1);
            entry.publish.last_request_unix_ms = entry.publish.last_request_unix_ms.max(now);
        })
        .await;
        self.notify_shared_publish_demand_changed();
    }

    /// Record one accepted upload request for a shared file.
    pub(crate) async fn note_file_upload_accept(&self, file_hash: &Ed2kHash) {
        let _ = self.metadata.add_file_upload_accept(&file_hash.to_string());
        self.update_shared_publish_stats(file_hash, |entry| {
            entry.publish.session_accept_count =
                entry.publish.session_accept_count.saturating_add(1);
            entry.publish.all_time_accept_count =
                entry.publish.all_time_accept_count.saturating_add(1);
        })
        .await;
        self.notify_shared_publish_demand_changed();
    }

    pub(crate) async fn note_upload_payload_sent(
        &self,
        handle: &Ed2kUploadSessionHandle,
        byte_count: u64,
    ) -> Ed2kUploadSessionStatus {
        self.note_upload_payload_sent_at(handle, byte_count, Instant::now())
            .await
    }

    pub(crate) async fn note_upload_payload_sent_at(
        &self,
        handle: &Ed2kUploadSessionHandle,
        byte_count: u64,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.note_session_uploaded_bytes(byte_count);
        self.upload_queue
            .lock()
            .await
            .note_uploaded_bytes(handle, byte_count, now)
    }

    pub(crate) async fn reserve_upload_payload_budget(
        &self,
        byte_count: u64,
    ) -> Ed2kUploadThrottleReservation {
        self.reserve_upload_payload_budget_at(byte_count, Instant::now())
            .await
    }

    pub(crate) async fn reserve_upload_payload_budget_at(
        &self,
        byte_count: u64,
        now: Instant,
    ) -> Ed2kUploadThrottleReservation {
        self.upload_queue
            .lock()
            .await
            .reserve_upload_payload(byte_count, now)
    }

    /// Release one upload session after disconnect or explicit cancel: an
    /// active slot is freed, while a WAITING entry survives with its wait-start
    /// time (master keeps US_ONUPLOADQUEUE clients on disconnect,
    /// BaseClient.cpp:1229) and ages out on the waiting timeout.
    pub(crate) async fn release_upload_session(&self, handle: &Ed2kUploadSessionHandle) {
        self.upload_queue
            .lock()
            .await
            .release_session(handle, Instant::now());
        // Drain any demand-upload bytes a contended per-fragment `try_write` left
        // parked for this file (RUST-PAR-025 Note-1). Session release is off the
        // hot path, so this final flush may block briefly on the catalog write lock
        // to guarantee the tail is credited rather than orphaned.
        if let Ok(file_hash) = handle.file_hash_hex().parse::<Ed2kHash>() {
            self.flush_pending_catalog_upload(&file_hash).await;
        }
        // Same rationale for the parked credit/all-time counters: session
        // release is off the hot path, so commit the tail durably here rather
        // than leaving it to the next interval flush.
        self.flush_parked_credit().await;
    }

    /// Seed the upload churn cooldown for a promoted waiter whose outbound
    /// promote-connect could not be established (RUST-PAR-020 U-GAP3: the fork's
    /// failed-admission / no-socket removal, UploadQueue.cpp:330-339,841-856).
    /// Called from the promote-connect driver's failure path.
    pub(crate) async fn note_failed_upload_promotion(&self, peer: &Ed2kUploadPeerIdentity) {
        self.upload_queue
            .lock()
            .await
            .note_failed_promotion(peer, Instant::now());
    }

    /// Drain the granted-but-disconnected waiter promotions that need an
    /// outbound connect + OP_ACCEPTUPLOADREQ (master `AddUpNextClient`,
    /// UploadQueue.cpp:327-361). Each grant is rebound to a fresh connection id
    /// owned by the promote-connect driver.
    pub(crate) async fn take_pending_upload_promotions(
        &self,
    ) -> Vec<super::Ed2kUploadPendingPromotion> {
        self.upload_queue.lock().await.take_pending_promotions(|| {
            self.next_upload_connection_id
                .fetch_add(1, Ordering::Relaxed)
        })
    }

    /// Release one queue-visible upload client selected from REST management state.
    pub async fn release_upload_client(&self, client_id: &str, waiting_queue: bool) -> bool {
        self.upload_queue
            .lock()
            .await
            .release_client(client_id, waiting_queue, Instant::now())
    }

    /// Return a management snapshot of active and waiting inbound upload sessions.
    pub async fn upload_queue_snapshot(&self) -> Vec<Ed2kUploadQueueSnapshotEntry> {
        self.upload_queue.lock().await.snapshot(Instant::now())
    }

    pub(crate) fn record_peer_credit_totals(
        &self,
        user_hash: [u8; 16],
        uploaded_bytes: u64,
        downloaded_bytes: u64,
    ) -> anyhow::Result<()> {
        // Absolute seed: parked deltas would be double-counted on their next
        // flush after the totals below overwrite the row, so drop them.
        self.discard_parked_peer_credit(user_hash);
        self.metadata.upsert_peer_credit(&MetadataPeerCredit {
            user_hash: hex::encode(user_hash),
            uploaded_bytes,
            downloaded_bytes,
        })
    }

    /// Persisted + parked credit totals for one peer (read-through over the
    /// parked ledger, so accrued-but-unflushed bytes are always visible).
    #[cfg(test)]
    pub(crate) fn peer_credit_by_hash(
        &self,
        user_hash: [u8; 16],
    ) -> anyhow::Result<Option<MetadataPeerCredit>> {
        let stored = self.metadata.peer_credit_by_hash(&hex::encode(user_hash))?;
        let (parked_uploaded, parked_downloaded) = self.parked_peer_credit_delta(user_hash);
        if stored.is_none() && parked_uploaded == 0 && parked_downloaded == 0 {
            return Ok(None);
        }
        let stored = stored.unwrap_or(MetadataPeerCredit {
            user_hash: hex::encode(user_hash),
            uploaded_bytes: 0,
            downloaded_bytes: 0,
        });
        Ok(Some(MetadataPeerCredit {
            user_hash: stored.user_hash,
            uploaded_bytes: stored.uploaded_bytes.saturating_add(parked_uploaded),
            downloaded_bytes: stored.downloaded_bytes.saturating_add(parked_downloaded),
        }))
    }

    /// Prune peer credit rows last seen more than 150 days ago (eMule
    /// `CClientCreditsList::LoadList` credit aging). Returns the number pruned.
    pub fn prune_aged_peer_credits(&self) -> anyhow::Result<usize> {
        self.metadata.prune_aged_peers()
    }

    /// Bind a verified secure-ident public key to the peer's credit row,
    /// wiping its credits if a DIFFERENT key verified for the same user hash
    /// before (eMule `CClientCredits::Verified` anti-takeover, ClientCredits.cpp
    /// :338-356). Called from the secure-ident verify paths (upload listener +
    /// download identity verify). Returns `true` when credits were wiped.
    pub(crate) fn record_verified_secure_ident(
        &self,
        user_hash: [u8; 16],
        public_key: &[u8],
    ) -> anyhow::Result<bool> {
        // Commit parked pre-bind deltas FIRST (under the flush gate) so the
        // wipe below wipes them with the rest: a background flush landing
        // after the wipe would otherwise resurrect pre-bind credit, breaking
        // the anti-theft rule.
        self.settle_parked_peer_credit(user_hash)?;
        self.metadata
            .record_verified_secure_ident(&hex::encode(user_hash), public_key)
    }

    /// The requested file's size, feeding the queue's per-session transfer cap
    /// (oracle `ResolveSessionTransferLimitBytes` reads
    /// `CKnownFile::GetFileSize`, UploadQueue.cpp:137-149). 0 (unknown file)
    /// disables the byte cap, like the oracle's NULL-file early return.
    fn shared_file_size(&self, file_hash: &Ed2kHash) -> u64 {
        self.metadata
            .transfer_manifest_by_hash(&file_hash.to_string())
            .ok()
            .flatten()
            .map(|manifest| manifest.file_size)
            .unwrap_or(0)
    }

    fn file_priority_score(&self, file_hash: &Ed2kHash, queued_count: u64) -> i128 {
        self.metadata
            .transfer_manifest_by_hash(&file_hash.to_string())
            .ok()
            .flatten()
            .map(|manifest| {
                upload_priority_score(
                    &manifest.upload_priority,
                    manifest.auto_upload_priority,
                    queued_count,
                )
            })
            .unwrap_or_else(|| upload_priority_score("normal", false, queued_count))
    }

    /// The requested file's all-time upload ratio in permille (eMule
    /// `CKnownFile::GetAllTimeUploadRatio`), feeding the upload-queue low-ratio
    /// score bonus. Returns the master neutral sentinel
    /// `LOW_RATIO_BONUS_DISABLED_RATIO_PERMILLE` (at/above the threshold, so the
    /// bonus is off) for an unknown file: eMule's `GetScoreBreakdown` only reaches
    /// the bonus for a known requested file (`pRequestedFile != NULL`).
    fn file_all_time_upload_ratio_permille(&self, file_hash: &Ed2kHash) -> i128 {
        match self
            .metadata
            .file_all_time_upload_totals(&file_hash.to_string())
        {
            Ok(Some((uploaded, size))) => {
                // Read-through over the parked ledger so unflushed served
                // bytes weight the ratio immediately, like eMule's in-memory
                // CKnownFile statistic.
                let uploaded =
                    uploaded.saturating_add(self.parked_file_all_time_uploaded(file_hash));
                if size > 0 {
                    i128::from(uploaded) * 1000 / i128::from(size)
                } else {
                    0
                }
            }
            _ => super::upload_queue::LOW_RATIO_BONUS_DISABLED_RATIO_PERMILLE,
        }
    }

    /// Add `delta` to the file's pending demand-upload bucket, then make ONE
    /// non-blocking attempt to flush the entire pending into the shared catalog.
    ///
    /// Correctness (all under the instant, await-free `pending_catalog_upload`
    /// std Mutex, so no add/flush can interleave):
    /// - No loss: the fragment lands in `pending` first; if the `try_write` fails
    ///   (catalog write lock contended) the bytes remain parked for a later flush.
    /// - No double-count: on a successful `try_write` the parked amount is applied
    ///   to the catalog exactly once and the bucket is removed atomically, so a
    ///   concurrent add starts a fresh bucket and a concurrent flush finds none.
    /// - Non-blocking: the catalog is only ever taken via `try_write`; the side-map
    ///   lock is held solely for O(1) map ops + that non-blocking probe.
    pub(super) fn accumulate_and_try_flush_catalog_upload(&self, file_hash: &Ed2kHash, delta: u64) {
        let key = file_hash.to_string();
        let mut pending = self.pending_catalog_upload.lock().unwrap();
        let amount = {
            let slot = pending.entry(key.clone()).or_insert(0);
            *slot = slot.saturating_add(delta);
            *slot
        };
        if amount == 0 {
            return;
        }
        if let Ok(mut catalog) = self.shared_catalog.try_write() {
            catalog.update_by_hash(file_hash, |entry| {
                entry.all_time_uploaded_bytes =
                    entry.all_time_uploaded_bytes.saturating_add(amount);
                entry.publish.session_uploaded_bytes =
                    entry.publish.session_uploaded_bytes.saturating_add(amount);
            });
            // The write lock was taken: the pending is resolved. If the file has a
            // catalog entry the whole amount landed in it; if it has none there is
            // nothing to credit (the pre-fix `try_write` path was a no-op too), so
            // either way the bucket is cleared, keeping the side map bounded.
            pending.remove(&key);
        }
    }

    /// Guaranteed (blocking) flush of a file's parked demand-upload bytes into the
    /// shared catalog. Called at session release -- OFF the per-fragment hot path
    /// -- so blocking on the catalog write lock is safe here and guarantees a tail
    /// parked during a publish tick is never orphaned.
    ///
    /// Lock ordering: this takes the catalog write lock FIRST, then the side-map
    /// lock. That is the reverse of the per-fragment path, but the per-fragment
    /// path only ever probes the catalog with a NON-blocking `try_write` while
    /// holding the side-map lock, so it never waits on the catalog -- no thread can
    /// hold the side-map lock while blocked on the catalog, so no circular wait
    /// (deadlock) is possible.
    async fn flush_pending_catalog_upload(&self, file_hash: &Ed2kHash) {
        let key = file_hash.to_string();
        // Cheap pre-check: skip taking the catalog write lock when the continuous
        // per-fragment flushes already drained this file (the common case).
        let has_pending = self
            .pending_catalog_upload
            .lock()
            .unwrap()
            .get(&key)
            .copied()
            .unwrap_or(0)
            > 0;
        if !has_pending {
            return;
        }
        let mut catalog = self.shared_catalog.write().await;
        let mut pending = self.pending_catalog_upload.lock().unwrap();
        // Re-read under the final lock: a concurrent per-fragment flush may have
        // drained (or grown) the bucket since the pre-check.
        if let Some(amount) = pending.remove(&key)
            && amount > 0
        {
            catalog.update_by_hash(file_hash, |entry| {
                entry.all_time_uploaded_bytes =
                    entry.all_time_uploaded_bytes.saturating_add(amount);
                entry.publish.session_uploaded_bytes =
                    entry.publish.session_uploaded_bytes.saturating_add(amount);
            });
        }
    }

    async fn update_shared_publish_stats(
        &self,
        file_hash: &Ed2kHash,
        update: impl FnOnce(&mut super::Ed2kSharedEntry),
    ) {
        // O(1) by-hash resolution of the unique non-hint entry, replacing the
        // former write-lock + full linear scan on every request/accept.
        let mut catalog = self.shared_catalog.write().await;
        catalog.update_by_hash(file_hash, update);
    }

    /// Enable/disable the credit system live (eMule `thePrefs.GetCreditSystem()`).
    /// When disabled every peer scores the neutral 1.0 credit ratio.
    pub fn set_credit_system_enabled(&self, enabled: bool) {
        self.credit_system_enabled.store(enabled, Ordering::Relaxed);
    }

    fn peer_credit_score_permille(&self, peer: &Ed2kUploadPeerIdentity) -> i128 {
        // Credit system off (eMule !thePrefs.GetCreditSystem()): everyone gets the
        // neutral 1.0 ratio, so stored bytes never weight the queue order.
        if !self.credit_system_enabled.load(Ordering::Relaxed) {
            return DEFAULT_CREDIT_SCORE_PERMILLE;
        }
        let Some(user_hash) = peer.user_hash else {
            return DEFAULT_CREDIT_SCORE_PERMILLE;
        };
        // Read-through over the parked ledger so accrued-but-unflushed bytes
        // weight the score immediately, like eMule's in-memory CClientCredits.
        let stored = self
            .metadata
            .peer_credit_by_hash(&hex::encode(user_hash))
            .ok()
            .flatten();
        let (parked_uploaded, parked_downloaded) = self.parked_peer_credit_delta(user_hash);
        if stored.is_none() && parked_uploaded == 0 && parked_downloaded == 0 {
            return DEFAULT_CREDIT_SCORE_PERMILLE;
        }
        let (stored_uploaded, stored_downloaded) = stored
            .map(|credit| (credit.uploaded_bytes, credit.downloaded_bytes))
            .unwrap_or((0, 0));
        credit_score_permille(
            stored_uploaded.saturating_add(parked_uploaded),
            stored_downloaded.saturating_add(parked_downloaded),
            peer.ident_verified,
        )
    }
}

fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}
