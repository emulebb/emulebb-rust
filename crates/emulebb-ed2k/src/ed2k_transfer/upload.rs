//! Runtime-facing upload queue methods.

use std::{sync::atomic::Ordering, time::Instant};

use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::MetadataPeerCredit;

use super::{
    Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadQueueSnapshotEntry,
    Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
    upload_queue::{DEFAULT_CREDIT_SCORE_PERMILLE, credit_score_permille, upload_priority_score},
};

impl Ed2kTransferRuntime {
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
        let handle = Ed2kUploadSessionHandle::new(peer, file_hash.to_string(), connection_id);
        let file_priority_score = self.file_priority_score(file_hash);
        let status = self.upload_queue.lock().await.begin_session(
            handle.key().clone(),
            connection_id,
            now,
            file_priority_score,
            credit_score_permille,
        );
        (handle, status)
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
        self.upload_queue
            .lock()
            .await
            .note_uploaded_bytes(handle, byte_count, now)
    }

    /// Release one upload slot or waiting entry after disconnect or explicit cancel.
    pub(crate) async fn release_upload_session(&self, handle: &Ed2kUploadSessionHandle) {
        self.upload_queue
            .lock()
            .await
            .release_session(handle, Instant::now());
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
        self.metadata.upsert_peer_credit(&MetadataPeerCredit {
            user_hash: hex::encode(user_hash),
            uploaded_bytes,
            downloaded_bytes,
        })
    }

    pub(crate) fn add_peer_credit_delta(
        &self,
        user_hash: [u8; 16],
        uploaded_delta: u64,
        downloaded_delta: u64,
    ) -> anyhow::Result<()> {
        if uploaded_delta == 0 && downloaded_delta == 0 {
            return Ok(());
        }
        self.metadata.add_peer_credit_delta(
            &hex::encode(user_hash),
            uploaded_delta,
            downloaded_delta,
        )
    }

    #[cfg(test)]
    pub(crate) fn peer_credit_by_hash(
        &self,
        user_hash: [u8; 16],
    ) -> anyhow::Result<Option<MetadataPeerCredit>> {
        self.metadata.peer_credit_by_hash(&hex::encode(user_hash))
    }

    fn file_priority_score(&self, file_hash: &Ed2kHash) -> i128 {
        self.metadata
            .transfer_manifest_by_hash(&file_hash.to_string())
            .ok()
            .flatten()
            .map(|manifest| upload_priority_score(&manifest.upload_priority))
            .unwrap_or_else(|| upload_priority_score("normal"))
    }

    fn peer_credit_score_permille(&self, peer: &Ed2kUploadPeerIdentity) -> i128 {
        peer.user_hash
            .map(hex::encode)
            .and_then(|user_hash| self.metadata.peer_credit_by_hash(&user_hash).ok().flatten())
            .map(|credit| credit_score_permille(credit.uploaded_bytes, credit.downloaded_bytes))
            .unwrap_or(DEFAULT_CREDIT_SCORE_PERMILLE)
    }
}
