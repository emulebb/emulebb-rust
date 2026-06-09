//! Runtime-facing upload queue methods.

use std::{sync::atomic::Ordering, time::Instant};

use emulebb_kad_proto::Ed2kHash;

use super::{
    Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadQueueSnapshotEntry,
    Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
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
        let connection_id = self
            .next_upload_connection_id
            .fetch_add(1, Ordering::Relaxed);
        let handle = Ed2kUploadSessionHandle::new(peer, file_hash.to_string(), connection_id);
        let status = self.upload_queue.lock().await.begin_session(
            handle.key().clone(),
            connection_id,
            Instant::now(),
        );
        (handle, status)
    }

    /// Poll the current queue-visible state for one upload session.
    pub(crate) async fn poll_upload_session(
        &self,
        handle: &Ed2kUploadSessionHandle,
        refresh_activity: bool,
    ) -> Ed2kUploadSessionStatus {
        self.upload_queue
            .lock()
            .await
            .poll_session(handle, Instant::now(), refresh_activity)
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

    /// Release one upload slot or waiting entry after disconnect or explicit cancel.
    pub(crate) async fn release_upload_session(&self, handle: &Ed2kUploadSessionHandle) {
        self.upload_queue
            .lock()
            .await
            .release_session(handle, Instant::now());
    }

    /// Return a management snapshot of active and waiting inbound upload sessions.
    pub async fn upload_queue_snapshot(&self) -> Vec<Ed2kUploadQueueSnapshotEntry> {
        self.upload_queue.lock().await.snapshot(Instant::now())
    }
}
