use std::net::SocketAddr;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::{
        ED2K_CONNECTION_IDLE_TIMEOUT, ED2K_UPLOAD_QUEUE_POLL_INTERVAL,
        ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL, Ed2kTransport,
    },
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadRangeAdmission,
        Ed2kUploadSessionHandle, Ed2kUploadSessionStatus, Ed2kVerifiedRangeReader, diag_sched,
    },
};

use super::super::super::codec::{encode_accept_upload_req, encode_queue_ranking};
use super::super::super::dump::dump_ed2k_tcp_listener_send;

pub(in crate::ed2k_tcp) enum ListenerQueuePoll {
    Continue,
    Close,
}

pub(in crate::ed2k_tcp) enum ListenerQueueDecision {
    Granted,
    Waiting,
    Stale,
}

pub(in crate::ed2k_tcp) struct ListenerUploadQueue {
    session: Option<Ed2kUploadSessionHandle>,
    file_hash: Option<Ed2kHash>,
    granted_sent: bool,
    last_queue_rank: Option<u16>,
    last_queue_rank_sent_at: Option<tokio::time::Instant>,
    // Stable peer identity for the `sched` diag_event_v1 emits, captured from the
    // advertised upload peer identity (so slot events align with the upload-queue
    // session key, not the ephemeral socket source port).
    diag_peer: Option<String>,
    diag_peer_hash: Option<[u8; 16]>,
    verified_reader: Option<(Ed2kHash, Ed2kVerifiedRangeReader)>,
}

impl ListenerUploadQueue {
    pub(in crate::ed2k_tcp) const fn new() -> Self {
        Self {
            session: None,
            file_hash: None,
            granted_sent: false,
            last_queue_rank: None,
            last_queue_rank_sent_at: None,
            diag_peer: None,
            diag_peer_hash: None,
            verified_reader: None,
        }
    }

    /// Capture the advertised peer identity for the `sched` diag emits.
    fn record_diag_peer(&mut self, peer_identity: &Ed2kUploadPeerIdentity) {
        self.diag_peer = Some(diag_sched::peer_label(
            peer_identity.ip,
            peer_identity.tcp_port,
        ));
        self.diag_peer_hash = peer_identity.user_hash;
    }

    /// Emit `upload_slot_opened` once per grant transition (peer + file known).
    fn emit_slot_opened(&self) {
        if let (Some(peer), Some(file_hash)) = (self.diag_peer.as_deref(), self.file_hash.as_ref())
        {
            diag_sched::upload_slot_opened(peer, self.diag_peer_hash, &file_hash.to_string());
        }
    }

    /// Emit `queue_rank` for a genuine waiting rank sent on the wire.
    fn emit_queue_rank(&self, rank: u16) {
        if let (Some(peer), Some(file_hash)) = (self.diag_peer.as_deref(), self.file_hash.as_ref())
        {
            diag_sched::queue_rank(peer, self.diag_peer_hash, &file_hash.to_string(), rank);
        }
    }

    /// Emit `upload_slot_closed` when a held session is released.
    fn emit_slot_closed(&self) {
        if let (Some(peer), Some(file_hash)) = (self.diag_peer.as_deref(), self.file_hash.as_ref())
        {
            diag_sched::upload_slot_closed(peer, self.diag_peer_hash, &file_hash.to_string());
        }
    }

    pub(in crate::ed2k_tcp) fn read_timeout(&self) -> std::time::Duration {
        if self.session.is_some() {
            ED2K_UPLOAD_QUEUE_POLL_INTERVAL
        } else {
            ED2K_CONNECTION_IDLE_TIMEOUT
        }
    }

    pub(in crate::ed2k_tcp) async fn poll_on_timeout(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
    ) -> Result<ListenerQueuePoll> {
        let Some(upload_session_handle) = self.session.as_ref() else {
            return Ok(ListenerQueuePoll::Close);
        };
        match transfer_runtime
            .poll_upload_session(upload_session_handle, false)
            .await
        {
            Ed2kUploadSessionStatus::Granted => {
                self.send_accept_if_needed(transport, peer_addr).await?;
                Ok(ListenerQueuePoll::Continue)
            }
            Ed2kUploadSessionStatus::Waiting { rank } => {
                let now = tokio::time::Instant::now();
                let should_refresh = self.last_queue_rank != Some(rank)
                    || self.last_queue_rank_sent_at.is_none_or(|sent_at| {
                        now.duration_since(sent_at) >= ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL
                    });
                if should_refresh {
                    self.send_queue_rank(transport, peer_addr, rank, now)
                        .await?;
                }
                Ok(ListenerQueuePoll::Continue)
            }
            Ed2kUploadSessionStatus::Stale | Ed2kUploadSessionStatus::Rejected => {
                Ok(ListenerQueuePoll::Close)
            }
        }
    }

    pub(in crate::ed2k_tcp) async fn start_upload_reply(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        peer_identity: Ed2kUploadPeerIdentity,
        requested: &Ed2kHash,
    ) -> Vec<u8> {
        let status = if self.file_hash.as_ref() == Some(requested) {
            match self.session.as_ref() {
                Some(upload_session_handle) => {
                    transfer_runtime
                        .poll_upload_session(upload_session_handle, true)
                        .await
                }
                None => Ed2kUploadSessionStatus::Stale,
            }
        } else {
            self.record_diag_peer(&peer_identity);
            let (session_handle, status) = transfer_runtime
                .begin_upload_session(peer_identity, requested)
                .await;
            // A rejected candidate was never enqueued, so do not retain a
            // dangling session handle for it.
            if status != Ed2kUploadSessionStatus::Rejected {
                self.session = Some(session_handle);
                self.file_hash = Some(*requested);
                self.verified_reader = None;
            }
            status
        };
        match status {
            Ed2kUploadSessionStatus::Granted => {
                self.mark_granted_sent();
                encode_accept_upload_req()
            }
            Ed2kUploadSessionStatus::Waiting { rank } => {
                self.mark_waiting(rank);
                self.emit_queue_rank(rank);
                encode_queue_ranking(rank)
            }
            // Admission refused (master AddClientToQueue returned without
            // queuing): signal a full queue so the peer backs off. eMule sends
            // OP_QUEUEFULL on the UDP reask path; on this TCP path it simply
            // does not admit, so report the maximum queue rank.
            Ed2kUploadSessionStatus::Rejected => {
                self.mark_waiting(u16::MAX);
                encode_queue_ranking(u16::MAX)
            }
            Ed2kUploadSessionStatus::Stale => {
                self.mark_waiting(1);
                encode_queue_ranking(1)
            }
        }
    }

    pub(in crate::ed2k_tcp) async fn ensure_session_for_parts(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        peer_identity: Ed2kUploadPeerIdentity,
        requested: &Ed2kHash,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
    ) -> Result<ListenerQueueDecision> {
        if self.file_hash.as_ref() == Some(requested) {
            // WHY: queued peers remember the requested file before they own a slot; a later
            // OP_REQUESTPARTS must re-check the global queue state instead of bypassing limits.
            let status = match self.session.as_ref() {
                Some(upload_session_handle) => {
                    transfer_runtime
                        .poll_upload_session(upload_session_handle, true)
                        .await
                }
                None => Ed2kUploadSessionStatus::Stale,
            };
            return self.send_status(transport, peer_addr, status).await;
        }
        self.record_diag_peer(&peer_identity);
        let (session_handle, status) = transfer_runtime
            .begin_upload_session(peer_identity, requested)
            .await;
        // A rejected candidate was never enqueued; do not retain a dangling
        // session handle for it.
        if status != Ed2kUploadSessionStatus::Rejected {
            self.session = Some(session_handle);
            self.file_hash = Some(*requested);
            self.granted_sent = false;
            self.verified_reader = None;
        }
        self.send_status(transport, peer_addr, status).await
    }

    pub(in crate::ed2k_tcp) async fn take_verified_reader(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        requested: &Ed2kHash,
    ) -> Result<Option<Ed2kVerifiedRangeReader>> {
        if let Some((cached_hash, reader)) = self.verified_reader.take() {
            if cached_hash == *requested {
                return Ok(Some(reader));
            }
        }
        transfer_runtime.open_verified_range_reader(requested).await
    }

    pub(in crate::ed2k_tcp) fn store_verified_reader(
        &mut self,
        requested: &Ed2kHash,
        reader: Ed2kVerifiedRangeReader,
    ) {
        if self.file_hash.as_ref() == Some(requested) && self.session.is_some() {
            self.verified_reader = Some((*requested, reader));
        }
    }

    pub(in crate::ed2k_tcp) async fn note_request_parts(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
    ) -> Result<ListenerQueueDecision> {
        let Some(upload_session_handle) = self.session.as_ref() else {
            return Ok(ListenerQueueDecision::Waiting);
        };
        let status = transfer_runtime
            .note_upload_request_parts(upload_session_handle)
            .await;
        self.send_status(transport, peer_addr, status).await
    }

    pub(in crate::ed2k_tcp) async fn note_range_request(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        start: u64,
        end: u64,
    ) -> (ListenerQueueDecision, Ed2kUploadRangeAdmission) {
        let Some(upload_session_handle) = self.session.as_ref() else {
            return (
                ListenerQueueDecision::Waiting,
                Ed2kUploadRangeAdmission::Accepted,
            );
        };
        let (status, admission) = transfer_runtime
            .note_upload_range_request(upload_session_handle, start, end)
            .await;
        (Self::decision_from_status(status), admission)
    }

    pub(in crate::ed2k_tcp) async fn note_range_served(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        start: u64,
        end: u64,
    ) -> ListenerQueueDecision {
        let Some(upload_session_handle) = self.session.as_ref() else {
            return ListenerQueueDecision::Waiting;
        };
        let status = transfer_runtime
            .note_upload_range_served(upload_session_handle, start, end)
            .await;
        Self::decision_from_status(status)
    }

    pub(in crate::ed2k_tcp) async fn note_payload_sent(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        byte_count: u64,
    ) {
        if let Some(upload_session_handle) = self.session.as_ref() {
            transfer_runtime
                .note_upload_payload_sent(upload_session_handle, byte_count)
                .await;
        }
    }

    /// The file this connection currently holds an upload slot/waiting entry
    /// for, if any. Unlike the session's `requested_file_hash` (overwritten by
    /// every file-touching handler), this tracks the file the granted slot is
    /// keyed on, so `OP_END_OF_DOWNLOAD` releases only when the peer signals end
    /// for the file it actually holds.
    pub(in crate::ed2k_tcp) const fn slot_file_hash(&self) -> Option<Ed2kHash> {
        if self.session.is_some() {
            self.file_hash
        } else {
            None
        }
    }

    pub(in crate::ed2k_tcp) async fn release(&mut self, transfer_runtime: &Ed2kTransferRuntime) {
        if let Some(upload_session_handle) = self.session.as_ref() {
            transfer_runtime
                .release_upload_session(upload_session_handle)
                .await;
            self.emit_slot_closed();
        }
        self.session = None;
        self.file_hash = None;
        self.granted_sent = false;
        self.last_queue_rank = None;
        self.last_queue_rank_sent_at = None;
        self.diag_peer = None;
        self.diag_peer_hash = None;
        self.verified_reader = None;
    }

    async fn send_status(
        &mut self,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
        status: Ed2kUploadSessionStatus,
    ) -> Result<ListenerQueueDecision> {
        match status {
            Ed2kUploadSessionStatus::Granted => {
                self.send_accept_if_needed(transport, peer_addr).await?;
                Ok(ListenerQueueDecision::Granted)
            }
            Ed2kUploadSessionStatus::Waiting { rank } => {
                self.send_queue_rank(transport, peer_addr, rank, tokio::time::Instant::now())
                    .await?;
                Ok(ListenerQueueDecision::Waiting)
            }
            Ed2kUploadSessionStatus::Stale | Ed2kUploadSessionStatus::Rejected => {
                Ok(ListenerQueueDecision::Stale)
            }
        }
    }

    const fn decision_from_status(status: Ed2kUploadSessionStatus) -> ListenerQueueDecision {
        match status {
            Ed2kUploadSessionStatus::Granted => ListenerQueueDecision::Granted,
            Ed2kUploadSessionStatus::Waiting { .. } => ListenerQueueDecision::Waiting,
            Ed2kUploadSessionStatus::Stale | Ed2kUploadSessionStatus::Rejected => {
                ListenerQueueDecision::Stale
            }
        }
    }

    async fn send_accept_if_needed(
        &mut self,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        if self.granted_sent {
            self.last_queue_rank = None;
            self.last_queue_rank_sent_at = None;
            return Ok(());
        }
        let reply = encode_accept_upload_req();
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "accept_upload", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_ACCEPTUPLOADREQ to {peer_addr}"))?;
        self.mark_granted_sent();
        Ok(())
    }

    async fn send_queue_rank(
        &mut self,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
        rank: u16,
        now: tokio::time::Instant,
    ) -> Result<()> {
        let reply = encode_queue_ranking(rank);
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "queue_ranking", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_QUEUERANKING to {peer_addr}"))?;
        self.granted_sent = false;
        self.last_queue_rank = Some(rank);
        self.last_queue_rank_sent_at = Some(now);
        self.emit_queue_rank(rank);
        Ok(())
    }

    fn mark_granted_sent(&mut self) {
        let newly_granted = !self.granted_sent;
        self.granted_sent = true;
        self.last_queue_rank = None;
        self.last_queue_rank_sent_at = None;
        if newly_granted {
            self.emit_slot_opened();
        }
    }

    fn mark_waiting(&mut self, rank: u16) {
        self.granted_sent = false;
        self.last_queue_rank = Some(rank);
        self.last_queue_rank_sent_at = Some(tokio::time::Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };

    use emulebb_kad_proto::Ed2kHash;

    use super::ListenerUploadQueue;
    use crate::ed2k_transfer::{ED2K_EMBLOCK_SIZE, Ed2kTransferRuntime};
    use crate::paths::unique_test_dir;

    /// FIX 5 invariant: the upload slot must be reclaimed on EVERY exit path.
    /// `handle_connection` now always falls through to `release` (the loop body
    /// runs inside a fallible scope, so an in-loop `?` lands in `result` instead
    /// of escaping past the release). This test proves the property the
    /// fall-through relies on: `release` frees the runtime slot and is safe to
    /// call again (idempotent), so calling it after an in-loop release -- or on
    /// an error path that already released -- never panics or double-frees.
    #[tokio::test]
    async fn release_reclaims_slot_and_is_idempotent() {
        let root = unique_test_dir("ed2k-listener-upload-release");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 4662);
        let identity = super::super::upload_peer_identity_from_socket(peer_addr);
        let file_hash = Ed2kHash::from_bytes([0x33; 16]);

        let mut queue = ListenerUploadQueue::new();
        // An empty queue grants the first requester a slot.
        let _reply = queue
            .start_upload_reply(&runtime, identity, &file_hash)
            .await;
        assert_eq!(
            runtime.upload_queue_snapshot().await.len(),
            1,
            "the granted session must occupy a slot"
        );

        // First release frees the slot.
        queue.release(&runtime).await;
        assert!(
            runtime.upload_queue_snapshot().await.is_empty(),
            "release must reclaim the slot deterministically"
        );

        // The unconditional post-loop release (or an error path that already
        // released) calling it a second time must be a harmless no-op.
        queue.release(&runtime).await;
        assert!(runtime.upload_queue_snapshot().await.is_empty());
    }

    /// FIX (END_OF_DOWNLOAD on the wrong hash): `slot_file_hash` must report the
    /// file the granted slot is keyed on, so OP_END_OF_DOWNLOAD compares against
    /// the held file rather than the mutable per-session `requested_file_hash`
    /// (which any later file-touching handler overwrites). Before a slot exists
    /// it is `None`; after a grant it is the granted file; after release it is
    /// `None` again.
    #[tokio::test]
    async fn slot_file_hash_tracks_the_granted_slot_not_the_last_request() {
        let root = unique_test_dir("ed2k-listener-slot-file-hash");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 4662);
        let identity = super::super::upload_peer_identity_from_socket(peer_addr);
        let file_a = Ed2kHash::from_bytes([0xA1; 16]);

        let mut queue = ListenerUploadQueue::new();
        // No slot yet: nothing to release on END_OF_DOWNLOAD.
        assert_eq!(queue.slot_file_hash(), None);

        // Granting a slot for file A keys the slot on A.
        let _reply = queue.start_upload_reply(&runtime, identity, &file_a).await;
        assert_eq!(
            queue.slot_file_hash(),
            Some(file_a),
            "the granted slot must report the file it is keyed on"
        );

        // After release the slot is gone, so a stray END_OF_DOWNLOAD matches
        // nothing (the post-loop unconditional release still guarantees cleanup).
        queue.release(&runtime).await;
        assert_eq!(queue.slot_file_hash(), None);
    }

    #[tokio::test]
    async fn verified_reader_cache_survives_repeated_parts_requests_for_slot_file() {
        let root = unique_test_dir("ed2k-listener-upload-reader-cache");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let library = root.join("library");
        fs::create_dir_all(&library).unwrap();
        let source_path = library.join("shared-upload-cache.bin");
        let file_len = usize::try_from(ED2K_EMBLOCK_SIZE * 3).unwrap();
        let bytes = (0..file_len)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source_path, &bytes).unwrap();
        let summary = runtime
            .ingest_local_file(&source_path, "shared-upload-cache.bin")
            .await
            .unwrap();
        let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();

        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 4662);
        let identity = super::super::upload_peer_identity_from_socket(peer_addr);
        let mut queue = ListenerUploadQueue::new();
        let _reply = queue.start_upload_reply(&runtime, identity, &hash).await;

        let mut reader = queue
            .take_verified_reader(&runtime, &hash)
            .await
            .unwrap()
            .unwrap();
        let first = reader
            .read_range_with_read_ahead(0, ED2K_EMBLOCK_SIZE, ED2K_EMBLOCK_SIZE * 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, bytes[0..ED2K_EMBLOCK_SIZE as usize]);
        assert_eq!(reader.disk_read_count(), 1);
        queue.store_verified_reader(&hash, reader);

        let mut reader = queue
            .take_verified_reader(&runtime, &hash)
            .await
            .unwrap()
            .unwrap();
        let second = reader
            .read_range(ED2K_EMBLOCK_SIZE, ED2K_EMBLOCK_SIZE * 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            second,
            bytes[ED2K_EMBLOCK_SIZE as usize..(ED2K_EMBLOCK_SIZE * 2) as usize]
        );
        assert_eq!(
            reader.disk_read_count(),
            1,
            "second OP_REQUESTPARTS should reuse the cached read-ahead window"
        );
        assert_eq!(reader.cache_hit_count(), 1);
    }
}
