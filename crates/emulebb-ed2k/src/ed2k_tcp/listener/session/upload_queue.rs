use std::net::SocketAddr;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::{
        ED2K_CONNECTION_IDLE_TIMEOUT, ED2K_UPLOAD_QUEUE_POLL_INTERVAL,
        ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL, Ed2kTransport,
    },
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadSessionHandle,
        Ed2kUploadSessionStatus,
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
}

impl ListenerUploadQueue {
    pub(in crate::ed2k_tcp) const fn new() -> Self {
        Self {
            session: None,
            file_hash: None,
            granted_sent: false,
            last_queue_rank: None,
            last_queue_rank_sent_at: None,
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
            .poll_upload_session(upload_session_handle, true)
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
            let (session_handle, status) = transfer_runtime
                .begin_upload_session(peer_identity, requested)
                .await;
            // A rejected candidate was never enqueued, so do not retain a
            // dangling session handle for it.
            if status != Ed2kUploadSessionStatus::Rejected {
                self.session = Some(session_handle);
                self.file_hash = Some(*requested);
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
        let (session_handle, status) = transfer_runtime
            .begin_upload_session(peer_identity, requested)
            .await;
        // A rejected candidate was never enqueued; do not retain a dangling
        // session handle for it.
        if status != Ed2kUploadSessionStatus::Rejected {
            self.session = Some(session_handle);
            self.file_hash = Some(*requested);
            self.granted_sent = false;
        }
        self.send_status(transport, peer_addr, status).await
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

    pub(in crate::ed2k_tcp) async fn release(&mut self, transfer_runtime: &Ed2kTransferRuntime) {
        if let Some(upload_session_handle) = self.session.as_ref() {
            transfer_runtime
                .release_upload_session(upload_session_handle)
                .await;
        }
        self.session = None;
        self.file_hash = None;
        self.granted_sent = false;
        self.last_queue_rank = None;
        self.last_queue_rank_sent_at = None;
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
        Ok(())
    }

    fn mark_granted_sent(&mut self) {
        self.granted_sent = true;
        self.last_queue_rank = None;
        self.last_queue_rank_sent_at = None;
    }

    fn mark_waiting(&mut self, rank: u16) {
        self.granted_sent = false;
        self.last_queue_rank = Some(rank);
        self.last_queue_rank_sent_at = Some(tokio::time::Instant::now());
    }
}
