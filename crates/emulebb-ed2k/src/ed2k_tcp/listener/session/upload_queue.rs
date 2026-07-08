use std::net::SocketAddr;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::{
        ED2K_CONNECTION_IDLE_TIMEOUT, ED2K_UPLOAD_QUEUE_POLL_INTERVAL,
        ED2K_WAITING_CONNECTION_IDLE_TIMEOUT, Ed2kTransport,
    },
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadRangeAdmission,
        Ed2kUploadSessionHandle, Ed2kUploadSessionStatus, Ed2kVerifiedRangeReader, diag_sched,
    },
};

use super::super::super::codec::{
    encode_accept_upload_req, encode_out_of_part_reqs, encode_queue_ranking,
};
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
    // Sticky: this peer was granted a slot at some point in this connection (never
    // cleared while `granted_sent` toggles per grant/demote). Distinguishes a
    // was-granted peer from a never-granted one for the close-reason funnel, since
    // `granted_sent` is now reset on a demote-back-to-queue.
    ever_granted: bool,
    // Stable peer identity for the `sched` diag_event_v1 emits, captured from the
    // advertised upload peer identity (so slot events align with the upload-queue
    // session key, not the ephemeral socket source port).
    diag_peer: Option<String>,
    diag_peer_hash: Option<[u8; 16]>,
    // Whether the peer bound to the current session was BANNED at admission
    // (mirrors the queue session key's `banned` flag). A banned client's slot
    // recycle must NOT get the OP_OUTOFPARTREQS courtesy packet (oracle
    // bRequeue=false, CheckForTimeOver, UploadQueue.cpp:2320-2321; requeue guard
    // in Process, UploadQueue.cpp:883-884).
    peer_banned: bool,
    verified_reader: Option<(Ed2kHash, Ed2kVerifiedRangeReader)>,
    // Per-connection ledger of requested upload blocks (fileHash, start, end,
    // count, first-seen) for MFC repeat_block_request parity. Bounded and pruned
    // to the observation window; a peer requests few distinct blocks at a time.
    block_request_ledger: Vec<([u8; 16], u64, u64, u32, std::time::Instant)>,
    // Most-specific pending close reason for the `upload_slot_closed` funnel diag,
    // set at the cancel/end/recycle/reject decision points; a plain disconnect
    // leaves it `None` and reports `peer_disconnected`. Pointer-sized, no alloc.
    close_reason: Option<&'static str>,
}

impl ListenerUploadQueue {
    pub(in crate::ed2k_tcp) const fn new() -> Self {
        Self {
            session: None,
            file_hash: None,
            granted_sent: false,
            ever_granted: false,
            diag_peer: None,
            diag_peer_hash: None,
            peer_banned: false,
            verified_reader: None,
            block_request_ledger: Vec::new(),
            close_reason: None,
        }
    }

    /// Record the most-specific reason for the next slot release, for the
    /// `upload_slot_closed` funnel diagnostic. Cheap `&'static str` assignment;
    /// the emit it feeds is compile-gated behind `packet-diagnostics`.
    pub(in crate::ed2k_tcp) fn note_close_reason(&mut self, reason: &'static str) {
        self.close_reason = Some(reason);
    }

    /// Records one requested upload block and returns the repeat count when this
    /// exact `(file, block range)` was already requested on this connection within
    /// the `REPEAT_BLOCK_WINDOW_SECS` window (MFC repeat_block_request parity). The
    /// block is still served; this only surfaces the behavior for diagnostics. The
    /// ledger is pruned to the window and capped so a peer requesting many distinct
    /// blocks cannot grow it without bound.
    pub(in crate::ed2k_tcp) fn note_block_request(
        &mut self,
        file_hash: &Ed2kHash,
        start: u64,
        end: u64,
    ) -> Option<u32> {
        use crate::ed2k_transfer::diag_bad_peer::REPEAT_BLOCK_WINDOW_SECS;
        const MAX_LEDGER_ENTRIES: usize = 512;
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(REPEAT_BLOCK_WINDOW_SECS);
        self.block_request_ledger
            .retain(|(_, _, _, _, first)| now.duration_since(*first) < window);
        let hash = file_hash.0;
        if let Some(entry) = self
            .block_request_ledger
            .iter_mut()
            .find(|(h, s, e, _, _)| *h == hash && *s == start && *e == end)
        {
            entry.3 = entry.3.saturating_add(1);
            return Some(entry.3);
        }
        if self.block_request_ledger.len() >= MAX_LEDGER_ENTRIES {
            self.block_request_ledger.remove(0);
        }
        self.block_request_ledger.push((hash, start, end, 1, now));
        None
    }

    /// Capture the advertised peer identity for the `sched` diag emits and the
    /// banned-recycle packet suppression.
    fn record_diag_peer(&mut self, peer_identity: &Ed2kUploadPeerIdentity) {
        self.diag_peer = Some(diag_sched::peer_label(
            peer_identity.ip,
            peer_identity.tcp_port,
        ));
        self.diag_peer_hash = peer_identity.user_hash;
        self.peer_banned = peer_identity.banned;
    }

    /// Whether a slot demotion/recycle owes the peer the OP_OUTOFPARTREQS
    /// courtesy packet: only a peer that actually saw OP_ACCEPTUPLOADREQ, and
    /// never a BANNED one (oracle bRequeue=false for `IsBanned()`,
    /// UploadQueue.cpp:2320-2321 -> the Process requeue guard skips
    /// SendOutOfPartReqsAndAddToWaitingQueue, UploadQueue.cpp:883-884; the
    /// banned client's queue entry is dropped, not re-added).
    const fn should_send_out_of_part_reqs(&self) -> bool {
        self.granted_sent && !self.peer_banned
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

    /// Emit `upload_slot_closed` (with its funnel `reason`) when a peer that is
    /// currently holding an active upload slot is released. Only an active-slot exit
    /// emits here, mirroring MFC (where `upload_slot_closed` fires from
    /// `RemoveFromUploadQueue`, i.e. active-list exits only): a peer already demoted
    /// back to the queue got its `slot_recycled` close at the recycle in the runtime
    /// queue, and a pure waiter's exit emits no close. The emission is compile-gated
    /// behind `packet-diagnostics`.
    fn emit_slot_closed(&self, reason: &str) {
        if !self.granted_sent {
            return;
        }
        if let (Some(peer), Some(file_hash)) = (self.diag_peer.as_deref(), self.file_hash.as_ref())
        {
            diag_sched::upload_slot_closed(
                peer,
                self.diag_peer_hash,
                &file_hash.to_string(),
                reason,
            );
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
        peer_idle_for: std::time::Duration,
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
            Ed2kUploadSessionStatus::Waiting { .. } => {
                // A slot we had granted was demoted back to the waiting queue (idle
                // recycle or session-cap rotation): tell the downloader to go OnQueue
                // with OP_OUTOFPARTREQS once, mirroring MFC
                // SendOutOfPartReqsAndAddToWaitingQueue, then keep the connection
                // rather than closing and shedding the peer. A BANNED peer gets no
                // packet (oracle bRequeue=false). `granted_sent` is cleared so a later
                // re-grant re-sends OP_ACCEPTUPLOADREQ; `ever_granted` stays set for
                // the funnel.
                if self.granted_sent {
                    if self.should_send_out_of_part_reqs() {
                        let packet = encode_out_of_part_reqs();
                        dump_ed2k_tcp_listener_send(
                            peer_addr,
                            transport.mode,
                            "out_of_part_reqs",
                            &packet,
                        );
                        transport.write_all(&packet).await?;
                        if let (Some(peer), Some(file_hash)) =
                            (self.diag_peer.as_deref(), self.file_hash.as_ref())
                        {
                            diag_sched::out_of_part_reqs(
                                peer,
                                self.diag_peer_hash,
                                &file_hash.to_string(),
                            );
                        }
                    }
                    self.granted_sent = false;
                }
                // No unsolicited rank refresh: the oracle sends OP_QUEUERANK /
                // OP_QUEUERANKING only in response to a re-ask (SendRankingInfo
                // call sites, UploadQueue.cpp:1866,1963,1986), never on a timer.
                // An idle waiting connection is closed like the oracle's socket
                // timeout (CClientReqSocket::CheckTimeOut); the queue entry
                // survives the close and is dialed back on a slot grant.
                if peer_idle_for >= ED2K_WAITING_CONNECTION_IDLE_TIMEOUT {
                    self.note_close_reason("waiting_socket_idle");
                    return Ok(ListenerQueuePoll::Close);
                }
                Ok(ListenerQueuePoll::Continue)
            }
            Ed2kUploadSessionStatus::Stale | Ed2kUploadSessionStatus::Rejected => {
                // A genuinely-gone session (a demoted waiter past waiting_timeout, or
                // a lost connection). `ever_granted` — not `granted_sent`, which is
                // cleared on demote — is the was-granted vs never-granted distinction.
                self.close_reason = Some(if self.ever_granted {
                    "slot_recycled"
                } else {
                    "rejected_never_granted"
                });
                // WHY: if this peer was actively granted an upload slot and the queue
                // is now recycling it (Stale), tell the downloader to go back to
                // OnQueue with OP_OUTOFPARTREQS before the socket closes -- mirroring
                // MFC CUpDownClient::SendOutOfPartReqsAndAddToWaitingQueue. Without it
                // the downloader is dropped silently and reconnects immediately (churn)
                // instead of re-queueing with the stock out-of-part-reqs cooldown. A
                // never-granted (Rejected) peer gets nothing, matching the master --
                // and so does a BANNED peer, whose recycle is dropped without the
                // packet (oracle bRequeue=false, UploadQueue.cpp:2320-2321).
                if self.should_send_out_of_part_reqs() {
                    let packet = encode_out_of_part_reqs();
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "out_of_part_reqs",
                        &packet,
                    );
                    let _ = transport.write_all(&packet).await;
                    if let (Some(peer), Some(file_hash)) =
                        (self.diag_peer.as_deref(), self.file_hash.as_ref())
                    {
                        diag_sched::out_of_part_reqs(
                            peer,
                            self.diag_peer_hash,
                            &file_hash.to_string(),
                        );
                    }
                }
                Ok(ListenerQueuePoll::Close)
            }
        }
    }

    /// Answer one OP_STARTUPLOADREQ for a served file. Returns the packet to
    /// put on the wire, or `None` where the oracle is silent: a rejected
    /// admission (AddClientToQueue early returns, UploadQueue.cpp:1854,
    /// 1905-1915, 1939-1941 — no packet).
    pub(in crate::ed2k_tcp) async fn start_upload_reply(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        peer_identity: Ed2kUploadPeerIdentity,
        requested: &Ed2kHash,
    ) -> Option<Vec<u8>> {
        let mut status = if self.file_hash.as_ref() == Some(requested) {
            match self.session.as_ref() {
                Some(upload_session_handle) => {
                    transfer_runtime
                        .poll_upload_session(upload_session_handle, true)
                        .await
                }
                None => Ed2kUploadSessionStatus::Stale,
            }
        } else {
            self.admit_fresh(transfer_runtime, peer_identity.clone(), requested)
                .await
        };
        if status == Ed2kUploadSessionStatus::Stale {
            // A re-ask from a peer the queue no longer tracks is a FRESH
            // admission (oracle AddClientToQueue: an untracked client is
            // enqueued anew and told its real rank via SendRankingInfo,
            // UploadQueue.cpp:1986, or silently refused). Never synthesize a
            // rank for a stale session.
            self.session = None;
            status = self
                .admit_fresh(transfer_runtime, peer_identity, requested)
                .await;
        }
        match status {
            Ed2kUploadSessionStatus::Granted => {
                self.mark_granted_sent();
                Some(encode_accept_upload_req())
            }
            Ed2kUploadSessionStatus::Waiting { rank } => {
                self.mark_waiting();
                self.emit_queue_rank(rank);
                Some(encode_queue_ranking(rank))
            }
            // Admission refused (master AddClientToQueue returned without
            // queuing): the oracle sends NOTHING on this TCP path
            // (UploadQueue.cpp:1854, 1905-1915, 1939-1941), so stay silent and
            // only record the rejection locally.
            Ed2kUploadSessionStatus::Rejected => {
                self.mark_waiting();
                // Keyed on the REQUESTED file: a rejected candidate never
                // updates `self.file_hash` (no session is retained for it).
                if let Some(peer) = self.diag_peer.as_deref() {
                    diag_sched::upload_admission_rejected(
                        peer,
                        self.diag_peer_hash,
                        &requested.to_string(),
                    );
                }
                None
            }
            // begin_session never reports Stale; a raced poll stays silent
            // like the oracle's untracked-client refusal.
            Ed2kUploadSessionStatus::Stale => {
                self.mark_waiting();
                None
            }
        }
    }

    /// Run one fresh queue admission for this connection (oracle
    /// `AddClientToQueue`). A rejected candidate was never enqueued, so no
    /// dangling session handle is retained for it.
    async fn admit_fresh(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        peer_identity: Ed2kUploadPeerIdentity,
        requested: &Ed2kHash,
    ) -> Ed2kUploadSessionStatus {
        self.record_diag_peer(&peer_identity);
        let (session_handle, status) = transfer_runtime
            .begin_upload_session(peer_identity, requested)
            .await;
        if status != Ed2kUploadSessionStatus::Rejected {
            self.session = Some(session_handle);
            self.file_hash = Some(*requested);
            self.verified_reader = None;
        }
        status
    }

    /// Attach a promoted-outbound slot grant (a waiter with no live connection
    /// promoted by the runtime queue) to this fresh outbound connection and
    /// push OP_ACCEPTUPLOADREQ (oracle `ConnectionEstablished`,
    /// BaseClient.cpp:1634-1641). Returns `false` when the grant went stale
    /// before the connect completed; the caller closes the connection.
    pub(in crate::ed2k_tcp) async fn attach_promoted_grant(
        &mut self,
        transfer_runtime: &Ed2kTransferRuntime,
        peer_identity: &Ed2kUploadPeerIdentity,
        handle: Ed2kUploadSessionHandle,
        file_hash: Ed2kHash,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
    ) -> Result<bool> {
        if transfer_runtime.poll_upload_session(&handle, true).await
            != Ed2kUploadSessionStatus::Granted
        {
            return Ok(false);
        }
        self.record_diag_peer(peer_identity);
        self.session = Some(handle);
        self.file_hash = Some(file_hash);
        self.verified_reader = None;
        self.send_accept_if_needed(transport, peer_addr).await?;
        Ok(true)
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
        if let Some((cached_hash, reader)) = self.verified_reader.take()
            && cached_hash == *requested
        {
            return Ok(Some(reader));
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
            let reason = self.close_reason.unwrap_or("peer_disconnected");
            self.emit_slot_closed(reason);
        }
        self.session = None;
        self.file_hash = None;
        self.granted_sent = false;
        self.close_reason = None;
        self.diag_peer = None;
        self.diag_peer_hash = None;
        self.peer_banned = false;
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
                self.send_queue_rank(transport, peer_addr, rank).await?;
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

    /// Send one queue rank in reply to a re-ask; rank is NEVER pushed on a
    /// timer (oracle SendRankingInfo fires only from the re-ask paths,
    /// UploadQueue.cpp:1866,1963,1986).
    async fn send_queue_rank(
        &mut self,
        transport: &mut Ed2kTransport,
        peer_addr: SocketAddr,
        rank: u16,
    ) -> Result<()> {
        let reply = encode_queue_ranking(rank);
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "queue_ranking", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_QUEUERANKING to {peer_addr}"))?;
        self.granted_sent = false;
        self.emit_queue_rank(rank);
        Ok(())
    }

    fn mark_granted_sent(&mut self) {
        let newly_granted = !self.granted_sent;
        self.granted_sent = true;
        self.ever_granted = true;
        if newly_granted {
            self.emit_slot_opened();
        }
    }

    fn mark_waiting(&mut self) {
        self.granted_sent = false;
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

    use super::{ListenerUploadQueue, encode_accept_upload_req, encode_queue_ranking};
    use crate::ed2k_transfer::{
        ED2K_EMBLOCK_SIZE, Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadQueueConfig,
    };
    use crate::paths::unique_test_dir;

    fn emule_identity(peer_addr: SocketAddr) -> Ed2kUploadPeerIdentity {
        let mut identity = super::super::upload_peer_identity_from_socket(peer_addr);
        identity.is_emule_client = true;
        identity
    }

    async fn use_one_slot_queue(runtime: &Ed2kTransferRuntime) {
        runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                ..Default::default()
            })
            .await;
    }

    /// Oracle bRequeue=false (CheckForTimeOver, UploadQueue.cpp:2320-2321): a
    /// BANNED client's slot recycle must not get the OP_OUTOFPARTREQS courtesy
    /// packet, while a normal granted peer must. A never-granted peer gets
    /// nothing either way.
    #[test]
    fn out_of_part_reqs_is_suppressed_for_banned_peers() {
        let mut queue = ListenerUploadQueue::new();

        // Never granted: no packet, banned or not.
        assert!(!queue.should_send_out_of_part_reqs());
        queue.peer_banned = true;
        assert!(!queue.should_send_out_of_part_reqs());

        // Granted + banned: suppressed (oracle bRequeue=false).
        queue.granted_sent = true;
        assert!(!queue.should_send_out_of_part_reqs());

        // Granted + not banned: the packet is owed.
        queue.peer_banned = false;
        assert!(queue.should_send_out_of_part_reqs());
    }

    #[test]
    fn note_block_request_flags_repeat_within_window() {
        let mut queue = ListenerUploadQueue::new();
        let file = Ed2kHash([7u8; 16]);
        // First request for a block is not a repeat.
        assert_eq!(queue.note_block_request(&file, 0, 180_000), None);
        // The same block again on this connection climbs the repeat count.
        assert_eq!(queue.note_block_request(&file, 0, 180_000), Some(2));
        assert_eq!(queue.note_block_request(&file, 0, 180_000), Some(3));
        // A different block on the same file is tracked independently.
        assert_eq!(queue.note_block_request(&file, 180_000, 360_000), None);
        // A different file is independent too.
        let other = Ed2kHash([9u8; 16]);
        assert_eq!(queue.note_block_request(&other, 0, 180_000), None);
    }

    /// UP-3: a re-ask on a STALE tracked session runs a FRESH admission — the
    /// oracle treats a re-ask from a client it no longer tracks as a plain
    /// `AddClientToQueue` and answers with the REAL state (SendRankingInfo,
    /// UploadQueue.cpp:1986) — never the old synthesized rank-1
    /// OP_QUEUERANKING.
    #[tokio::test]
    async fn stale_reask_runs_a_fresh_admission_with_the_real_reply() {
        let root = unique_test_dir("ed2k-listener-stale-reask");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21)), 4662);
        let identity = emule_identity(peer_addr);
        let file_hash = Ed2kHash::from_bytes([0x44; 16]);

        let mut queue = ListenerUploadQueue::new();
        let first = queue
            .start_upload_reply(&runtime, identity.clone(), &file_hash)
            .await;
        assert_eq!(first, Some(encode_accept_upload_req()));

        // Drop the runtime entry behind the listener's back: the next poll on
        // the retained handle reports Stale.
        let stale_handle = queue.session.clone().unwrap();
        runtime.release_upload_session(&stale_handle).await;
        assert!(runtime.upload_queue_snapshot().await.is_empty());

        // The re-ask is a fresh admission; the queue is empty, so the peer is
        // granted a REAL slot, not told a synthesized waiting rank.
        let reask = queue
            .start_upload_reply(&runtime, identity, &file_hash)
            .await;
        assert_eq!(reask, Some(encode_accept_upload_req()));
        assert_eq!(runtime.upload_queue_snapshot().await.len(), 1);
    }

    /// UP-3: a refused admission sends NOTHING — the oracle AddClientToQueue
    /// early-returns without a packet (per-IP cap, UploadQueue.cpp:1905-1915;
    /// queue caps 1939-1941) — where rust previously synthesized
    /// OP_QUEUERANKING(0xFFFF).
    #[tokio::test]
    async fn rejected_admission_sends_no_packet() {
        let root = unique_test_dir("ed2k-listener-rejected-admission");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        use_one_slot_queue(&runtime).await;
        let file_hash = Ed2kHash::from_bytes([0x55; 16]);
        let shared_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));

        // Occupy the single slot, then fill the per-IP waiter cap (3).
        let mut queues = Vec::new();
        for (index, port) in [4661u16, 4662, 4663, 4664].into_iter().enumerate() {
            let mut queue = ListenerUploadQueue::new();
            let reply = queue
                .start_upload_reply(
                    &runtime,
                    emule_identity(SocketAddr::new(shared_ip, port)),
                    &file_hash,
                )
                .await;
            let expected = if index == 0 {
                encode_accept_upload_req()
            } else {
                encode_queue_ranking(u16::try_from(index).unwrap())
            };
            assert_eq!(reply, Some(expected));
            queues.push(queue);
        }

        // The 4th same-IP candidate is refused: silence on the wire, no
        // retained session handle, and the queue is unchanged.
        let mut rejected = ListenerUploadQueue::new();
        let reply = rejected
            .start_upload_reply(
                &runtime,
                emule_identity(SocketAddr::new(shared_ip, 4665)),
                &file_hash,
            )
            .await;
        assert_eq!(reply, None, "a rejected admission must stay silent");
        assert!(rejected.session.is_none());
        assert_eq!(runtime.upload_queue_snapshot().await.len(), 4);
    }

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
