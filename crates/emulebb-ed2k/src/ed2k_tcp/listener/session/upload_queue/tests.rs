
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

/// REG-2: on a recycle demote the oracle sends OP_OUTOFPARTREQS AND THEN
/// OP_QUEUERANKING (SendOutOfPartReqsAndAddToWaitingQueue ->
/// AddClientToQueue(this, true) -> SendRankingInfo(),
/// UploadQueue.cpp:883-885,1980-1986). The rank is gated on the eMule extended
/// protocol exactly like every other rank (round-17 339764d), and a banned
/// peer reaches neither send (oracle bRequeue=false). This checks the two
/// composed gates the demote path emits through.
#[test]
fn recycle_demote_rank_follows_out_of_part_reqs_only_for_emule_and_never_banned() {
    let mut queue = ListenerUploadQueue::new();
    queue.granted_sent = true;

    // eMule waiter: the courtesy OP_OUTOFPARTREQS is owed AND the rank follows.
    queue.peer_ext_protocol = true;
    queue.peer_banned = false;
    assert!(queue.should_send_out_of_part_reqs());
    assert_eq!(queue.rank_packet(3), Some(encode_queue_ranking(3)));

    // Plain-eDonkey waiter: OUTOFPARTREQS is owed but the rank is suppressed
    // (SendRankingInfo `!ExtProtocolAvailable()` early return).
    queue.peer_ext_protocol = false;
    assert!(queue.should_send_out_of_part_reqs());
    assert_eq!(queue.rank_packet(3), None);

    // Banned waiter: neither the courtesy packet nor the rank.
    queue.peer_banned = true;
    queue.peer_ext_protocol = true;
    assert!(!queue.should_send_out_of_part_reqs());
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

/// REG-1: a BANNED peer's STARTUPLOADREQ is refused at admission (master
/// `AddClientToQueue` `if (client->IsBanned()) return;`, UploadQueue.cpp:1854):
/// no reply packet reaches the wire and no queue entry is created.
#[tokio::test]
async fn banned_peer_start_upload_req_gets_no_reply_and_no_queue_entry() {
    let root = unique_test_dir("ed2k-listener-banned-admission");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x77; 16]);
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 4662);
    let mut identity = emule_identity(peer_addr);
    identity.banned = true;

    let mut queue = ListenerUploadQueue::new();
    let reply = queue
        .start_upload_reply(&runtime, identity, &file_hash)
        .await;
    assert_eq!(reply, None, "a banned peer's admission must stay silent");
    assert!(
        queue.session.is_none(),
        "no session is retained for a banned peer"
    );
    assert!(
        runtime.upload_queue_snapshot().await.is_empty(),
        "a banned peer must not create a queue entry"
    );
}

/// UP-3: OP_QUEUERANKING is gated on the eMule extended protocol — the
/// oracle's SendRankingInfo early-returns for a plain-eDonkey peer
/// (`!ExtProtocolAvailable()`, UploadClient.cpp:962-963) and never sends
/// the legacy edonkey OP_QUEUERANK — while a tracked eMule waiter's
/// re-ask still earns its real rank (UP-1 re-attach).
#[tokio::test]
async fn queue_rank_is_sent_only_to_emule_extended_protocol_peers() {
    let root = unique_test_dir("ed2k-listener-rank-family-gate");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    use_one_slot_queue(&runtime).await;
    let file_hash = Ed2kHash::from_bytes([0x66; 16]);

    // Slot occupant.
    let mut granted = ListenerUploadQueue::new();
    let occupant_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41)), 4661);
    let reply = granted
        .start_upload_reply(&runtime, emule_identity(occupant_addr), &file_hash)
        .await;
    assert_eq!(reply, Some(encode_accept_upload_req()));

    // A plain-eDonkey waiter is enqueued but hears nothing.
    let edonkey_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)), 4662);
    let edonkey_identity = super::super::upload_peer_identity_from_socket(edonkey_addr);
    assert!(!edonkey_identity.is_emule_client);
    let mut edonkey_queue = ListenerUploadQueue::new();
    let reply = edonkey_queue
        .start_upload_reply(&runtime, edonkey_identity.clone(), &file_hash)
        .await;
    assert_eq!(reply, None, "a plain-eDonkey waiter must hear nothing");
    assert!(
        edonkey_queue.session.is_some(),
        "the silent waiter is still enqueued"
    );

    // An eMule waiter behind it gets its real rank on the wire.
    let emule_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 43)), 4663);
    let mut emule_queue = ListenerUploadQueue::new();
    let reply = emule_queue
        .start_upload_reply(&runtime, emule_identity(emule_addr), &file_hash)
        .await;
    assert_eq!(reply, Some(encode_queue_ranking(2)));

    // A tracked eMule waiter's re-ask still answers with the real rank...
    let reply = emule_queue
        .start_upload_reply(&runtime, emule_identity(emule_addr), &file_hash)
        .await;
    assert_eq!(reply, Some(encode_queue_ranking(2)));

    // ...and the eDonkey waiter's re-ask stays silent.
    let reply = edonkey_queue
        .start_upload_reply(&runtime, edonkey_identity, &file_hash)
        .await;
    assert_eq!(reply, None);
    assert_eq!(runtime.upload_queue_snapshot().await.len(), 3);
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
