//! End-to-end tests for the uploader-side UDP reask reciprocity reply: the
//! runtime locates the reasking peer in the global upload queue + consults the
//! shared catalog, then the peer parses the obfuscated answer it would receive.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_client_udp::codec::ReaskFilePing;
use crate::ed2k_client_udp::dispatch::{InboundReaskMessage, parse_inbound_reask_datagram};
use crate::ed2k_transfer::{Ed2kSharedEntry, Ed2kTransferRuntime, Ed2kUploadPeerIdentity};
use crate::paths::unique_test_dir;

use super::upload_queue_support::{one_slot_config, upload_peer};

const OUR_PUBLIC_IP: [u8; 4] = [203, 0, 113, 9];
const PEER_USER_HASH: [u8; 16] = [0x55; 16];
const PEER_UDP_VERSION: u8 = 4;

fn shared_entry(file_hash: &Ed2kHash) -> Ed2kSharedEntry {
    Ed2kSharedEntry {
        file_hash: file_hash.to_string(),
        canonical_name: "ubuntu-linux.iso".to_string(),
        file_size: 9_728_000,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
    }
}

/// A reasking peer that queues on us with a known UDP endpoint + crypt support.
fn reasking_peer(udp_port: u16) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        tcp_port: 4662,
        udp_port: Some(udp_port),
        udp_version: PEER_UDP_VERSION,
        should_crypt: true,
        user_hash: Some(PEER_USER_HASH),
        client_id: Some(0x0A00_0007),
        friend_slot: false,
        ident_verified: false,
        ident_bad_guy: false,
        gpl_evildoer: false,
        banned: false,
        emule_version: 0x99,
        is_emule_client: true,
    }
}

#[tokio::test]
async fn reciprocity_acks_a_located_waiting_peer_with_its_rank() {
    let root = unique_test_dir("ed2k-reask-reciprocity-ack");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
    runtime
        .shared_catalog()
        .write()
        .await
        .push(shared_entry(&file_hash));

    // One slot: the first peer is granted, our reasker waits at rank 1.
    let (_granted, _) = runtime
        .begin_upload_session(upload_peer(1, 0x11, 0x0A00_0001), &file_hash)
        .await;
    let peer_udp_port = 4672;
    let (_waiting, _) = runtime
        .begin_upload_session(reasking_peer(peer_udp_port), &file_hash)
        .await;

    let ping = ReaskFilePing {
        file_hash,
        part_status: None,
        complete_source_count: None,
    };
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), peer_udp_port);
    let reply = runtime
        .reask_reciprocity_reply(&ping, from, OUR_PUBLIC_IP)
        .await
        .expect("an ack reply");

    // The peer parses the obfuscated ack keyed on its own hash + the IP it sees
    // us as (our public IP); it should read rank 1.
    match parse_inbound_reask_datagram(&reply, OUR_PUBLIC_IP, &PEER_USER_HASH, PEER_UDP_VERSION) {
        Some(InboundReaskMessage::Ack(ack)) => assert_eq!(ack.queue_position, 1),
        other => panic!("expected obfuscated Ack, got {other:?}"),
    }
}

#[tokio::test]
async fn reciprocity_replies_file_not_found_for_an_unshared_file() {
    let root = unique_test_dir("ed2k-reask-reciprocity-fnf");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0xCD; 16]);

    let ping = ReaskFilePing {
        file_hash,
        part_status: None,
        complete_source_count: None,
    };
    // Unknown sender, file we do not share -> FileNotFound (sent in the clear).
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 4672);
    let reply = runtime
        .reask_reciprocity_reply(&ping, from, OUR_PUBLIC_IP)
        .await
        .expect("a file-not-found reply");
    match parse_inbound_reask_datagram(&reply, OUR_PUBLIC_IP, &[0u8; 16], PEER_UDP_VERSION) {
        Some(InboundReaskMessage::FileNotFound) => {}
        other => panic!("expected FileNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn reask_transfer_info_advertises_partfile_bitmap_for_incomplete_download() {
    use crate::ed2k_transfer::{ED2K_PART_SIZE, new_transfer_job};

    let root = unique_test_dir("ed2k-reask-transfer-info");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    // A fresh two-part job is incomplete with no verified pieces yet.
    let file_hash = Ed2kHash::from_bytes([0x42; 16]);
    let job = new_transfer_job(file_hash, "ubuntu-linux.iso".to_string(), ED2K_PART_SIZE + 7);
    runtime.ensure_job(&job).await.unwrap();

    // Two live sources: one advertises both parts (complete), one only one part.
    let hex = file_hash.to_string();
    runtime.note_download_source_part_bitmap(
        &hex,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 4662),
        None,
        vec![true, true],
    );
    runtime.note_download_source_part_bitmap(
        &hex,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 4662),
        None,
        vec![true, false],
    );

    let info = runtime.reask_transfer_info(&file_hash).await;
    let part_status = info.part_status.expect("a partfile bitmap");
    assert_eq!(part_status.len(), 2);
    assert!(part_status.iter().all(|have| !have));
    // Only the all-parts source counts as complete.
    assert_eq!(info.complete_source_count, 1);

    // An unknown file has no manifest, so no bitmap is advertised.
    let unknown = runtime
        .reask_transfer_info(&Ed2kHash::from_bytes([0x99; 16]))
        .await;
    assert!(unknown.part_status.is_none());
}

#[tokio::test]
async fn reciprocity_is_silent_for_an_unknown_sender_with_room() {
    let root = unique_test_dir("ed2k-reask-reciprocity-silent");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
    // We share the file, but the sender is not queued on us and the queue has
    // room -> deliberate silence (force the peer onto TCP). No datagram.
    runtime
        .shared_catalog()
        .write()
        .await
        .push(shared_entry(&file_hash));

    let ping = ReaskFilePing {
        file_hash,
        part_status: None,
        complete_source_count: None,
    };
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)), 4672);
    assert!(
        runtime
            .reask_reciprocity_reply(&ping, from, OUR_PUBLIC_IP)
            .await
            .is_none()
    );
}
