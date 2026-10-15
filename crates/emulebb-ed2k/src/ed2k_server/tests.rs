use super::TCP_PACKET_HEADER_LEN;
use super::background::send_source_request_batch;
use super::offer_policy::{
    OFFER_FILES_CAPABILITY_VERSION, OfferFilesCapabilityAdvertisement, OfferFilesPolicy,
};
use super::session::{OfferFilesPacingMode, ServerSessionPhase};
use super::session_driver::ServerSessionExit;
use super::types::ServerSessionContext;
use super::{
    BackgroundServerSearchRequest, CT_EMULE_VERSION, CT_NAME, CT_SERVER_FLAGS,
    CT_SERVER_UDPSEARCH_FLAGS, CT_VERSION, ConfiguredServerEntry, ED2K_FILETYPE_PROGRAM,
    EDONKEY_VERSION, EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_TCP_CRYPT_MAGIC_REQUESTER,
    EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC, EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT,
    EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER, EMULE_VERSION_MAJOR, EMULE_VERSION_MINOR,
    EMULE_VERSION_UPDATE, Ed2kFoundSource, Ed2kHash, Ed2kPacket, Ed2kSearchFile, Ed2kServerFailure,
    Ed2kServerFailurePhase, Ed2kServerFailureReason, Ed2kServerListEvent,
    Ed2kServerSourceBatchTarget, Ed2kServerState, Ed2kUdpSourceRequestTarget, FT_AICH_HASH,
    FT_COMPLETE_SOURCES, FT_FILENAME, FT_FILERATING, FT_FILESIZE, FT_FILESIZE_HI, FT_FILETYPE,
    FT_FOLDERNAME, FT_SOURCES, HELLO_NICKNAME, OFFER_FILE_SAMPLE_HASH, OFFER_FILE_SAMPLE_NAME,
    OFFER_FILE_SAMPLE_SIZE, OP_EDONKEYPROT, OP_EMULEPROT, OP_FOUNDSOURCES, OP_GETSERVERLIST,
    OP_GETSOURCES, OP_GETSOURCES_OBFU, OP_GLOBFOUNDSOURCES, OP_GLOBGETSOURCES, OP_GLOBGETSOURCES2,
    OP_GLOBSEARCHREQ, OP_GLOBSEARCHREQ2, OP_GLOBSEARCHREQ3, OP_GLOBSEARCHRES, OP_GLOBSERVSTATRES,
    OP_IDCHANGE, OP_LOGINREQUEST, OP_OFFERFILES, OP_PACKEDPROT, OP_QUERY_MORE_RESULT, OP_REJECT,
    OP_SEARCHREQUEST, OP_SEARCHRESULT, OP_SERVERIDENT, OP_SERVERSTATUS,
    PendingBackgroundServerSearch, ResolvedServerEntry, SERVER_OBFUSCATION_PRIME_BYTES,
    SERVER_OBFUSCATION_PUBLIC_KEY_LEN, SERVER_TCP_FLAG_COMPRESSION, SERVER_TCP_FLAG_LARGEFILES,
    SERVER_TCP_FLAG_TCPOBFUSCATION, SERVER_TCP_FLAG_TYPETAGINTEGER, SERVER_UDP_FLAG_EXT_GETFILES,
    SERVER_UDP_FLAG_EXT_GETSOURCES, SERVER_UDP_FLAG_EXT_GETSOURCES2, SERVER_UDP_FLAG_LARGEFILES,
    SERVER_UDP_FLAG_TCPOBFUSCATION, SERVER_UDP_FLAG_UDPOBFUSCATION,
    SOURCE_OBFUSCATION_USER_HASH_PRESENT, ST_DESCRIPTION, ST_HARDFILES, ST_SERVERNAME,
    ST_SOFTFILES, ServerSession, ServerSessionRole, ServerTransportMode, ServerUdpPacket,
    TAG_SHORT_NAME_MASK, TAGTYPE_STR1, TAGTYPE_STRING, TAGTYPE_UINT8, TAGTYPE_UINT16,
    TAGTYPE_UINT32, TAGTYPE_UINT64, biguint_to_fixed_be, decode_callback_request,
    decode_found_sources, decode_id_change_payload, decode_search_result_page,
    decode_search_results, decode_server_ident, decode_server_ident_details,
    decode_server_ident_snapshot, decode_server_payload, decode_server_udp_datagram,
    decode_server_udp_datagram_with_key, derive_server_cipher, derive_server_udp_cipher,
    ed2k_server_list_event_channel, encode_login_request, encode_offer_files_payload,
    encode_packet, encode_search_request, encode_server_udp_crypt_ping, encode_server_udp_datagram,
    encode_source_request, encode_udp_search_request, encode_udp_source_request_batch,
    format_server_flags, handle_background_udp_packet, handle_server_packet, ipv4_from_client_id,
    login_identity_for_server_transport, new_ed2k_server_search_channel,
    offer_files_catalog_fingerprint, run_one_server_session, run_server_transport_attempts,
    search_keyword_via_background_session, search_source_batch_via_background_session,
    search_source_via_background_session, server_capabilities, server_opcode_allows_compression,
    server_transport_attempts, server_udp_crypt_ping_endpoint, server_udp_endpoint,
    should_use_server_obfuscation, source_request_opcode, validate_found_sources,
};
use crate::{
    NatManager,
    ed2k_tcp::{Ed2kHelloIdentity, ed2k_callback_session_channel, emule_connect_options},
    ed2k_transfer::{Ed2kSharedEntry, IndexedSharedCatalog},
    kad_firewall::KadFirewallState,
    reachability::ExternalReachability,
};
use flate2::{Compression, write::ZlibEncoder};
use hex::decode;
use num_bigint::BigUint;
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
};
use tokio_util::sync::CancellationToken;

fn test_server(obfuscation_port_tcp: u16, udp_flags: u32) -> ResolvedServerEntry {
    ResolvedServerEntry {
        entry: ConfiguredServerEntry {
            host: "127.0.0.1".to_string(),
            port: 4661,
            name: Some("test".to_string()),
            description: None,
            dynamic_host: None,
            udp_flags,
            udp_key: 0,
            udp_key_ip: 0,
            obfuscation_port_tcp,
            obfuscation_port_udp: 0,
            soft_files: 0,
            hard_files: 0,
            priority: "normal".to_string(),
            static_server: false,
        },
        ip: Ipv4Addr::LOCALHOST,
    }
}

fn test_udp_obfuscated_server() -> ResolvedServerEntry {
    ResolvedServerEntry {
        entry: ConfiguredServerEntry {
            host: "127.0.0.1".to_string(),
            port: 4661,
            name: Some("test".to_string()),
            description: None,
            dynamic_host: None,
            udp_flags: SERVER_UDP_FLAG_UDPOBFUSCATION | SERVER_UDP_FLAG_EXT_GETSOURCES2,
            udp_key: 0x1122_3344,
            udp_key_ip: 0x5566_7788,
            obfuscation_port_tcp: 4661,
            obfuscation_port_udp: 4675,
            soft_files: 0,
            hard_files: 0,
            priority: "normal".to_string(),
            static_server: false,
        },
        ip: Ipv4Addr::LOCALHOST,
    }
}

#[test]
fn callback_request_only_trusts_crypt_profile_with_user_hash() {
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&u32::from_le_bytes([127, 0, 0, 1]).to_le_bytes());
    truncated.extend_from_slice(&4662u16.to_le_bytes());
    truncated.push(emule_connect_options(true));

    let callback = decode_callback_request(&truncated)
        .unwrap()
        .expect("callback");

    assert_eq!(callback.peer_addr, "127.0.0.1:4662".parse().unwrap());
    assert_eq!(callback.connect_options, None);
    assert_eq!(callback.user_hash, None);

    let mut full = truncated;
    full.extend_from_slice(&[0x11; 16]);
    let callback = decode_callback_request(&full).unwrap().expect("callback");

    assert_eq!(callback.connect_options, Some(emule_connect_options(true)));
    assert_eq!(callback.user_hash, Some([0x11; 16]));
}

#[test]
fn id_change_decoder_preserves_zero_client_id_as_unaccepted_login() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&SERVER_TCP_FLAG_TCPOBFUSCATION.to_le_bytes());
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(&u32::from_le_bytes([127, 0, 0, 1]).to_le_bytes());

    let id_change = decode_id_change_payload(&payload).unwrap();

    assert_eq!(id_change.client_id, 0);
    assert_eq!(id_change.server_flags, Some(SERVER_TCP_FLAG_TCPOBFUSCATION));
    assert_eq!(
        id_change.reported_client_ip,
        Some("127.0.0.1".parse().unwrap())
    );
}

async fn connected_id_change_fixture() -> (
    ServerSession,
    TcpStream,
    tokio::sync::mpsc::UnboundedReceiver<Ed2kServerListEvent>,
    ServerSessionContext,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = TcpStream::connect(addr).await.unwrap();
    let (stream, peer_addr) = listener.accept().await.unwrap();
    let mut session = ServerSession::from_stream_for_test(stream, peer_addr);
    session.server_soft_files = 1_000;

    let (server_list_events, events) = ed2k_server_list_event_channel();
    let (callback_sessions, _callback_inbox) = ed2k_callback_session_channel();
    let shared_catalog = IndexedSharedCatalog::from_entries(vec![Ed2kSharedEntry {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "id-change-offer.bin".to_string(),
        file_size: 1_234,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        media: Default::default(),
        all_time_uploaded_bytes: 0,
        complete_parts: Vec::new(),
        publish: Default::default(),
    }]);
    let context = ServerSessionContext {
        bind_ip: Ipv4Addr::LOCALHOST,
        nat: Arc::new(NatManager::default()),
        hello_identity: Ed2kHelloIdentity {
            user_hash: [0u8; 16],
            client_id: 0,
            tcp_port: 4662,
            udp_port: 4672,
            server_ip: 0,
            server_port: 0,
            connect_options: 0,
            direct_udp_callback: false,
        },
        nickname: "test".to_string(),
        last_client_id: Arc::new(AtomicU32::new(0)),
        probe_search_term: None,
        shared_catalog: Arc::new(RwLock::new(shared_catalog)),
        state: Arc::new(RwLock::new(Ed2kServerState::default())),
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        keepalive_interval: None,
        connect_timeout: Duration::from_secs(25),
        rotation_interval: None,
        shutdown: Arc::new(AtomicBool::new(false)),
        public_ip: ExternalReachability::new(),
        server_list_events: Some(server_list_events),
        add_servers_from_server: false,
        offer_files_capability_enabled: false,
        callback_sessions,
    };
    (session, peer, events, context)
}

async fn read_client_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; TCP_PACKET_HEADER_LEN];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], OP_EDONKEYPROT);
    let payload_len =
        u32::from_le_bytes(header[1..5].try_into().unwrap()).saturating_sub(1) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.unwrap();
    (header[5], payload)
}

async fn read_single_offer_file(stream: &mut TcpStream, expected_client_id: u32) {
    let (opcode, payload) = tokio::time::timeout(Duration::from_secs(1), read_client_frame(stream))
        .await
        .expect("server session should publish one offer-files frame");
    assert_eq!(opcode, OP_OFFERFILES);
    assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 1);
    assert_eq!(
        u32::from_le_bytes(payload[20..24].try_into().unwrap()),
        expected_client_id
    );
}

fn id_change_packet(
    client_id: u32,
    server_flags: u32,
    reported_ip: Option<Ipv4Addr>,
) -> Ed2kPacket {
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&client_id.to_le_bytes());
    payload.extend_from_slice(&server_flags.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    if let Some(reported_ip) = reported_ip {
        payload.extend_from_slice(&reported_ip.octets());
    }
    Ed2kPacket {
        opcode: OP_IDCHANGE,
        payload,
    }
}

#[tokio::test]
async fn redundant_same_id_idchange_does_not_rerun_connected_startup() {
    let (mut session, mut peer, mut events, context) = connected_id_change_fixture().await;
    let client_id = 0x0102_0304;

    handle_server_packet(
        &mut session,
        id_change_packet(client_id, 0, None),
        &context,
        false,
    )
    .await
    .unwrap();

    assert!(session.login_accepted);
    assert_eq!(session.assigned_client_id, Some(client_id));
    assert_eq!(
        context.public_ip.get(),
        Some(ipv4_from_client_id(client_id))
    );
    assert!(matches!(session.phase, ServerSessionPhase::OfferFilesSent));
    assert!(matches!(
        events.try_recv(),
        Ok(Ed2kServerListEvent::ConnectSucceeded { .. })
    ));
    assert!(
        events.try_recv().is_err(),
        "first acceptance emits exactly one ConnectSucceeded event"
    );
    read_single_offer_file(&mut peer, client_id).await;

    handle_server_packet(
        &mut session,
        id_change_packet(client_id, 0, None),
        &context,
        false,
    )
    .await
    .unwrap();

    assert_eq!(session.assigned_client_id, Some(client_id));
    assert!(
        events.try_recv().is_err(),
        "redundant same-ID IDCHANGE must not re-emit ConnectSucceeded"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(75), read_client_frame(&mut peer))
            .await
            .is_err(),
        "redundant same-ID IDCHANGE must not republish the catalog"
    );
}

#[tokio::test]
async fn client_id_reassignment_republishes_catalog_with_new_endpoint() {
    let (mut session, mut peer, mut events, context) = connected_id_change_fixture().await;
    let low_id = 0x0000_0001;
    let high_id = 0x0102_0304;

    context
        .public_ip
        .set_server_public_ip(Ipv4Addr::new(203, 0, 113, 1));
    handle_server_packet(
        &mut session,
        id_change_packet(low_id, 0, None),
        &context,
        false,
    )
    .await
    .unwrap();

    assert!(matches!(
        events.try_recv(),
        Ok(Ed2kServerListEvent::ConnectSucceeded { .. })
    ));
    assert_eq!(session.assigned_client_id, Some(low_id));
    assert!(
        !context.public_ip.is_known(),
        "LowID without a reported IP clears the public IP"
    );
    read_single_offer_file(&mut peer, 0).await;

    handle_server_packet(
        &mut session,
        id_change_packet(high_id, 0, None),
        &context,
        false,
    )
    .await
    .unwrap();

    assert!(matches!(
        events.try_recv(),
        Ok(Ed2kServerListEvent::ConnectSucceeded { .. })
    ));
    assert_eq!(session.assigned_client_id, Some(high_id));
    assert_eq!(context.public_ip.get(), Some(ipv4_from_client_id(high_id)));
    assert!(
        events.try_recv().is_err(),
        "reassignment emits exactly one additional ConnectSucceeded event"
    );
    read_single_offer_file(&mut peer, high_id).await;
}

mod background;
mod decoders;
mod protocol;
