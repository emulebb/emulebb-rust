use super::*;

pub(super) async fn test_dht() -> DhtNode {
    DhtNode::new(DhtConfig {
        bind_addr: Some(test_bind_addr()),
        node_id: NodeId::from_bytes([0x3C; 16]),
        udp_key: 0x1122_3344,
        ..DhtConfig::default()
    })
    .await
    .unwrap()
}

pub(super) fn listener_hello_identity() -> Ed2kHelloIdentity {
    Ed2kHelloIdentity {
        user_hash: [0x22; 16],
        client_id: 0x1234_5678,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    }
}

pub(super) fn peer_hello_identity() -> Ed2kHelloIdentity {
    Ed2kHelloIdentity {
        user_hash: [0x77; 16],
        client_id: 0x8765_4321,
        tcp_port: 46671,
        udp_port: 46672,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    }
}

pub(super) fn listener_secure_ident() -> Arc<Ed2kSecureIdent> {
    test_peer_secure_ident()
}

pub(super) fn listener_test_identity(
    user_hash_byte: u8,
    client_id: u32,
    tcp_port: u16,
    udp_port: u16,
) -> Ed2kHelloIdentity {
    Ed2kHelloIdentity {
        user_hash: [user_hash_byte; 16],
        client_id,
        tcp_port,
        udp_port,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    }
}

pub(super) struct VerifiedUploadFile {
    pub(super) file_hash: Ed2kHash,
    pub(super) payload: Vec<u8>,
}

pub(super) struct ListenerTestRuntime {
    listener: Option<TcpListener>,
    dht: DhtNode,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    secure_ident: Arc<Ed2kSecureIdent>,
    hello_identity: Ed2kHelloIdentity,
    pub(super) peer_addr: SocketAddr,
    pub(super) transfer_runtime: Arc<Ed2kTransferRuntime>,
}

impl ListenerTestRuntime {
    pub(super) async fn new(
        root_name: &str,
        hello_identity: Ed2kHelloIdentity,
        dht_node_id: [u8; 16],
        udp_key: u32,
    ) -> Self {
        let root = unique_test_dir(root_name);
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(test_bind_addr()),
            node_id: NodeId::from_bytes(dht_node_id),
            udp_key,
            ..DhtConfig::default()
        })
        .await
        .unwrap();

        Self {
            listener: Some(listener),
            dht,
            server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            secure_ident: listener_secure_ident(),
            hello_identity,
            peer_addr,
            transfer_runtime,
        }
    }

    pub(super) async fn use_one_slot_upload_queue(&self) {
        self.transfer_runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                elastic_percent: 0,
                upload_limit_bytes_per_sec: 0,
                elastic_underfill_bytes_per_sec: 0,
                elastic_underfill: Duration::from_secs(10),
                waiting_capacity: 8,
                soft_queue_size: 10_000,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
                session_transfer_percent: 0,
                session_time_limit: Duration::ZERO,
            })
            .await;
    }

    pub(super) async fn seed_verified_upload_file(
        &self,
        name: &str,
        payload: Vec<u8>,
    ) -> VerifiedUploadFile {
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let job = new_transfer_job(file_hash, name.to_string(), payload.len() as u64);
        self.transfer_runtime.ensure_job(&job).await.unwrap();
        self.transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        self.transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        VerifiedUploadFile { file_hash, payload }
    }

    /// Build the outbound promote-connect driver over this fixture's runtime,
    /// for tests that drive the disconnected-waiter slot-grant path directly.
    pub(super) fn upload_promote_driver(
        &self,
    ) -> Arc<crate::ed2k_tcp::upload_promote::UploadPromoteDriver> {
        Arc::new(crate::ed2k_tcp::upload_promote::UploadPromoteDriver {
            dht: self.dht.clone(),
            server_state: Arc::clone(&self.server_state),
            kad_firewall: Arc::clone(&self.kad_firewall),
            secure_ident: Arc::clone(&self.secure_ident),
            transfer_runtime: Arc::clone(&self.transfer_runtime),
            hello_identity: self.hello_identity,
            reachability: crate::reachability::ExternalReachability::new(),
            buddy_registry: crate::buddy_socket::BuddySocketRegistry::new(),
            bind_ip: test_bind_ip(),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    pub(super) fn spawn_listener_connections(
        &mut self,
        connection_count: usize,
    ) -> tokio::task::JoinHandle<()> {
        let listener = self.listener.take().expect("listener already spawned");
        let dht = self.dht.clone();
        let transfer_runtime = Arc::clone(&self.transfer_runtime);
        let server_state = Arc::clone(&self.server_state);
        let kad_firewall = Arc::clone(&self.kad_firewall);
        let secure_ident = Arc::clone(&self.secure_ident);
        let hello_identity = self.hello_identity;

        tokio::spawn(async move {
            let mut sessions = Vec::with_capacity(connection_count);
            for _ in 0..connection_count {
                let (stream, addr) = listener.accept().await.unwrap();
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                sessions.push(tokio::spawn(async move {
                    handle_connection_test!(
                        stream,
                        addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await
                }));
            }

            for session in sessions {
                session.await.unwrap().unwrap();
            }
        })
    }

    pub(super) fn spawn_listener_loop(&mut self) -> tokio::task::JoinHandle<()> {
        let listener = self.listener.take().expect("listener already spawned");
        let dht = self.dht.clone();
        let transfer_runtime = Arc::clone(&self.transfer_runtime);
        let server_state = Arc::clone(&self.server_state);
        let kad_firewall = Arc::clone(&self.kad_firewall);
        let secure_ident = Arc::clone(&self.secure_ident);
        let hello_identity = self.hello_identity;

        tokio::spawn(async move {
            loop {
                let (stream, addr) = listener.accept().await.unwrap();
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                tokio::spawn(async move {
                    let _ = handle_connection_test!(
                        stream,
                        addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await;
                });
            }
        })
    }
}

pub(super) fn spawn_single_listener_connection(
    listener: TcpListener,
    dht: DhtNode,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    secure_ident: Arc<Ed2kSecureIdent>,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    hello_identity: Ed2kHelloIdentity,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        handle_connection_test!(
            stream,
            remote_addr,
            &dht,
            &server_state,
            &kad_firewall,
            &secure_ident,
            &transfer_runtime,
            hello_identity,
        )
        .await
        .unwrap();
    })
}

pub(super) async fn connect_peer_and_exchange_hello(
    peer_addr: SocketAddr,
    peer_identity: Ed2kHelloIdentity,
) -> TcpStream {
    let mut stream = TcpStream::connect(peer_addr).await.unwrap();
    stream
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _hello_answer = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    stream
}

/// Drive the peer side of a full mutual secure-ident exchange against the
/// listener so the listener RSA-verifies the peer (eMule `IS_IDENTIFIED`): the
/// peer answers the listener's challenge with a real signature over the
/// listener's public key, which is the prerequisite for credit attribution.
/// Must be called immediately after the hello, before any upload requests.
pub(super) async fn complete_peer_secure_ident_with_listener(
    stream: &mut TcpStream,
    peer_secure_ident: &Ed2kSecureIdent,
) {
    // 1) Listener probes us with KEY_AND_SIGNATURE_NEEDED + its challenge.
    let probe = read_until_opcode(stream, OP_EMULEPROT, OP_SECIDENTSTATE).await;
    let (_state, listener_challenge) = decode_secident_state(&probe[6..]).unwrap();

    // 2) Send our public key, then challenge the listener for its key+signature.
    stream
        .write_all(&encode_packet(
            OP_EMULEPROT,
            OP_PUBLICKEY,
            &peer_secure_ident.public_key_payload().unwrap(),
        ))
        .await
        .unwrap();
    let peer_challenge = 0x1357_9BDFu32;
    stream
        .write_all(&encode_secident_state(
            ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
            peer_challenge,
        ))
        .await
        .unwrap();

    // 3) Listener answers with its public key; sign it + the listener challenge.
    let listener_public_key = read_until_opcode(stream, OP_EMULEPROT, OP_PUBLICKEY).await;
    let listener_public_key = decode_public_key_payload(&listener_public_key[6..]).unwrap();
    stream
        .write_all(&encode_packet(
            OP_EMULEPROT,
            OP_SIGNATURE,
            &peer_secure_ident
                .signature_payload(&listener_public_key, listener_challenge)
                .unwrap(),
        ))
        .await
        .unwrap();
}

pub(super) async fn connect_obfuscated_peer_and_exchange_hello(
    peer_addr: SocketAddr,
    listener_user_hash: [u8; 16],
    peer_identity: Ed2kHelloIdentity,
) -> Ed2kTransport {
    let mut transport = Ed2kTransport::connect_outgoing(
        test_bind_ip(),
        peer_addr,
        emule_connect_options(true),
        Some(listener_user_hash),
        Some(emule_connect_options(true)),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(transport.mode, Ed2kTransportMode::Obfuscated);
    transport
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _hello_answer =
        read_transport_until_opcode(&mut transport, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    transport
}

pub(super) async fn connect_peer_and_request_upload(
    peer_addr: SocketAddr,
    peer_identity: Ed2kHelloIdentity,
    file_hash: &Ed2kHash,
) -> TcpStream {
    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_identity).await;
    stream
        .write_all(&encode_start_upload_req(file_hash))
        .await
        .unwrap();
    stream
}

pub(super) async fn connect_obfuscated_peer_and_request_upload(
    peer_addr: SocketAddr,
    listener_user_hash: [u8; 16],
    peer_identity: Ed2kHelloIdentity,
    file_hash: &Ed2kHash,
) -> Ed2kTransport {
    let mut transport =
        connect_obfuscated_peer_and_exchange_hello(peer_addr, listener_user_hash, peer_identity)
            .await;
    transport
        .write_all(&encode_start_upload_req(file_hash))
        .await
        .unwrap();
    transport
}

pub(super) async fn connect_peer_until_upload_accepted(
    peer_addr: SocketAddr,
    peer_identity: Ed2kHelloIdentity,
    file_hash: &Ed2kHash,
) -> TcpStream {
    let mut stream = connect_peer_and_request_upload(peer_addr, peer_identity, file_hash).await;
    let accepted = wait_for_upload_accept(&mut stream).await;
    assert_eq!(accepted.len(), 6);
    stream
}

pub(super) async fn connect_obfuscated_peer_until_upload_accepted(
    peer_addr: SocketAddr,
    listener_user_hash: [u8; 16],
    peer_identity: Ed2kHelloIdentity,
    file_hash: &Ed2kHash,
) -> Ed2kTransport {
    let mut transport = connect_obfuscated_peer_and_request_upload(
        peer_addr,
        listener_user_hash,
        peer_identity,
        file_hash,
    )
    .await;
    wait_for_transport_upload_accept(&mut transport).await;
    transport
}

pub(super) async fn connect_peer_until_queue_rank(
    peer_addr: SocketAddr,
    peer_identity: Ed2kHelloIdentity,
    file_hash: &Ed2kHash,
    expected_rank: u16,
) -> TcpStream {
    let mut stream = connect_peer_and_request_upload(peer_addr, peer_identity, file_hash).await;
    wait_for_queue_rank(&mut stream, expected_rank).await;
    stream
}

pub(super) async fn connect_obfuscated_peer_until_queue_rank(
    peer_addr: SocketAddr,
    listener_user_hash: [u8; 16],
    peer_identity: Ed2kHelloIdentity,
    file_hash: &Ed2kHash,
    expected_rank: u16,
) -> Ed2kTransport {
    let mut transport = connect_obfuscated_peer_and_request_upload(
        peer_addr,
        listener_user_hash,
        peer_identity,
        file_hash,
    )
    .await;
    wait_for_transport_queue_rank(&mut transport, expected_rank).await;
    transport
}

pub(super) async fn wait_for_queue_rank(stream: &mut TcpStream, expected_rank: u16) {
    let queue_ranking = read_until_opcode(stream, OP_EMULEPROT, OP_QUEUERANKING).await;
    assert_eq!(
        u16::from_le_bytes([queue_ranking[6], queue_ranking[7]]),
        expected_rank
    );
}

pub(super) async fn wait_for_transport_queue_rank(
    transport: &mut Ed2kTransport,
    expected_rank: u16,
) {
    let queue_ranking = read_transport_until_opcode(transport, OP_EMULEPROT, OP_QUEUERANKING).await;
    assert_eq!(
        u16::from_le_bytes([queue_ranking.payload[0], queue_ranking.payload[1]]),
        expected_rank
    );
}

pub(super) async fn wait_for_queue_rank_timeout(stream: &mut TcpStream, expected_rank: u16) {
    tokio::time::timeout(
        Duration::from_secs(2),
        wait_for_queue_rank(stream, expected_rank),
    )
    .await
    .unwrap();
}

/// Assert that NO queue ranking is pushed within `window`: the oracle sends
/// rank only in response to a re-ask (SendRankingInfo call sites,
/// UploadQueue.cpp:1866,1963,1986), never unsolicited on a timer.
pub(super) async fn assert_queue_rank_silence(stream: &mut TcpStream, window: Duration) {
    let pushed = tokio::time::timeout(
        window,
        read_until_opcode(stream, OP_EMULEPROT, OP_QUEUERANKING),
    )
    .await;
    assert!(
        pushed.is_err(),
        "an unsolicited OP_QUEUERANKING was pushed on a waiting connection"
    );
}

/// Assert that NO upload-request reply (OP_FILEREQANSNOFIL, OP_ACCEPTUPLOADREQ
/// or OP_QUEUERANKING) arrives within `window` and the connection stays open.
/// The oracle answers an OP_STARTUPLOADREQ for an unknown file with silence
/// (only CheckFailedFileIdReqs bookkeeping, ListenSocket.cpp:706-707).
/// Unrelated packets (e.g. the secure-ident probe) may still flow.
pub(super) async fn assert_start_upload_silence(stream: &mut TcpStream, window: Duration) {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining, try_read_packet(stream)).await {
            // The window elapsed in silence.
            Err(_elapsed) => return,
            Ok(Err(err)) => panic!("connection dropped during the silence window: {err}"),
            Ok(Ok(packet)) => {
                let reply = (packet[0], packet[5]);
                assert!(
                    reply != (OP_EDONKEYPROT, OP_FILEREQANSNOFIL)
                        && reply != (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ)
                        && reply != (OP_EMULEPROT, OP_QUEUERANKING),
                    "unexpected OP_STARTUPLOADREQ reply opcode 0x{:02X}",
                    packet[5]
                );
            }
        }
    }
}

pub(super) async fn wait_for_upload_accept(stream: &mut TcpStream) -> Vec<u8> {
    read_until_opcode(stream, OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ).await
}

pub(super) async fn wait_for_transport_upload_accept(transport: &mut Ed2kTransport) {
    let accepted = read_transport_until_opcode(transport, OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ).await;
    assert!(accepted.payload.is_empty());
}

pub(super) async fn wait_for_upload_accept_timeout(stream: &mut TcpStream) {
    let accepted = tokio::time::timeout(Duration::from_secs(3), wait_for_upload_accept(stream))
        .await
        .unwrap();
    assert_eq!(accepted.len(), 6);
}

pub(super) async fn wait_for_transport_upload_accept_timeout(transport: &mut Ed2kTransport) {
    tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_transport_upload_accept(transport),
    )
    .await
    .unwrap();
}

pub(super) async fn send_cancel_transfer(stream: &mut TcpStream) {
    stream
        .write_all(&encode_packet(OP_EDONKEYPROT, OP_CANCELTRANSFER, &[]))
        .await
        .unwrap();
}

pub(super) async fn send_transport_cancel_transfer(transport: &mut Ed2kTransport) {
    transport
        .write_all(&encode_packet(OP_EDONKEYPROT, OP_CANCELTRANSFER, &[]))
        .await
        .unwrap();
}

pub(super) async fn request_upload_file(stream: &mut TcpStream, file_hash: &Ed2kHash) {
    stream
        .write_all(&encode_start_upload_req(file_hash))
        .await
        .unwrap();
}

pub(super) async fn request_upload_parts(
    stream: &mut TcpStream,
    file_hash: &Ed2kHash,
    ranges: &[(u64, u64)],
) {
    stream
        .write_all(&encode_request_parts_batch(file_hash, ranges).unwrap())
        .await
        .unwrap();
}

pub(super) async fn request_transport_upload_parts(
    transport: &mut Ed2kTransport,
    file_hash: &Ed2kHash,
    ranges: &[(u64, u64)],
) {
    transport
        .write_all(&encode_request_parts_batch(file_hash, ranges).unwrap())
        .await
        .unwrap();
}

pub(super) async fn read_upload_bytes(
    stream: &mut TcpStream,
    file_hash: &Ed2kHash,
    expected_start: u64,
    expected_end: u64,
) -> Vec<u8> {
    let mut reconstructed = Vec::new();
    let mut pending = None;
    while reconstructed.len() < usize::try_from(expected_end - expected_start).unwrap() {
        let packet = tokio::time::timeout(Duration::from_secs(5), read_packet(stream))
            .await
            .expect("timed out waiting for upload payload");
        match (packet[0], packet[5]) {
            (OP_EMULEPROT, OP_COMPRESSEDPART) => {
                let (decoded_hash, start, advertised_len, fragment) =
                    decode_compressed_part_fragment(&packet[6..], false).unwrap();
                assert_eq!(decoded_hash, *file_hash);
                // The serve walks the requested range in EMBLOCKSIZE blocks, each
                // its own zlib stream possibly spanning several wire fragments
                // (all sharing the same `start`); a new block opens (pending ==
                // None) at the next contiguous offset.
                if pending.is_none() {
                    assert_eq!(
                        start,
                        expected_start + u64::try_from(reconstructed.len()).unwrap()
                    );
                }
                let block_end = (start + ED2K_EMBLOCK_SIZE).min(expected_end);
                let pending_stream = pending.get_or_insert_with(|| PendingCompressedPart {
                    piece_index: 0,
                    start,
                    end: block_end,
                    advertised_compressed_len: advertised_len,
                    compressed_received: 0,
                    uncompressed_written: 0,
                    inflater: Decompress::new(true),
                    zstream_error: false,
                });
                let (bytes, finished) =
                    inflate_compressed_part_fragment(pending_stream, fragment).unwrap();
                reconstructed.extend_from_slice(&bytes);
                if finished {
                    pending = None;
                }
            }
            (OP_EDONKEYPROT, OP_SENDINGPART) => {
                let (decoded_hash, start, end, bytes) =
                    decode_sending_part_payload(&packet[6..], false).unwrap();
                assert_eq!(decoded_hash, *file_hash);
                assert_eq!(
                    start,
                    expected_start + u64::try_from(reconstructed.len()).unwrap()
                );
                assert_eq!(end, start + u64::try_from(bytes.len()).unwrap());
                reconstructed.extend_from_slice(&bytes);
            }
            _ => {}
        }
    }
    reconstructed
}

pub(super) async fn read_transport_upload_bytes(
    transport: &mut Ed2kTransport,
    file_hash: &Ed2kHash,
    expected_start: u64,
    expected_end: u64,
) -> (Vec<u8>, bool) {
    let mut reconstructed = Vec::new();
    let mut saw_compressed = false;
    let mut pending = None;
    while reconstructed.len() < usize::try_from(expected_end - expected_start).unwrap() {
        let packet = tokio::time::timeout(Duration::from_secs(5), transport.read_packet())
            .await
            .expect("timed out waiting for upload payload")
            .unwrap()
            .expect("transport closed before upload payload completed");
        match (packet.protocol, packet.opcode) {
            (OP_EMULEPROT, OP_COMPRESSEDPART) => {
                saw_compressed = true;
                let (decoded_hash, start, advertised_len, fragment) =
                    decode_compressed_part_fragment(&packet.payload, false).unwrap();
                assert_eq!(decoded_hash, *file_hash);
                // The serve walks the requested range in EMBLOCKSIZE blocks, each
                // its own complete zlib stream. A block's compressed stream may
                // span several wire fragments, all carrying the same `start`; a
                // new block begins (pending == None) at the next contiguous
                // offset. Only validate `start` when a new block opens.
                if pending.is_none() {
                    assert_eq!(
                        start,
                        expected_start + u64::try_from(reconstructed.len()).unwrap()
                    );
                }
                let block_end = (start + ED2K_EMBLOCK_SIZE).min(expected_end);
                let pending_stream = pending.get_or_insert_with(|| PendingCompressedPart {
                    piece_index: 0,
                    start,
                    end: block_end,
                    advertised_compressed_len: advertised_len,
                    compressed_received: 0,
                    uncompressed_written: 0,
                    inflater: Decompress::new(true),
                    zstream_error: false,
                });
                let (bytes, finished) =
                    inflate_compressed_part_fragment(pending_stream, fragment).unwrap();
                reconstructed.extend_from_slice(&bytes);
                if finished {
                    pending = None;
                }
            }
            (OP_EDONKEYPROT, OP_SENDINGPART) => {
                let (decoded_hash, start, end, bytes) =
                    decode_sending_part_payload(&packet.payload, false).unwrap();
                assert_eq!(decoded_hash, *file_hash);
                assert_eq!(
                    start,
                    expected_start + u64::try_from(reconstructed.len()).unwrap()
                );
                assert_eq!(end, start + u64::try_from(bytes.len()).unwrap());
                reconstructed.extend_from_slice(&bytes);
            }
            _ => {}
        }
    }
    (reconstructed, saw_compressed)
}

/// Obfuscated-transport counterpart of [`complete_peer_secure_ident_with_listener`].
pub(super) async fn complete_peer_secure_ident_with_listener_transport(
    transport: &mut Ed2kTransport,
    peer_secure_ident: &Ed2kSecureIdent,
) {
    let probe = read_transport_until_opcode(transport, OP_EMULEPROT, OP_SECIDENTSTATE).await;
    let (_state, listener_challenge) = decode_secident_state(&probe.payload).unwrap();

    transport
        .write_all(
            &encode_packed_packet(
                OP_PUBLICKEY,
                &peer_secure_ident.public_key_payload().unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let peer_challenge = 0x1357_9BDFu32;
    transport
        .write_all(&encode_secident_state(
            ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
            peer_challenge,
        ))
        .await
        .unwrap();

    let listener_public_key =
        read_transport_until_opcode(transport, OP_EMULEPROT, OP_PUBLICKEY).await;
    let listener_public_key = decode_public_key_payload(&listener_public_key.payload).unwrap();
    transport
        .write_all(
            &encode_packed_packet(
                OP_SIGNATURE,
                &peer_secure_ident
                    .signature_payload(&listener_public_key, listener_challenge)
                    .unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
}

pub(super) async fn read_transport_until_opcode(
    transport: &mut Ed2kTransport,
    protocol: u8,
    opcode: u8,
) -> EmuleTcpPacket {
    loop {
        let packet = tokio::time::timeout(Duration::from_secs(5), transport.read_packet())
            .await
            .expect("timed out waiting for eD2k transport packet")
            .unwrap()
            .expect("transport closed before expected packet");
        if packet.protocol == protocol && packet.opcode == opcode {
            return packet;
        }
    }
}
