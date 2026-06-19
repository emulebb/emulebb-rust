use super::*;

pub(super) fn test_peer_secure_ident() -> Arc<Ed2kSecureIdent> {
    Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    )
}

pub(super) fn test_peer_hello(peer_addr: SocketAddr) -> Vec<u8> {
    test_peer_hello_with_obfuscation(peer_addr, [0x42; 16], false)
}

pub(super) fn test_peer_hello_with_obfuscation(
    peer_addr: SocketAddr,
    user_hash: [u8; 16],
    obfuscation_enabled: bool,
) -> Vec<u8> {
    encode_hello_answer(Ed2kHelloIdentity {
        user_hash,
        client_id: 0x5912_0559,
        tcp_port: peer_addr.port(),
        udp_port: 0,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(obfuscation_enabled),
        direct_udp_callback: false,
    })
}

pub(super) async fn start_plain_download_session(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    _peer_secure_ident: &Ed2kSecureIdent,
) {
    let hello = read_packet(stream).await;
    assert_eq!(hello[0], OP_EDONKEYPROT);
    assert_eq!(hello[5], OP_HELLO);
    stream.write_all(&test_peer_hello(peer_addr)).await.unwrap();

    let secure_ident_probe = read_packet(stream).await;
    assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
    assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
}

pub(super) async fn start_obfuscated_download_session(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    peer_user_hash: [u8; 16],
    _peer_secure_ident: &Ed2kSecureIdent,
) {
    let hello = transport.read_packet().await.unwrap().unwrap();
    assert_eq!(hello.protocol, OP_EDONKEYPROT);
    assert_eq!(hello.opcode, OP_HELLO);
    transport
        .write_all(&test_peer_hello_with_obfuscation(
            peer_addr,
            peer_user_hash,
            true,
        ))
        .await
        .unwrap();

    let secure_ident_probe = transport.read_packet().await.unwrap().unwrap();
    assert_eq!(secure_ident_probe.protocol, OP_EMULEPROT);
    assert_eq!(secure_ident_probe.opcode, OP_SECIDENTSTATE);
}

pub(super) async fn answer_startup_metadata(
    stream: &mut TcpStream,
    file_hash: &Ed2kHash,
    file_size: u64,
    file_name: &str,
    include_file_status: bool,
) {
    answer_startup_metadata_with_expected_size(
        stream,
        file_hash,
        file_size,
        file_size,
        file_name,
        include_file_status,
    )
    .await;
}

pub(super) async fn answer_startup_metadata_with_expected_size(
    stream: &mut TcpStream,
    file_hash: &Ed2kHash,
    expected_request_size: u64,
    answer_file_size: u64,
    file_name: &str,
    include_file_status: bool,
) {
    let startup_request = read_packet(stream).await;
    assert_startup_multipacket_ext2(
        startup_request[0],
        startup_request[5],
        &startup_request[6..],
        file_hash,
        expected_request_size,
        false,
    );
    let filename_answer = encode_startup_multipacket_ext2_answer(
        file_hash,
        answer_file_size,
        file_name,
        include_file_status,
    );
    stream.write_all(&filename_answer).await.unwrap();
}

pub(super) async fn answer_transport_startup_metadata(
    transport: &mut Ed2kTransport,
    file_hash: &Ed2kHash,
    file_size: u64,
    file_name: &str,
    include_file_status: bool,
) {
    answer_transport_startup_metadata_with_source_exchange(
        transport,
        file_hash,
        file_size,
        file_name,
        include_file_status,
        true,
    )
    .await;
}

pub(super) async fn answer_transport_startup_metadata_with_source_exchange(
    transport: &mut Ed2kTransport,
    file_hash: &Ed2kHash,
    file_size: u64,
    file_name: &str,
    include_file_status: bool,
    expect_request_sources2: bool,
) {
    let startup_request = transport.read_packet().await.unwrap().unwrap();
    assert_startup_multipacket_ext2_with_source_exchange(
        startup_request.protocol,
        startup_request.opcode,
        &startup_request.payload,
        file_hash,
        file_size,
        false,
        expect_request_sources2,
    );
    let filename_answer = encode_startup_multipacket_ext2_answer(
        file_hash,
        file_size,
        file_name,
        include_file_status,
    );
    transport.write_all(&filename_answer).await.unwrap();
}

pub(super) async fn accept_upload_and_read_parts_request(
    stream: &mut TcpStream,
    use_i64: bool,
) -> (Ed2kHash, Vec<(u64, u64)>) {
    let start_upload = read_packet(stream).await;
    assert_eq!(start_upload[0], OP_EDONKEYPROT);
    assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
    stream.write_all(&encode_accept_upload_req()).await.unwrap();

    let request_parts = read_packet(stream).await;
    let expected_opcode = if use_i64 {
        super::OP_REQUESTPARTS_I64
    } else {
        OP_REQUESTPARTS
    };
    assert_eq!(request_parts[0], OP_EDONKEYPROT);
    assert_eq!(request_parts[5], expected_opcode);
    decode_request_parts_payload(&request_parts[6..], use_i64).unwrap()
}

pub(super) async fn accept_transport_upload_and_read_parts_request(
    transport: &mut Ed2kTransport,
    use_i64: bool,
) -> (Ed2kHash, Vec<(u64, u64)>) {
    let start_upload = transport.read_packet().await.unwrap().unwrap();
    assert_eq!(start_upload.protocol, OP_EDONKEYPROT);
    assert_eq!(start_upload.opcode, super::OP_STARTUPLOADREQ);
    transport
        .write_all(&encode_accept_upload_req())
        .await
        .unwrap();

    let request_parts = transport.read_packet().await.unwrap().unwrap();
    let expected_opcode = if use_i64 {
        super::OP_REQUESTPARTS_I64
    } else {
        OP_REQUESTPARTS
    };
    assert_eq!(request_parts.protocol, OP_EDONKEYPROT);
    assert_eq!(request_parts.opcode, expected_opcode);
    decode_request_parts_payload(&request_parts.payload, use_i64).unwrap()
}
