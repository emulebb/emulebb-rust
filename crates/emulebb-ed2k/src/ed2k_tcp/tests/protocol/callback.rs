use super::*;
use crate::ed2k_tcp::{reply_with_firewall_udp, send_kad_firewall_tcp_ack};

#[tokio::test]
async fn callback_connect_uses_plaintext_when_peer_has_no_crypt_metadata() {
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut packet = [0u8; 6];
        stream.read_exact(&mut packet).await.unwrap();
        packet
    });

    let mode = connect_callback_peer(
        test_bind_ip(),
        peer_addr,
        Ed2kHelloIdentity {
            user_hash: [0x55; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        None,
        None,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(mode, Ed2kPeerConnectMode::Plaintext);
    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLO);
}

#[tokio::test]
async fn callback_connect_uses_obfuscation_when_peer_supports_crypt() {
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_user_hash = [0x66; 16];
    let expected_hello = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x77; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });
    let expected_hello_for_server = expected_hello.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut prefix = [0u8; 5];
        stream.read_exact(&mut prefix).await.unwrap();
        assert!(!matches!(
            prefix[0],
            OP_EDONKEYPROT | OP_EMULEPROT | super::OP_PACKEDPROT
        ));
        let random_key_part = [prefix[1], prefix[2], prefix[3], prefix[4]];

        let mut receive_cipher = derive_obfuscation_key(
            peer_user_hash,
            EMULE_TCP_CRYPT_MAGIC_REQUESTER,
            random_key_part,
        );
        let mut send_cipher = derive_obfuscation_key(
            peer_user_hash,
            EMULE_TCP_CRYPT_MAGIC_SERVER,
            random_key_part,
        );

        let mut encrypted_header = [0u8; 7];
        stream.read_exact(&mut encrypted_header).await.unwrap();
        let (padding_len, _, requested_method) =
            decode_incoming_obfuscation_header(&mut receive_cipher, encrypted_header).unwrap();
        assert_eq!(requested_method, EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        if padding_len > 0 {
            let mut encrypted_padding = vec![0u8; padding_len];
            stream.read_exact(&mut encrypted_padding).await.unwrap();
            receive_cipher.apply(&mut encrypted_padding);
        }

        let mut response = Vec::new();
        response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        response.push(0);
        send_cipher.apply(&mut response);
        stream.write_all(&response).await.unwrap();

        let mut encrypted_packet = vec![0u8; expected_hello_for_server.len()];
        stream.read_exact(&mut encrypted_packet).await.unwrap();
        receive_cipher.apply(&mut encrypted_packet);
        encrypted_packet
    });

    let mode = connect_callback_peer(
        test_bind_ip(),
        peer_addr,
        Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        Some(peer_user_hash),
        Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(mode, Ed2kPeerConnectMode::Obfuscated);
    assert_eq!(packet, expected_hello);
}

#[tokio::test]
async fn callback_connect_stays_plaintext_when_local_obfuscation_is_disabled() {
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let expected_hello = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x88; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });
    let expected_hello_for_server = expected_hello.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut packet = vec![0u8; expected_hello_for_server.len()];
        stream.read_exact(&mut packet).await.unwrap();
        let reply = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0xAA; 16],
            client_id: 0x521B_5895,
            tcp_port: 46671,
            udp_port: 46673,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&reply).await.unwrap();
        packet
    });

    let mode = connect_callback_peer(
        test_bind_ip(),
        peer_addr,
        Ed2kHelloIdentity {
            user_hash: [0x88; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        Some([0x99; 16]),
        Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(mode, Ed2kPeerConnectMode::Plaintext);
    assert_eq!(packet, expected_hello);
}

#[tokio::test]
async fn udp_firewall_check_request_completes_hello_exchange_before_request() {
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let helper_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, peer_addr) = listener.accept().await.unwrap();
        assert_eq!(peer_addr.ip(), IpAddr::V4(test_bind_ip()));

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[0], OP_EDONKEYPROT);
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x10; 16],
            client_id: 0x521B_5895,
            tcp_port: 46671,
            udp_port: 46673,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let emule_info = encode_emule_info_request(46673);
        stream.write_all(&emule_info).await.unwrap();

        let mut saw_emule_info_answer = false;
        let mut saw_secure_ident_probe = false;
        let mut fwcheck = None;
        for _ in 0..3 {
            let packet = read_packet(&mut stream).await;
            match (packet[0], packet[5]) {
                (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                    saw_secure_ident_probe = true;
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                    saw_emule_info_answer = true;
                }
                (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
                    fwcheck = Some(packet);
                    break;
                }
                other => panic!("unexpected helper packet {:?}", other),
            }
        }
        assert!(saw_emule_info_answer || saw_secure_ident_probe);
        fwcheck.expect("expected OP_FWCHECKUDPREQ after hello exchange")
    });

    request_udp_firewall_check(
        None,
        test_bind_ip(),
        helper_addr,
        Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            client_id: 0x1234_5678,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        FirewallCheckUdpRequest {
            internal_udp_port: 41000,
            external_udp_port: 41000,
            sender_udp_key: 0xAABB_CCDD,
        },
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let fwcheck = server.await.unwrap();
    assert_eq!(&fwcheck[6..8], &41000u16.to_le_bytes());
    assert_eq!(&fwcheck[8..10], &41000u16.to_le_bytes());
    assert_eq!(&fwcheck[10..14], &0xAABB_CCDDu32.to_le_bytes());
}

#[tokio::test]
async fn udp_firewall_check_request_skips_silent_helper_before_request() {
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let helper_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, peer_addr) = listener.accept().await.unwrap();
        assert_eq!(peer_addr.ip(), IpAddr::V4(test_bind_ip()));

        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(header[0], OP_EDONKEYPROT);
        assert_eq!(header[5], OP_HELLO);

        let mut extra_header = [0u8; 6];
        let read_result = tokio::time::timeout(
            Duration::from_millis(500),
            stream.read_exact(&mut extra_header),
        )
        .await;
        match read_result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(_)) => {
                panic!(
                    "silent helper unexpectedly received opcode 0x{:02X}",
                    extra_header[5]
                );
            }
        }
    });

    let error = request_udp_firewall_check(
        None,
        test_bind_ip(),
        helper_addr,
        Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            client_id: 0x1234_5678,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        FirewallCheckUdpRequest {
            internal_udp_port: 41000,
            external_udp_port: 41000,
            sender_udp_key: 0xAABB_CCDD,
        },
        Duration::from_millis(300),
    )
    .await
    .expect_err("silent helper must not receive firewall request");
    assert!(
        error
            .to_string()
            .contains("did not complete HELLO before OP_FWCHECKUDPREQ"),
        "{error:#}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn firewall_udp_reply_ignores_zero_internal_port_like_stock() {
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some(test_bind_addr()),
        node_id: NodeId::from_bytes([0x44; 16]),
        udp_key: 0x1122_3344,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let udp = tokio::net::UdpSocket::bind((test_bind_ip(), 0))
        .await
        .unwrap();
    let external_udp_port = udp.local_addr().unwrap().port();

    reply_with_firewall_udp(
        &dht,
        IpAddr::V4(test_bind_ip()),
        FirewallCheckUdpRequest {
            internal_udp_port: 0,
            external_udp_port,
            sender_udp_key: 0xAABB_CCDD,
        },
    )
    .await
    .unwrap();

    let mut buf = [0u8; 64];
    let recv = tokio::time::timeout(Duration::from_millis(150), udp.recv_from(&mut buf)).await;
    assert!(
        recv.is_err(),
        "zero internal port must suppress all UDP replies"
    );
}

#[tokio::test]
async fn kad_firewall_tcp_ack_sends_hello_then_modern_ack() {
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let hello_identity = Ed2kHelloIdentity {
        user_hash: [0x77; 16],
        client_id: 0x1234_5678,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let expected_hello = encode_hello_request(hello_identity);

    let server = tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(test_bind_ip()));

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello, expected_hello);

        let ack = read_packet(&mut stream).await;
        assert_eq!(ack[0], OP_EMULEPROT);
        assert_eq!(ack[5], OP_KAD_FWTCPCHECK_ACK);
        assert_eq!(ack.len(), 6);
    });

    let mode = send_kad_firewall_tcp_ack(
        test_bind_ip(),
        peer_addr,
        hello_identity,
        [0x10; 16],
        emule_connect_options(false),
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(mode, Ed2kPeerConnectMode::Plaintext);
    server.await.unwrap();
}
