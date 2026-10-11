use super::*;

fn with_obfuscation(mut identity: Ed2kHelloIdentity) -> Ed2kHelloIdentity {
    identity.connect_options = emule_connect_options(true);
    identity
}

#[tokio::test]
async fn listener_upload_queue_promotes_waiter_after_disconnect() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-disconnect",
        listener_test_identity(0x22, 0x1234_5678, 41001, 41000),
        [0x3D; 16],
        0x1122_3344,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x51; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x31, 0x0102_0304, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x32, 0x0506_0708, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_promotes_waiter_after_cancel_transfer() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-cancel",
        listener_test_identity(0x23, 0x2233_4455, 41002, 41003),
        [0x3E; 16],
        0x5566_7788,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x61; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x41, 0x1111_1111, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x42, 0x2222_2222, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_obfuscated_waiter_promotes_after_cancel_transfer() {
    let listener_identity =
        with_obfuscation(listener_test_identity(0x2A, 0x3141_2718, 41002, 41003));
    let listener_user_hash = listener_identity.user_hash;
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-obfuscated-cancel",
        listener_identity,
        [0x4A; 16],
        0x1234_8765,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued-obfuscated.txt", vec![0x62; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let mut first_transport = connect_obfuscated_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_user_hash,
        with_obfuscation(listener_test_identity(0x43, 0x1111_3333, 4661, 4665)),
        &file.file_hash,
    )
    .await;
    let mut second_transport = connect_obfuscated_peer_until_queue_rank(
        runtime.peer_addr,
        listener_user_hash,
        with_obfuscation(listener_test_identity(0x44, 0x2222_4444, 4662, 4666)),
        &file.file_hash,
        1,
    )
    .await;

    send_transport_cancel_transfer(&mut first_transport).await;

    wait_for_transport_upload_accept_timeout(&mut second_transport).await;
    drop(second_transport);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_sends_rank_only_on_reask() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-rank-on-reask",
        listener_test_identity(0x51, 0x3141_5926, 41002, 41003),
        [0x4E; 16],
        0x2233_4455,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x71; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x61, 0x1111_2222, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x62, 0x2222_3333, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;
    let mut third_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x63, 0x3333_4444, 4663, 4667),
        &file.file_hash,
        2,
    )
    .await;

    // No timer push while waiting (the initial rank above was the solicited
    // OP_STARTUPLOADREQ reply).
    assert_queue_rank_silence(&mut second_stream, Duration::from_millis(1200)).await;

    // The slot frees and the second peer is promoted; the third peer's rank
    // just improved to 1, but the oracle never pushes the new rank unsolicited.
    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);
    wait_for_upload_accept_timeout(&mut second_stream).await;
    assert_queue_rank_silence(&mut third_stream, Duration::from_millis(1200)).await;

    // Only a re-ask earns the fresh rank.
    request_upload_file(&mut third_stream, &file.file_hash).await;
    wait_for_queue_rank_timeout(&mut third_stream, 1).await;

    drop(second_stream);
    drop(third_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_queue_keeps_waiter_queued_after_parts_request() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-parts-request",
        listener_test_identity(0x52, 0x4252_5252, 41002, 41003),
        [0x4F; 16],
        0x3344_5566,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued-parts.txt", vec![0x72; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x63, 0x1111_3333, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut queued_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x64, 0x2222_4444, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    request_upload_parts(&mut queued_stream, &file.file_hash, &[(0, 1024)]).await;
    wait_for_queue_rank_timeout(&mut queued_stream, 1).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut queued_stream).await;
    drop(queued_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_queue_dials_disconnected_waiter_for_slot_grant() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-promote-dial",
        listener_test_identity(0x73, 0x4444_5555, 41002, 41003),
        [0x7E; 16],
        0x8899_AABB,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("promoted.txt", vec![0x5D; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    // The waiter's own "client" listener: the promote driver must dial this
    // advertised endpoint to deliver the slot grant.
    let waiter_listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let waiter_port = waiter_listener.local_addr().unwrap().port();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x81, 0x0102_0304, 4661, 4665),
        &file.file_hash,
    )
    .await;
    // HighID waiter advertising the listening port in its hello.
    let waiter_identity = listener_test_identity(0x92, 0x0A0B_0C0D, waiter_port, 4666);
    let queued_stream =
        connect_peer_until_queue_rank(runtime.peer_addr, waiter_identity, &file.file_hash, 1).await;
    // The waiter disconnects: its queue entry survives detached (master keeps
    // US_ONUPLOADQUEUE clients across disconnects, BaseClient.cpp:1229).
    drop(queued_stream);
    let detach_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = runtime.transfer_runtime.upload_queue_snapshot().await;
        if snapshot
            .iter()
            .any(|entry| entry.user_hash == Some([0x92; 16]) && !entry.connected)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < detach_deadline,
            "the waiter detach was never observed: {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Free the slot: the disconnected waiter is promoted and queued for the
    // outbound promote-connect (master AddUpNextClient, UploadQueue.cpp:327-361).
    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    // Drive the promote driver until it dials the waiter's endpoint.
    let driver = runtime.upload_promote_driver();
    let mut waiter_side = None;
    for _ in 0..50 {
        driver.promote_pending_once().await;
        match tokio::time::timeout(Duration::from_millis(200), waiter_listener.accept()).await {
            Ok(accepted) => {
                waiter_side = Some(accepted.unwrap().0);
                break;
            }
            Err(_) => continue,
        }
    }
    let mut waiter_side = waiter_side.expect("the promote driver never dialed the waiter");

    // The dialed connection announces us and delivers the grant: OP_HELLO
    // first, then OP_ACCEPTUPLOADREQ (oracle ConnectionEstablished,
    // BaseClient.cpp:1634-1641).
    let hello = read_until_opcode(&mut waiter_side, OP_EDONKEYPROT, OP_HELLO).await;
    assert!(!hello.is_empty());
    let accept = read_until_opcode(&mut waiter_side, OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ).await;
    assert_eq!(accept.len(), 6, "OP_ACCEPTUPLOADREQ carries no payload");
    let snapshot = runtime.transfer_runtime.upload_queue_snapshot().await;
    assert!(
        snapshot.iter().any(|entry| {
            entry.user_hash == Some([0x92; 16])
                && entry.phase == crate::ed2k_transfer::Ed2kUploadSessionPhaseSnapshot::Granted
        }),
        "the dialed waiter must hold the granted slot: {snapshot:?}"
    );

    drop(waiter_side);
    server.abort();
}

#[tokio::test]
async fn listener_claims_low_id_callback_at_hello_without_a_second_upload_request() {
    use crate::ed2k_transfer::{
        Ed2kUploadCallbackRoute, Ed2kUploadPeerIdentity, Ed2kUploadPendingPromotion,
        Ed2kUploadSessionPhaseSnapshot,
    };

    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-lowid-callback-hello",
        listener_test_identity(0x74, 0x4455_6677, 41002, 41003),
        [0x83; 16],
        0x99AA_BBCC,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("callback-promoted.txt", vec![0x6D; 4096])
        .await;

    let active_peer = Ed2kUploadPeerIdentity {
        ip: IpAddr::V4(test_bind_ip()),
        tcp_port: 4661,
        udp_port: Some(4665),
        udp_version: 4,
        should_crypt: false,
        user_hash: Some([0x84; 16]),
        client_id: Some(0x0A00_0084),
        server_endpoint: None,
        friend_slot: false,
        ident_verified: false,
        ident_bad_guy: false,
        gpl_evildoer: false,
        banned: false,
        emule_version: 0x99,
        is_emule_client: true,
        kad_port: 0,
        supports_direct_udp_callback: false,
        firewall_context: Default::default(),
        client_software: None,
    };
    let callback_hello = Ed2kHelloIdentity {
        direct_udp_callback: true,
        ..listener_test_identity(0x85, 0x0000_0085, 4662, 4666)
    };
    let callback_peer = Ed2kUploadPeerIdentity {
        ip: IpAddr::V4(test_bind_ip()),
        tcp_port: callback_hello.tcp_port,
        udp_port: Some(callback_hello.udp_port),
        udp_version: 4,
        should_crypt: false,
        user_hash: Some(callback_hello.user_hash),
        client_id: Some(callback_hello.client_id),
        server_endpoint: None,
        friend_slot: false,
        ident_verified: false,
        ident_bad_guy: false,
        gpl_evildoer: false,
        banned: false,
        emule_version: 0x99,
        is_emule_client: true,
        kad_port: 0,
        supports_direct_udp_callback: true,
        firewall_context: Default::default(),
        client_software: None,
    };

    let (active, active_status) = runtime
        .transfer_runtime
        .begin_upload_session(active_peer, &file.file_hash)
        .await;
    assert_eq!(
        active_status,
        crate::ed2k_transfer::Ed2kUploadSessionStatus::Granted
    );
    let (waiting, waiting_status) = runtime
        .transfer_runtime
        .begin_upload_session(callback_peer.clone(), &file.file_hash)
        .await;
    assert_eq!(
        waiting_status,
        crate::ed2k_transfer::Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    runtime
        .transfer_runtime
        .release_upload_session(&waiting)
        .await;
    runtime
        .transfer_runtime
        .release_upload_session(&active)
        .await;
    let promotions = runtime
        .transfer_runtime
        .take_pending_upload_promotions()
        .await;
    let [Ed2kUploadPendingPromotion::Callback(permit)] = promotions.as_slice() else {
        panic!("detached LowID waiter must produce one callback permit");
    };
    assert!(
        runtime
            .transfer_runtime
            .begin_upload_callback_dispatch(
                permit,
                Ed2kUploadCallbackRoute::DirectUdp {
                    endpoint: SocketAddr::new(callback_peer.ip, callback_hello.udp_port),
                },
            )
            .await
    );
    let producer_cancel = permit.cancellation_token();

    let server = runtime.spawn_listener_loop();
    let mut callback_stream = TcpStream::connect(runtime.peer_addr).await.unwrap();
    callback_stream
        .write_all(&encode_hello_request(callback_hello))
        .await
        .unwrap();
    let hello_answer =
        read_until_opcode(&mut callback_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    assert!(!hello_answer.is_empty());
    let accept = read_until_opcode(&mut callback_stream, OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ).await;
    assert_eq!(
        accept.len(),
        6,
        "callback HELLO must receive OP_ACCEPTUPLOADREQ without OP_STARTUPLOADREQ"
    );
    assert!(producer_cancel.is_cancelled());
    let snapshot = runtime.transfer_runtime.upload_queue_snapshot().await;
    assert!(snapshot.iter().any(|entry| {
        entry.user_hash == Some(callback_hello.user_hash)
            && entry.file_hash == file.file_hash.to_string()
            && entry.phase == Ed2kUploadSessionPhaseSnapshot::Granted
            && entry.connected
    }));

    drop(callback_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_queue_rejects_unverified_reconnect_claim() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-reconnect-hello",
        listener_test_identity(0x71, 0x4242_2424, 41002, 41003),
        [0x5E; 16],
        0x6677_8899,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x7B; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x81, 0x1111_1111, 4661, 4665),
        &file.file_hash,
    )
    .await;

    let queued_identity = listener_test_identity(0x91, 0x3333_3333, 4662, 4666);
    let queued_stream =
        connect_peer_until_queue_rank(runtime.peer_addr, queued_identity, &file.file_hash, 1).await;
    drop(queued_stream);
    let detach_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = runtime.transfer_runtime.upload_queue_snapshot().await;
        if snapshot
            .iter()
            .any(|entry| entry.user_hash == Some([0x91; 16]) && !entry.connected)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < detach_deadline,
            "the waiter detach was never observed: {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut claimant_stream =
        connect_peer_and_request_upload(runtime.peer_addr, queued_identity, &file.file_hash).await;
    assert_start_upload_silence(&mut claimant_stream, Duration::from_millis(250)).await;
    let snapshot = runtime.transfer_runtime.upload_queue_snapshot().await;
    assert!(
        snapshot
            .iter()
            .all(|entry| entry.user_hash != Some([0x91; 16])),
        "two unverified connections claiming one identity must invalidate the queued lease: {snapshot:?}"
    );

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);
    drop(claimant_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_queue_preserves_waiter_rank_across_file_switch() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-file-switch",
        listener_test_identity(0x71, 0x4343_2525, 41002, 41003),
        [0x6E; 16],
        0x7788_99AA,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let first_file = runtime
        .seed_verified_upload_file("queued-one.txt", vec![0x7B; 4096])
        .await;
    let second_file = runtime
        .seed_verified_upload_file("queued-two.txt", vec![0x8C; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x81, 0x1111_1111, 4661, 4665),
        &first_file.file_hash,
    )
    .await;
    let mut queued_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x91, 0x3333_3333, 4662, 4666),
        &first_file.file_hash,
        1,
    )
    .await;
    let mut trailing_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0xA1, 0x4444_4444, 4663, 4667),
        &first_file.file_hash,
        2,
    )
    .await;

    request_upload_file(&mut queued_stream, &second_file.file_hash).await;
    wait_for_queue_rank(&mut queued_stream, 1).await;
    // The trailing waiter did not re-ask, so no rank is pushed to it; its rank
    // is confirmed via a genuine re-ask below.
    assert_queue_rank_silence(&mut trailing_stream, Duration::from_millis(800)).await;
    request_upload_file(&mut trailing_stream, &first_file.file_hash).await;
    wait_for_queue_rank_timeout(&mut trailing_stream, 2).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut queued_stream).await;

    drop(queued_stream);
    drop(trailing_stream);
    server.abort();
}

#[tokio::test]
async fn listener_ignores_start_upload_for_an_unknown_file() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-unknown-file",
        listener_test_identity(0x53, 0x5556_5758, 41002, 41003),
        [0x5B; 16],
        0x99AA_BBCC,
    )
    .await;
    let file = runtime
        .seed_verified_upload_file("served.txt", vec![0x73; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut stream = connect_peer_and_exchange_hello(
        runtime.peer_addr,
        listener_test_identity(0x65, 0x4444_5555, 4661, 4665),
    )
    .await;

    // OP_STARTUPLOADREQ for a file we do not serve: NOTHING comes back — the
    // oracle only does CheckFailedFileIdReqs bookkeeping
    // (ListenSocket.cpp:706-707). OP_FILEREQANSNOFIL is reserved for the
    // file-request opcodes (OP_REQUESTFILENAME et al.).
    let unknown_hash = Ed2kHash::from_bytes([0xEE; 16]);
    request_upload_file(&mut stream, &unknown_hash).await;
    assert_start_upload_silence(&mut stream, Duration::from_millis(1200)).await;

    // The session survives the silent refusal: a follow-up request for the
    // served file is granted normally.
    request_upload_file(&mut stream, &file.file_hash).await;
    wait_for_upload_accept_timeout(&mut stream).await;

    drop(stream);
    server.abort();
}
