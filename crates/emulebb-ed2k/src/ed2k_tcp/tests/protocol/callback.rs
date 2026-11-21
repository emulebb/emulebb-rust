use super::*;
use crate::ed2k_tcp::{reply_with_firewall_udp, send_kad_firewall_tcp_ack};

#[tokio::test]
async fn callback_preparation_waits_for_start_skip_or_cancellation_without_early_hydration() {
    use crate::ed2k_transfer::Ed2kCallbackPreparationOutcome;
    for decision in 0..3 {
        let mut runtime = ListenerTestRuntime::new(
            "callback-core-decision",
            listener_hello_identity(),
            [0x76; 16],
            0x12345678,
        )
        .await;
        let payload = vec![0x63; 16];
        let hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let job = crate::ed2k_transfer::test_support::admit_download_job(
            &runtime.transfer_runtime,
            hash,
            "Prepared.bin".into(),
            payload.len() as u64,
        );
        let source = Ed2kSourceHint {
            ip: test_bind_ip().to_string(),
            tcp_port: 46671,
            user_hash: Some(hex::encode([0x77; 16])),
            connect_options: None,
            file_comment: String::new(),
            file_rating: 0,
        };
        let mut owner = runtime
            .transfer_runtime
            .prepare_callback_download(
                Ed2kCallbackDownload {
                    preparation_id: None,
                    job_token: job.token,
                    file_hash: hash,
                    display_name: "Prepared.bin".into(),
                    file_size: payload.len() as u64,
                    source,
                },
                Duration::from_secs(5),
            )
            .unwrap();
        let server_ip = Ipv4Addr::new(203, 0, 113, 22);
        let server = SocketAddr::from((server_ip, 4661));
        let reservation = runtime
            .transfer_runtime
            .reserve_callback_ticket(
                Ed2kCallbackTicketRequest::server(
                    server,
                    0x4321,
                    Some([0x77; 16]),
                    46671,
                    owner.download().clone(),
                    Duration::from_secs(5),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let Ed2kCallbackReservation::Dispatch(permit) = reservation else {
            panic!("missing dispatch ownership");
        };
        runtime
            .transfer_runtime
            .mark_callback_ticket_dispatched(permit)
            .await;
        let baseline = runtime
            .transfer_runtime
            .download_resource_snapshot()
            .resident_bytes;
        let listener = runtime.spawn_listener_results(1);
        let addr = runtime.peer_addr;
        let (quiet_tx, quiet_rx) = tokio::sync::oneshot::channel();
        let peer_payload = payload.clone();
        let peer = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(&encode_hello_request(Ed2kHelloIdentity {
                    user_hash: [0x77; 16],
                    client_id: 0x4321,
                    tcp_port: 46671,
                    udp_port: 46672,
                    server_ip: u32::from_le_bytes(server_ip.octets()),
                    server_port: 4661,
                    connect_options: emule_connect_options(false),
                    direct_udp_callback: false,
                }))
                .await
                .unwrap();
            let request = read_until_opcode(&mut stream, OP_EMULEPROT, OP_MULTIPACKET_EXT2).await;
            assert!(request.windows(16).any(|bytes| bytes == hash.0));
            stream
                .write_all(&encode_startup_multipacket_ext2_answer(
                    &hash,
                    16,
                    "Prepared.bin",
                    false,
                ))
                .await
                .unwrap();
            let mut before_admission = [0];
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(30),
                    stream.read(&mut before_admission)
                )
                .await
                .is_err(),
                "listener must wait for Core before queue/hashset/payload work"
            );
            quiet_tx.send(()).unwrap();
            if decision == 0 {
                let mut start = read_packet(&mut stream).await;
                if start[5] == OP_REQUESTSOURCES2 {
                    assert_eq!(start, encode_request_sources2(&hash));
                    start = read_packet(&mut stream).await;
                }
                assert_eq!(start[5], OP_STARTUPLOADREQ);
                stream.write_all(&encode_accept_upload_req()).await.unwrap();
                let request = read_packet(&mut stream).await;
                assert_eq!(request[5], OP_REQUESTPARTS);
                let (requested, ranges) =
                    decode_request_parts_payload(&request[6..], false).unwrap();
                assert_eq!(requested, hash);
                for (start, end) in ranges {
                    stream
                        .write_all(
                            &encode_sending_part(
                                &hash,
                                start,
                                end,
                                &peer_payload[start as usize..end as usize],
                                false,
                            )
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                }
                let mut bytes = [0; 256];
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !matches!(stream.read(&mut bytes).await, Ok(0) | Err(_)) {}
                })
                .await
                .unwrap();
            } else {
                let mut byte = [0];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            }
        });
        let Ed2kCallbackPreparationOutcome::Available(availability) =
            owner.availability().await.unwrap()
        else {
            panic!("expected accepted peer availability");
        };
        let user_hash = availability.user_hash;
        let availability = std::sync::Arc::new(availability.available_parts.clone());
        assert!(
            runtime
                .transfer_runtime
                .download_live_source_has_rare_part(
                    job.token,
                    16,
                    user_hash,
                    std::sync::Arc::clone(&availability),
                    std::time::Instant::now()
                )
                .await
                .unwrap()
        );
        assert!(
            !runtime
                .transfer_runtime
                .download_live_source_has_rare_part(
                    job.token,
                    16,
                    user_hash,
                    std::sync::Arc::clone(&availability),
                    std::time::Instant::now() - Duration::from_secs(31)
                )
                .await
                .unwrap()
        );
        assert!(
            runtime
                .transfer_runtime
                .download_source_endpoints_after(job.token, 0, 256)
                .await
                .unwrap()
                .is_empty(),
            "accepted callback proof must not turn its socket or LowID into a direct source"
        );
        quiet_rx.await.unwrap();
        assert_eq!(
            runtime
                .transfer_runtime
                .download_resource_snapshot()
                .resident_bytes,
            baseline
        );
        let record = runtime
            .transfer_runtime
            .download_job(job.token.job_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            record
                .storage
                .as_ref()
                .is_none_or(|storage| !storage.path.exists())
        );
        drop(record);
        if decision == 0 {
            let selected = runtime
                .transfer_runtime
                .begin_download_job_execution(job.token, None)
                .await
                .unwrap();
            let token = selected.as_ref().unwrap().token;
            drop(selected);
            let execution =
                crate::ed2k_transfer::new_transfer_job(token, hash, "Prepared.bin".into(), 16);
            drop(
                runtime
                    .transfer_runtime
                    .ensure_job(&execution)
                    .await
                    .unwrap(),
            );
            owner.start(token).unwrap();
            assert_eq!(
                owner.completed().await.unwrap(),
                Ed2kPeerDownloadOutcome::Completed
            );
            assert_eq!(
                runtime
                    .transfer_runtime
                    .manifest(token)
                    .await
                    .unwrap()
                    .pieces[0]
                    .bytes_written,
                16
            );
        } else if decision == 1 {
            owner.skip().unwrap();
            assert_eq!(
                owner.completed().await.unwrap(),
                Ed2kPeerDownloadOutcome::NoNeededParts
            );
        } else {
            owner.cancel();
            assert!(owner.completed().await.is_err());
        }
        peer.await.unwrap();
        let results = listener.await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].is_ok(), decision != 2);
    }
}

fn callback_request(
    peer_addr: SocketAddr,
    expected_user_hash: Option<[u8; 16]>,
    peer_connect_options: Option<u8>,
) -> Ed2kCallbackSessionRequest {
    Ed2kCallbackSessionRequest {
        peer_addr,
        expected_user_hash,
        peer_connect_options,
        timeout: Duration::from_secs(3),
        origin: Ed2kCallbackSessionOrigin::Server,
    }
}

async fn stop_callback_supervisor(
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    supervisor: tokio::task::JoinHandle<()>,
) {
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::time::timeout(Duration::from_secs(2), supervisor)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn adopted_callback_session_serves_after_hello_answer() {
    let runtime = ListenerTestRuntime::new(
        "ed2k-callback-adopted-session",
        listener_hello_identity(),
        [0x9A; 16],
        0x1234_5678,
    )
    .await;
    let file = runtime
        .seed_verified_upload_file("callback.txt", b"callback payload".to_vec())
        .await;
    let requester = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let requester_addr = requester.local_addr().unwrap();
    let (callback_sessions, shutdown, supervisor) = runtime.spawn_callback_session_supervisor();
    callback_sessions
        .try_start(callback_request(requester_addr, None, None))
        .unwrap();
    let (mut stream, _) = requester.accept().await.unwrap();

    let hello = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLO).await;
    assert_eq!(hello[0], OP_EDONKEYPROT);
    assert_eq!(hello[5], OP_HELLO);

    stream
        .write_all(&encode_hello_answer(peer_hello_identity()))
        .await
        .unwrap();
    stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            OP_REQUESTFILENAME,
            &file.file_hash.0,
        ))
        .await
        .unwrap();
    let filename_answer =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
    assert_eq!(&filename_answer[6..22], &file.file_hash.0);

    drop(stream);
    stop_callback_supervisor(shutdown, supervisor).await;
}

#[tokio::test]
async fn adopted_callback_session_rejects_mismatched_expected_identity() {
    let runtime = ListenerTestRuntime::new(
        "ed2k-callback-expected-identity-mismatch",
        listener_hello_identity(),
        [0x9B; 16],
        0x2345_6789,
    )
    .await;
    let requester = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let requester_addr = requester.local_addr().unwrap();
    let (callback_sessions, shutdown, supervisor) = runtime.spawn_callback_session_supervisor();
    callback_sessions
        .try_start(callback_request(requester_addr, Some([0x99; 16]), None))
        .unwrap();
    let (mut stream, _) = requester.accept().await.unwrap();

    let _hello = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLO).await;
    let observed_identity = peer_hello_identity();
    stream
        .write_all(&encode_hello_answer(observed_identity))
        .await
        .unwrap();

    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
        .await
        .expect("mismatched callback identity did not close")
        .unwrap();
    assert_eq!(read, 0);
    assert!(
        !runtime
            .transfer_runtime
            .is_client_banned(Some(test_bind_ip()), Some(&observed_identity.user_hash),)
    );

    stop_callback_supervisor(shutdown, supervisor).await;
}

#[tokio::test]
async fn adopted_callback_session_accepts_simultaneous_hello() {
    let runtime = ListenerTestRuntime::new(
        "ed2k-callback-simultaneous-hello",
        listener_hello_identity(),
        [0x9C; 16],
        0x3456_789A,
    )
    .await;
    let file = runtime
        .seed_verified_upload_file("simultaneous-hello.txt", b"callback payload".to_vec())
        .await;
    let requester = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let requester_addr = requester.local_addr().unwrap();
    let (callback_sessions, shutdown, supervisor) = runtime.spawn_callback_session_supervisor();
    let peer_identity = peer_hello_identity();
    callback_sessions
        .try_start(callback_request(
            requester_addr,
            Some(peer_identity.user_hash),
            None,
        ))
        .unwrap();
    let (mut stream, _) = requester.accept().await.unwrap();

    let _hello = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLO).await;
    stream
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _hello_answer = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

    stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            OP_REQUESTFILENAME,
            &file.file_hash.0,
        ))
        .await
        .unwrap();
    let filename_answer =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
    assert_eq!(&filename_answer[6..22], &file.file_hash.0);

    drop(stream);
    stop_callback_supervisor(shutdown, supervisor).await;
}

#[tokio::test]
async fn inbound_callback_claim_is_scoped_to_the_server_route() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-inbound-ticketed-callback",
        listener_hello_identity(),
        [0x9B; 16],
        0x2345_6789,
    )
    .await;
    let peer_user_hash = [0x73; 16];
    let peer_client_id = 0x0000_4321;
    let peer_tcp_port = 46671;
    let server_ip = Ipv4Addr::new(203, 0, 113, 17);
    let server_endpoint = SocketAddr::from((server_ip, 4661));
    let other_server_ip = Ipv4Addr::new(203, 0, 113, 18);
    let other_server_endpoint = SocketAddr::from((other_server_ip, 4661));
    let ticket_hash = Ed2kHash::from_bytes([0x31; 16]);
    let other_server_hash = Ed2kHash::from_bytes([0x32; 16]);
    let ticket_hash_job = crate::ed2k_transfer::test_support::admit_download_job(
        &runtime.transfer_runtime,
        ticket_hash,
        "ticketed.bin".to_string(),
        1,
    );
    runtime
        .transfer_runtime
        .ensure_job(&ticket_hash_job)
        .await
        .unwrap();
    let other_server_hash_job = crate::ed2k_transfer::test_support::admit_download_job(
        &runtime.transfer_runtime,
        other_server_hash,
        "other-server.bin".to_string(),
        1,
    );
    runtime
        .transfer_runtime
        .ensure_job(&other_server_hash_job)
        .await
        .unwrap();

    let source = Ed2kSourceHint {
        ip: test_bind_ip().to_string(),
        tcp_port: peer_tcp_port,
        user_hash: Some(hex::encode(peer_user_hash)),
        connect_options: Some(emule_connect_options(false)),
        file_comment: String::new(),
        file_rating: 0,
    };
    let reservation = runtime
        .transfer_runtime
        .reserve_callback_ticket(
            Ed2kCallbackTicketRequest::server(
                server_endpoint,
                peer_client_id,
                None,
                peer_tcp_port,
                Ed2kCallbackDownload {
                    preparation_id: None,
                    job_token: ticket_hash_job.token,
                    file_hash: ticket_hash,
                    display_name: "ticketed.bin".to_string(),
                    file_size: 1,
                    source: source.clone(),
                },
                Duration::from_secs(30),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let Ed2kCallbackReservation::Dispatch(permit) = reservation else {
        panic!("first callback ticket must own dispatch")
    };
    assert_eq!(
        runtime
            .transfer_runtime
            .mark_callback_ticket_dispatched(permit)
            .await,
        Ed2kCallbackDispatchOutcome::Armed
    );
    let other_server_reservation = runtime
        .transfer_runtime
        .reserve_callback_ticket(
            Ed2kCallbackTicketRequest::server(
                other_server_endpoint,
                peer_client_id,
                None,
                peer_tcp_port,
                Ed2kCallbackDownload {
                    preparation_id: None,
                    job_token: other_server_hash_job.token,
                    file_hash: other_server_hash,
                    display_name: "other-server.bin".to_string(),
                    file_size: 1,
                    source,
                },
                Duration::from_secs(30),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let Ed2kCallbackReservation::Dispatch(other_server_permit) = other_server_reservation else {
        panic!("other server callback ticket must own its own dispatch")
    };
    assert_eq!(
        runtime
            .transfer_runtime
            .mark_callback_ticket_dispatched(other_server_permit)
            .await,
        Ed2kCallbackDispatchOutcome::Armed
    );
    let listener_task = runtime.spawn_listener_connections(1);
    let mut stream = TcpStream::connect(runtime.peer_addr).await.unwrap();
    stream
        .write_all(&encode_hello_request(Ed2kHelloIdentity {
            user_hash: peer_user_hash,
            client_id: peer_client_id,
            tcp_port: peer_tcp_port,
            udp_port: 46672,
            server_ip: u32::from_le_bytes(server_ip.octets()),
            server_port: server_endpoint.port(),
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }))
        .await
        .unwrap();

    let request = loop {
        let packet = read_packet(&mut stream).await;
        if matches!(
            packet[5],
            OP_REQUESTFILENAME | OP_MULTIPACKET | OP_MULTIPACKET_EXT | OP_MULTIPACKET_EXT2
        ) {
            break packet;
        }
    };
    assert!(
        request
            .windows(ticket_hash.0.len())
            .any(|window| window == ticket_hash.0),
        "listener must claim the ticket for the peer's server route"
    );
    assert!(
        !request
            .windows(other_server_hash.0.len())
            .any(|window| window == other_server_hash.0),
        "listener must not claim a same-client-id ticket from another server route"
    );
    stream
        .write_all(&encode_file_req_ans_nofil(&ticket_hash))
        .await
        .unwrap();
    listener_task.await.unwrap();

    let other_server_session = runtime
        .transfer_runtime
        .claim_callback_session(Ed2kCallbackHelloIdentity {
            user_hash: peer_user_hash,
            client_id: peer_client_id,
            server_endpoint: Some(other_server_endpoint),
            peer_ip: Some(test_bind_ip()),
            tcp_port: peer_tcp_port,
        })
        .unwrap()
        .expect("other server's same-client-id ticket must remain pending");
    assert_eq!(
        other_server_session.current().unwrap().unwrap().file_hash,
        other_server_hash
    );
    other_server_session.finish().unwrap();
}

#[tokio::test]
async fn inbound_ticketed_callback_switches_a4af_after_file_not_found() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-inbound-ticketed-callback-a4af",
        listener_hello_identity(),
        [0x9C; 16],
        0x3456_789A,
    )
    .await;
    let peer_user_hash = [0x74; 16];
    let peer_client_id = 0x0000_4322;
    let peer_tcp_port = 46673;
    let server_ip = Ipv4Addr::new(203, 0, 113, 19);
    let server_endpoint = SocketAddr::from((server_ip, 4661));
    let first_hash = Ed2kHash::from_bytes([0x51; 16]);
    let second_hash = Ed2kHash::from_bytes([0x52; 16]);
    let source = Ed2kSourceHint {
        ip: test_bind_ip().to_string(),
        tcp_port: peer_tcp_port,
        user_hash: Some(hex::encode(peer_user_hash)),
        connect_options: Some(emule_connect_options(false)),
        file_comment: String::new(),
        file_rating: 0,
    };
    let [first_hash_job, second_hash_job] =
        [(first_hash, "first.bin"), (second_hash, "second.bin")].map(|(hash, name)| {
            crate::ed2k_transfer::test_support::admit_download_job(
                &runtime.transfer_runtime,
                hash,
                name.to_string(),
                1,
            )
        });
    for job in [&first_hash_job, &second_hash_job] {
        runtime.transfer_runtime.ensure_job(job).await.unwrap();
    }

    let first_reservation = runtime
        .transfer_runtime
        .reserve_callback_ticket(
            Ed2kCallbackTicketRequest::server(
                server_endpoint,
                peer_client_id,
                None,
                peer_tcp_port,
                Ed2kCallbackDownload {
                    preparation_id: None,
                    job_token: first_hash_job.token,
                    file_hash: first_hash,
                    display_name: "first.bin".to_string(),
                    file_size: 1,
                    source: source.clone(),
                },
                Duration::from_secs(30),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let Ed2kCallbackReservation::Dispatch(permit) = first_reservation else {
        panic!("first A4AF callback ticket must own dispatch")
    };
    assert_eq!(
        runtime
            .transfer_runtime
            .mark_callback_ticket_dispatched(permit)
            .await,
        Ed2kCallbackDispatchOutcome::Armed
    );
    assert!(matches!(
        runtime
            .transfer_runtime
            .reserve_callback_ticket(
                Ed2kCallbackTicketRequest::server(
                    server_endpoint,
                    peer_client_id,
                    None,
                    peer_tcp_port,
                    Ed2kCallbackDownload {
                        preparation_id: None,
                        job_token: second_hash_job.token,
                        file_hash: second_hash,
                        display_name: "second.bin".to_string(),
                        file_size: 1,
                        source,
                    },
                    Duration::from_secs(30),
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        Ed2kCallbackReservation::Joined { .. }
    ));

    let listener_task = runtime.spawn_listener_connections(1);
    let mut stream = TcpStream::connect(runtime.peer_addr).await.unwrap();
    stream
        .write_all(&encode_hello_request(Ed2kHelloIdentity {
            user_hash: peer_user_hash,
            client_id: peer_client_id,
            tcp_port: peer_tcp_port,
            udp_port: 46674,
            server_ip: u32::from_le_bytes(server_ip.octets()),
            server_port: server_endpoint.port(),
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }))
        .await
        .unwrap();

    for expected_hash in [first_hash, second_hash] {
        let request = loop {
            let packet = read_packet(&mut stream).await;
            if matches!(
                packet[5],
                OP_REQUESTFILENAME | OP_MULTIPACKET | OP_MULTIPACKET_EXT | OP_MULTIPACKET_EXT2
            ) {
                break packet;
            }
        };
        assert!(
            request
                .windows(expected_hash.0.len())
                .any(|window| window == expected_hash.0),
            "callback A4AF must advance in reservation order"
        );
        stream
            .write_all(&encode_file_req_ans_nofil(&expected_hash))
            .await
            .unwrap();
    }
    listener_task.await.unwrap();
}

#[tokio::test]
async fn inbound_ticketed_callback_peer_close_consumes_current_and_retains_a4af_tail() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-inbound-ticketed-callback-close",
        listener_hello_identity(),
        [0x9D; 16],
        0x4567_89AB,
    )
    .await;
    let peer_user_hash = [0x75; 16];
    let peer_client_id = 0x0000_4323;
    let peer_tcp_port = 46675;
    let server_ip = Ipv4Addr::new(203, 0, 113, 20);
    let server_endpoint = SocketAddr::from((server_ip, 4661));
    let first_hash = Ed2kHash::from_bytes([0x61; 16]);
    let second_hash = Ed2kHash::from_bytes([0x62; 16]);
    let retry_hash = Ed2kHash::from_bytes([0x63; 16]);
    let source = Ed2kSourceHint {
        ip: test_bind_ip().to_string(),
        tcp_port: peer_tcp_port,
        user_hash: Some(hex::encode(peer_user_hash)),
        connect_options: Some(emule_connect_options(false)),
        file_comment: String::new(),
        file_rating: 0,
    };
    let [first_hash_job, second_hash_job, retry_hash_job] = [
        (first_hash, "first.bin"),
        (second_hash, "second.bin"),
        (retry_hash, "retry.bin"),
    ]
    .map(|(hash, name)| {
        crate::ed2k_transfer::test_support::admit_download_job(
            &runtime.transfer_runtime,
            hash,
            name.to_string(),
            1,
        )
    });
    for job in [&first_hash_job, &second_hash_job, &retry_hash_job] {
        runtime.transfer_runtime.ensure_job(job).await.unwrap();
    }

    let first_reservation = runtime
        .transfer_runtime
        .reserve_callback_ticket(
            Ed2kCallbackTicketRequest::server(
                server_endpoint,
                peer_client_id,
                None,
                peer_tcp_port,
                Ed2kCallbackDownload {
                    preparation_id: None,
                    job_token: first_hash_job.token,
                    file_hash: first_hash,
                    display_name: "first.bin".to_string(),
                    file_size: 1,
                    source: source.clone(),
                },
                Duration::from_secs(30),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let Ed2kCallbackReservation::Dispatch(permit) = first_reservation else {
        panic!("first callback file must own dispatch")
    };
    assert_eq!(
        runtime
            .transfer_runtime
            .mark_callback_ticket_dispatched(permit)
            .await,
        Ed2kCallbackDispatchOutcome::Armed
    );
    assert!(matches!(
        runtime
            .transfer_runtime
            .reserve_callback_ticket(
                Ed2kCallbackTicketRequest::server(
                    server_endpoint,
                    peer_client_id,
                    None,
                    peer_tcp_port,
                    Ed2kCallbackDownload {
                        preparation_id: None,
                        job_token: second_hash_job.token,
                        file_hash: second_hash,
                        display_name: "second.bin".to_string(),
                        file_size: 1,
                        source: source.clone(),
                    },
                    Duration::from_secs(30),
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        Ed2kCallbackReservation::Joined { .. }
    ));

    let listener_task = runtime.spawn_listener_connections(1);
    let mut stream = TcpStream::connect(runtime.peer_addr).await.unwrap();
    stream
        .write_all(&encode_hello_request(Ed2kHelloIdentity {
            user_hash: peer_user_hash,
            client_id: peer_client_id,
            tcp_port: peer_tcp_port,
            udp_port: 46676,
            server_ip: u32::from_le_bytes(server_ip.octets()),
            server_port: server_endpoint.port(),
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }))
        .await
        .unwrap();
    let request = loop {
        let packet = read_packet(&mut stream).await;
        if matches!(
            packet[5],
            OP_REQUESTFILENAME | OP_MULTIPACKET | OP_MULTIPACKET_EXT | OP_MULTIPACKET_EXT2
        ) {
            break packet;
        }
    };
    assert!(
        request
            .windows(first_hash.0.len())
            .any(|window| window == first_hash.0)
    );
    drop(stream);
    listener_task.await.unwrap();

    let retry_reservation = runtime
        .transfer_runtime
        .reserve_callback_ticket(
            Ed2kCallbackTicketRequest::server(
                server_endpoint,
                peer_client_id,
                None,
                peer_tcp_port,
                Ed2kCallbackDownload {
                    preparation_id: None,
                    job_token: retry_hash_job.token,
                    file_hash: retry_hash,
                    display_name: "retry.bin".to_string(),
                    file_size: 1,
                    source,
                },
                Duration::from_secs(30),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let Ed2kCallbackReservation::Dispatch(retry_permit) = retry_reservation else {
        panic!("retained A4AF tail must require a fresh callback dispatch")
    };
    assert_eq!(
        runtime
            .transfer_runtime
            .mark_callback_ticket_dispatched(retry_permit)
            .await,
        Ed2kCallbackDispatchOutcome::Armed
    );
    let mut retry_session = runtime
        .transfer_runtime
        .claim_callback_session(Ed2kCallbackHelloIdentity {
            user_hash: peer_user_hash,
            client_id: peer_client_id,
            server_endpoint: Some(server_endpoint),
            peer_ip: Some(test_bind_ip()),
            tcp_port: peer_tcp_port,
        })
        .unwrap()
        .expect("fresh dispatch must admit the retained callback tail");
    let captured = retry_session.current().unwrap().unwrap();
    assert_eq!(
        captured.file_hash, second_hash,
        "the closed session's current file was acknowledged, but its A4AF tail must survive"
    );
    retry_session.acknowledge_download(&captured).unwrap();
    let captured = retry_session.current().unwrap().unwrap();
    assert_eq!(
        captured.file_hash, retry_hash,
        "new retry work must follow the retained tail"
    );
    retry_session.acknowledge_download(&captured).unwrap();
    retry_session.finish().unwrap();
}

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

    let runtime = ListenerTestRuntime::new(
        "ed2k-callback-plaintext-session",
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
        [0x55; 16],
        0x1020_3040,
    )
    .await;
    let (callback_sessions, shutdown, supervisor) = runtime.spawn_callback_session_supervisor();
    callback_sessions
        .try_start(callback_request(peer_addr, None, None))
        .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLO);
    stop_callback_supervisor(shutdown, supervisor).await;
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

    let runtime = ListenerTestRuntime::new(
        "ed2k-callback-obfuscated-session",
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
        [0x66; 16],
        0x5060_7080,
    )
    .await;
    let (callback_sessions, shutdown, supervisor) = runtime.spawn_callback_session_supervisor();
    callback_sessions
        .try_start(callback_request(
            peer_addr,
            Some(peer_user_hash),
            Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
        ))
        .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLO);
    assert_eq!(&packet[7..23], &[0x77; 16]);
    stop_callback_supervisor(shutdown, supervisor).await;
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

    let runtime = ListenerTestRuntime::new(
        "ed2k-callback-local-plaintext-session",
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
        [0x88; 16],
        0x90A0_B0C0,
    )
    .await;
    let (callback_sessions, shutdown, supervisor) = runtime.spawn_callback_session_supervisor();
    callback_sessions
        .try_start(callback_request(
            peer_addr,
            Some([0x99; 16]),
            Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
        ))
        .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLO);
    assert_eq!(&packet[7..23], &[0x88; 16]);
    stop_callback_supervisor(shutdown, supervisor).await;
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
        crate::networking::EgressBinding::new(
            test_bind_ip(),
            crate::networking::EgressRoute::StrictInterface,
        ),
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
        crate::networking::EgressBinding::new(
            test_bind_ip(),
            crate::networking::EgressRoute::StrictInterface,
        ),
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
        crate::networking::EgressBinding::new(
            test_bind_ip(),
            crate::networking::EgressRoute::StrictInterface,
        ),
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
