use super::*;
use crate::ed2k_tcp::{
    Ed2kPeerProbeOptions, Ed2kPeerProbeOutcome, Ed2kPreparedDownloadOptions, probe_file_from_peer,
};

fn assert_worker_owned<T: Send + 'static>(_: &T) {}

fn source(peer: SocketAddr) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash: Ed2kHash([0x51; 16]),
        ip: test_bind_ip(),
        tcp_port: peer.port(),
        client_id: u32::from_le_bytes(test_bind_ip().octets()),
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    }
}

fn options<'request>(
    runtime: &Arc<Ed2kTransferRuntime>,
    source: &'request Ed2kFoundSource,
    secure: &Arc<Ed2kSecureIdent>,
) -> Ed2kPeerProbeOptions<'request> {
    Ed2kPeerProbeOptions {
        bind_ip: test_bind_ip(),
        egress_route: crate::networking::EgressRoute::StrictInterface,
        peer: source,
        hello_identity: peer_hello_identity(),
        secure_ident: Arc::clone(secure),
        transfer_runtime: Arc::clone(runtime),
        file_size: ED2K_PART_SIZE + 1,
        verified_parts: &[],
        timeout: Duration::from_secs(3),
    }
}

#[tokio::test]
async fn probe_observes_peer_status_without_job_storage_or_payload_requests() {
    let root = unique_test_dir("source-probe-status");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let secure = test_peer_secure_ident();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let source = source(addr);
    let hash = source.file_hash;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[5], OP_HELLO);
        stream.write_all(&test_peer_hello(addr)).await.unwrap();
        assert_eq!(read_packet(&mut stream).await[5], OP_SECIDENTSTATE);
        let request = read_packet(&mut stream).await;
        assert_eq!(request[5], OP_MULTIPACKET_EXT2);
        assert_startup_multipacket_ext2_with_source_exchange(
            request[0],
            request[5],
            &request[6..],
            &hash,
            ED2K_PART_SIZE + 1,
            true,
            false,
        );
        let answer = crate::ed2k_tcp::encode_multipacket_ext2_answer(
            &Ed2kFileIdentifier {
                file_hash: hash,
                file_size: Some(ED2K_PART_SIZE + 1),
                aich_root: None,
            },
            "Sample Probe.bin",
            crate::ed2k_string::Ed2kStringEncoding::Utf8,
            true,
            Some(&[2, 0, 1]),
        )
        .unwrap();
        stream.write_all(&answer).await.unwrap();
        let mut extra = [0; 6];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut extra))
                .await
                .unwrap()
                .unwrap(),
            0,
            "probe must close without requesting hashsets or payload"
        );
    });
    let before = runtime.download_resource_snapshot().resident_bytes;
    let result = probe_file_from_peer(options(&runtime, &source, &secure))
        .await
        .unwrap();
    let Ed2kPeerProbeOutcome::Available(prepared) = result else {
        panic!("missing validated status")
    };
    let status = prepared.availability();
    assert_eq!(status.user_hash, [0x42; 16]);
    assert_eq!(status.available_parts, [true, false]);
    assert_eq!(status.file_name.as_deref(), Some("Sample Probe.bin"));
    assert_eq!(runtime.download_resource_snapshot().connections, 1);
    drop(prepared);
    server.await.unwrap();
    assert_eq!(runtime.download_resource_snapshot().resident_bytes, before);
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
    assert!(
        runtime
            .download_jobs_after(None, 1, false)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn probe_refuses_excess_preparation_before_opening_socket() {
    let root = unique_test_dir("source-probe-admission");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let secure = test_peer_secure_ident();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let source = source(listener.local_addr().unwrap());
    let first = runtime.try_admit_source_probe().unwrap();
    let second = runtime.try_admit_source_probe().unwrap();
    assert!(matches!(
        probe_file_from_peer(options(&runtime, &source, &secure))
            .await
            .unwrap(),
        Ed2kPeerProbeOutcome::Deferred
    ));
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    drop((first, second));
    assert!(runtime.try_admit_source_probe().is_some());
}

#[tokio::test]
async fn dropped_probe_releases_connection_and_preparation_ownership() {
    let root = unique_test_dir("source-probe-cancel");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let secure = test_peer_secure_ident();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let source = source(listener.local_addr().unwrap());
    let mut probe = Box::pin(probe_file_from_peer(options(&runtime, &source, &secure)));
    let (mut stream, _) = tokio::select! {
        accepted = listener.accept() => accepted.unwrap(),
        result = &mut probe => panic!("probe ended before connection: {result:?}"),
    };
    assert_eq!(runtime.download_resource_snapshot().connections, 1);
    drop(probe);
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
    let first = runtime.try_admit_source_probe().unwrap();
    let second = runtime.try_admit_source_probe().unwrap();
    let mut bytes = [0; 256];
    tokio::time::timeout(Duration::from_secs(3), async {
        while stream.read(&mut bytes).await.unwrap() != 0 {}
    })
    .await
    .unwrap();
    drop((first, second));
}

#[tokio::test]
async fn probe_deadline_releases_resources_when_peer_never_answers() {
    let root = unique_test_dir("source-probe-deadline");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let secure = test_peer_secure_ident();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let source = source(listener.local_addr().unwrap());
    let mut input = options(&runtime, &source, &secure);
    input.timeout = Duration::from_millis(100);
    let error = probe_file_from_peer(input)
        .await
        .expect_err("silent peer must exhaust the total deadline");
    assert!(error.to_string().contains("timed out"));
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
    let first = runtime.try_admit_source_probe().unwrap();
    let second = runtime.try_admit_source_probe().unwrap();
    drop((first, second));
}

#[tokio::test]
async fn probe_retires_under_unrelated_control_packet_flood() {
    let root = unique_test_dir("source-probe-flood");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let secure = test_peer_secure_ident();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let source = source(addr);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_packet(&mut stream).await[5], OP_HELLO);
        stream.write_all(&test_peer_hello(addr)).await.unwrap();
        assert_eq!(read_packet(&mut stream).await[5], OP_SECIDENTSTATE);
        assert_eq!(read_packet(&mut stream).await[5], OP_MULTIPACKET_EXT2);
        let flood = encode_packet(OP_EMULEPROT, OP_BUDDYPONG, &[]).repeat(65);
        stream.write_all(&flood).await.unwrap();
        let mut bytes = [0; 64];
        let _ = stream.read(&mut bytes).await;
    });
    let error = probe_file_from_peer(options(&runtime, &source, &secure))
        .await
        .expect_err("flood must retire the probe");
    assert!(error.to_string().contains("packet allowance"));
    server.await.unwrap();
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
}

#[tokio::test]
async fn prepared_peer_persists_status_and_downloads_on_the_original_socket() {
    let root = unique_test_dir("prepared-peer-download");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let secure = test_peer_secure_ident();
    let payload = vec![0x63; 128 * 1024];
    let hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let job = crate::ed2k_transfer::test_support::admit_download_job(
        &runtime,
        hash,
        "Sample.bin".into(),
        payload.len() as u64,
    );
    let other = crate::ed2k_transfer::test_support::admit_download_job(
        &runtime,
        Ed2kHash([0x73; 16]),
        "Other.bin".into(),
        payload.len() as u64,
    );
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut source = source(addr);
    source.file_hash = hash;
    let size = payload.len() as u64;
    let server_payload = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_packet(&mut stream).await[5], OP_HELLO);
        stream.write_all(&test_peer_hello(addr)).await.unwrap();
        assert_eq!(read_packet(&mut stream).await[5], OP_SECIDENTSTATE);
        assert_eq!(read_packet(&mut stream).await[5], OP_MULTIPACKET_EXT2);
        stream
            .write_all(&encode_startup_multipacket_ext2_answer(
                &hash,
                size,
                "Sample.bin",
                false,
            ))
            .await
            .unwrap();
        // The first frame after promotion must join the queue on this socket,
        // without another HELLO/file request. This fixture suppresses SX2 below.
        let (requested_hash, ranges) =
            accept_upload_and_read_parts_request(&mut stream, false).await;
        assert_eq!(requested_hash, hash);
        for (start, end) in ranges {
            stream
                .write_all(
                    &encode_sending_part(
                        &hash,
                        start,
                        end,
                        &server_payload[start as usize..end as usize],
                        false,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let mut bytes = [0; 256];
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            while !matches!(stream.read(&mut bytes).await, Ok(0) | Err(_)) {}
        })
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err(),
            "handoff must not redial"
        );
    });
    let before = runtime.download_resource_snapshot().resident_bytes;
    let prepared = {
        let probe_source = source.clone();
        let verified = vec![false];
        let mut input = options(&runtime, &probe_source, &secure);
        input.file_size = size;
        input.verified_parts = &verified;
        let Ed2kPeerProbeOutcome::Available(prepared) = probe_file_from_peer(input).await.unwrap()
        else {
            panic!("missing prepared peer")
        };
        prepared
    };
    assert_eq!(runtime.download_resource_snapshot().resident_bytes, before);
    assert!(prepared.remember_availability(other.token).await.is_err());
    assert_worker_owned(&prepared);
    prepared.remember_availability(job.token).await.unwrap();
    let observed = runtime
        .download_source_availability_after(job.token, 0, i64::MAX, 0, 256)
        .await
        .unwrap();
    assert_eq!(observed.len(), 1);
    assert!(observed[0].has_part(0));
    drop(observed);
    assert_eq!(runtime.download_resource_snapshot().resident_bytes, before);
    drop(runtime.ensure_job(&job).await.unwrap());
    let result = prepared
        .download(Ed2kPreparedDownloadOptions {
            job_token: job.token,
            timeout: Duration::from_secs(3),
            current_source_count: usize::MAX,
            upload_context: None,
            established_context: None,
            reask_register: None,
        })
        .await
        .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
    assert_eq!(runtime.available_sources_per_part(job.token, 1), [1]);
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
    let first = runtime.try_admit_source_probe().unwrap();
    let second = runtime.try_admit_source_probe().unwrap();
    drop((first, second));
    server.await.unwrap();
    assert_eq!(
        runtime.manifest(job.token).await.unwrap().pieces[0].bytes_written,
        size
    );
}

#[tokio::test]
async fn prepared_status_is_applied_before_cached_hashes_can_join_the_queue() {
    let root = unique_test_dir("prepared-peer-no-needed-parts");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let secure = test_peer_secure_ident();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let source = source(addr);
    let job = crate::ed2k_transfer::test_support::admit_download_job(
        &runtime,
        source.file_hash,
        "Sample.bin".into(),
        16,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    drop(
        runtime
            .store_md4_hashset(job.token, Vec::new())
            .await
            .unwrap(),
    );
    let hash = source.file_hash;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_packet(&mut stream).await[5], OP_HELLO);
        stream.write_all(&test_peer_hello(addr)).await.unwrap();
        assert_eq!(read_packet(&mut stream).await[5], OP_SECIDENTSTATE);
        assert_eq!(read_packet(&mut stream).await[5], OP_MULTIPACKET_EXT2);
        let answer = crate::ed2k_tcp::encode_multipacket_ext2_answer(
            &Ed2kFileIdentifier {
                file_hash: hash,
                file_size: Some(16),
                aich_root: None,
            },
            "Sample.bin",
            crate::ed2k_string::Ed2kStringEncoding::Utf8,
            true,
            Some(&[1, 0, 0]),
        )
        .unwrap();
        stream.write_all(&answer).await.unwrap();
        let mut bytes = [0; 6];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0,
            "no-needed-parts status must prevent an upload-queue request"
        );
    });
    let mut input = options(&runtime, &source, &secure);
    input.file_size = 16;
    let Ed2kPeerProbeOutcome::Available(prepared) = probe_file_from_peer(input).await.unwrap()
    else {
        panic!("missing prepared peer")
    };
    assert_eq!(prepared.availability().available_parts, [false]);
    let result = prepared
        .download(Ed2kPreparedDownloadOptions {
            job_token: job.token,
            timeout: Duration::from_secs(3),
            current_source_count: usize::MAX,
            upload_context: None,
            established_context: None,
            reask_register: None,
        })
        .await
        .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::NoNeededParts);
    server.await.unwrap();
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
}
