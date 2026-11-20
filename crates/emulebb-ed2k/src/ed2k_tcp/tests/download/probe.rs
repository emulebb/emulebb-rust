use super::*;
use crate::ed2k_tcp::{Ed2kPeerProbeOptions, Ed2kPeerProbeOutcome, probe_file_from_peer};

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

fn options<'a>(
    runtime: &'a Ed2kTransferRuntime,
    source: &'a Ed2kFoundSource,
    secure: &'a Ed2kSecureIdent,
) -> Ed2kPeerProbeOptions<'a> {
    Ed2kPeerProbeOptions {
        bind_ip: test_bind_ip(),
        egress_route: crate::networking::EgressRoute::StrictInterface,
        peer: source,
        hello_identity: peer_hello_identity(),
        secure_ident: secure,
        transfer_runtime: runtime,
        file_size: ED2K_PART_SIZE + 1,
        verified_parts: &[],
        timeout: Duration::from_secs(3),
    }
}

#[tokio::test]
async fn probe_observes_peer_status_without_job_storage_or_payload_requests() {
    let root = unique_test_dir("source-probe-status");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
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
    let Ed2kPeerProbeOutcome::Available(status) = result else {
        panic!("missing validated status")
    };
    assert_eq!(status.user_hash, [0x42; 16]);
    assert_eq!(status.available_parts, [true, false]);
    assert_eq!(status.file_name.as_deref(), Some("Sample Probe.bin"));
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
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let secure = test_peer_secure_ident();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let source = source(listener.local_addr().unwrap());
    let first = runtime.try_admit_source_probe().unwrap();
    let second = runtime.try_admit_source_probe().unwrap();
    assert_eq!(
        probe_file_from_peer(options(&runtime, &source, &secure))
            .await
            .unwrap(),
        Ed2kPeerProbeOutcome::Deferred
    );
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
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
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
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
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
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
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
