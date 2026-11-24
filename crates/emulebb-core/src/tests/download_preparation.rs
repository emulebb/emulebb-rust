use super::*;
use crate::download_preparation::DownloadPreparation;

pub(crate) fn local_preparation_core(
    root: &Path,
    user_hash: [u8; 16],
    max_concurrent: Option<u32>,
) -> (EmulebbCore, Ed2kNetworkConfig) {
    std::fs::create_dir_all(root).unwrap();
    let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut network = test_network_config_with_store(
        root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.p2p_bind_ip = Some(Ipv4Addr::LOCALHOST);
    network.kad_bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    network.listen_port = port;
    network.ed2k.listen_port = Some(port);
    network.user_hash = user_hash;
    network.nat_config.enabled = false;
    network.ed2k.server_entries.clear();
    let server_probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    network.ed2k.server_endpoints = vec![server_probe.local_addr().unwrap().to_string()];
    network.ed2k.enable_udp_reask = false;
    network.kad_publish_shared_files = false;
    network.kad_udp_firewall_check_enabled = false;
    network.kad_tcp_firewall_check_enabled = false;
    network.kad_buddy_enabled = false;
    network.kad_routing_maintenance_enabled = false;
    let core = EmulebbCore::new_with_network(
        "test",
        test_index_with_settings(
            FileIndex::in_memory().unwrap(),
            serde_json::json!({"network":{"kadEnabled":false}, "transfers":{"maxConcurrentDownloads":max_concurrent}}),
        ),
        root,
        Some(network.clone()),
    )
    .unwrap();
    (core, network)
}

#[tokio::test]
async fn native_probe_capacity_refusal_releases_only_its_exact_core_reservation() {
    use emulebb_ed2k::{
        ed2k_tcp::{Ed2kPeerProbeOptions, Ed2kPeerProbeOutcome, probe_file_from_peer},
        ed2k_transfer::Ed2kDownloadCoordinatorConfig,
    };
    let root = unique_runtime_dir("core-probe-capacity-refusal");
    let (core, network) = local_preparation_core(&root, [0x65; 16], None);
    let hash = Ed2kHash::from_bytes([0x66; 16]);
    let file = hash.to_string();
    let owner = a4af_test_owner(&core, &file);
    let source = direct_test_source(hash, Ipv4Addr::LOCALHOST, 41012);
    core.state
        .lock()
        .await
        .download_source_registry
        .add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file.clone(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    let (leased, _, _) = core
        .acquire_direct_download_source_leases(owner.token(), &file, std::slice::from_ref(&source))
        .await;
    assert_eq!(leased.len(), 1);
    let first = core
        .capture_download_probe_lease(owner.token(), &source, &file)
        .await
        .unwrap();
    core.ed2k_transfers
        .apply_download_coordinator_config(Ed2kDownloadCoordinatorConfig {
            max_connections: 1,
            max_connections_per_window: 0,
            ..Ed2kDownloadCoordinatorConfig::default()
        });
    let held = core.ed2k_transfers.try_admit_source_connection();
    assert!(held.decision().admitted);
    let result = probe_file_from_peer(Ed2kPeerProbeOptions {
        bind_ip: network.bind_ip,
        egress_route: network.egress_route,
        peer: &source,
        hello_identity: core.ed2k_hello_identity(&network),
        secure_ident: Arc::clone(&network.secure_ident),
        transfer_runtime: Arc::clone(&core.ed2k_transfers),
        file_size: 1024,
        verified_parts: &[false],
        timeout: Duration::from_secs(1),
    })
    .await
    .unwrap();
    assert!(matches!(result, Ed2kPeerProbeOutcome::Deferred));
    core.finish_download_probe_lease(owner.token(), &source, &file, first, true)
        .await;
    assert!(
        core.state
            .lock()
            .await
            .active_download_peer_endpoints
            .is_empty()
    );
    let (leased, _, retry) = core
        .acquire_direct_download_source_leases(owner.token(), &file, std::slice::from_ref(&source))
        .await;
    assert_eq!(leased.len(), 1);
    assert!(retry.is_none());
    let second = core
        .capture_download_probe_lease(owner.token(), &source, &file)
        .await
        .unwrap();
    assert_ne!(first, second);
    core.finish_download_probe_lease(owner.token(), &source, &file, first, true)
        .await;
    assert_eq!(
        core.capture_download_probe_lease(owner.token(), &source, &file)
            .await,
        Some(second)
    );
    core.finish_download_probe_lease(owner.token(), &source, &file, second, false)
        .await;
    let (leased, deferred, retry) = core
        .acquire_direct_download_source_leases(owner.token(), &file, std::slice::from_ref(&source))
        .await;
    assert!(leased.is_empty());
    assert_eq!(deferred, 1);
    assert!(retry.unwrap() > Duration::from_secs(1190));
    drop(held);
    drop(owner);
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn availability_persistence_capacity_preserves_source_without_peer_cooldown() {
    use emulebb_ed2k::ed2k_transfer::LocalMutationError;
    for (error, immediate) in [
        (anyhow::Error::new(LocalMutationError::Busy), true),
        (anyhow::Error::new(LocalMutationError::Closing), true),
        (
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into(),
            false,
        ),
        (
            std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
            false,
        ),
    ] {
        let root = unique_runtime_dir("core-probe-availability-capacity");
        let (core, _) = local_preparation_core(&root, [0x65; 16], None);
        let hash = Ed2kHash::from_bytes([0x66; 16]);
        let file = hash.to_string();
        let owner = a4af_test_owner(&core, &file);
        let source = direct_test_source(hash, Ipv4Addr::LOCALHOST, 41012);
        core.state
            .lock()
            .await
            .download_source_registry
            .add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: file.clone(),
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        let (leased, _, _) = core
            .acquire_direct_download_source_leases(
                owner.token(),
                &file,
                std::slice::from_ref(&source),
            )
            .await;
        assert_eq!(leased.len(), 1);
        let lease = core
            .capture_download_probe_lease(owner.token(), &source, &file)
            .await
            .unwrap();
        core.settle_source_reservation(
            &crate::download_preparation::PreparedSourceReservation {
                source: source.clone(),
                token: owner.token(),
                hash,
                lease,
            },
            false,
            Some(&error.context("persisting probe availability")),
        )
        .await;
        assert!(
            core.state
                .lock()
                .await
                .active_download_peer_endpoints
                .is_empty()
        );
        let (leased, _, retry) = core
            .acquire_direct_download_source_leases(
                owner.token(),
                &file,
                std::slice::from_ref(&source),
            )
            .await;
        assert_eq!(leased.len(), usize::from(immediate));
        if immediate {
            assert!(retry.is_none());
        } else {
            assert!(retry.unwrap() > Duration::from_secs(1190));
        }
        drop(owner);
        drop(core);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn prepared_execution_refusals_settle_exact_source_and_release_permits() {
    use crate::download_preparation::PreparedSourceReservation;
    use emulebb_ed2k::ed2k_transfer::LocalMutationError;
    for (error, immediate) in [
        (anyhow::Error::new(LocalMutationError::Busy), true),
        (anyhow::Error::new(LocalMutationError::Closing), true),
        (
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into(),
            false,
        ),
        (
            std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
            false,
        ),
    ] {
        let root = unique_runtime_dir("core-prepared-execution-refusal");
        let (core, _) = local_preparation_core(&root, [0x65; 16], None);
        let hash = Ed2kHash::from_bytes([0x66; 16]);
        let file = hash.to_string();
        let mut owner = a4af_test_owner(&core, &file);
        let source = direct_test_source(hash, Ipv4Addr::LOCALHOST, 41012);
        core.state
            .lock()
            .await
            .download_source_registry
            .add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: file.clone(),
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        let (leased, _, _) = core
            .acquire_direct_download_source_leases(
                owner.token(),
                &file,
                std::slice::from_ref(&source),
            )
            .await;
        assert_eq!(leased.len(), 1);
        let lease = core
            .capture_download_probe_lease(owner.token(), &source, &file)
            .await
            .unwrap();
        let mut reservation = PreparedSourceReservation {
            source: source.clone(),
            token: owner.token(),
            hash,
            lease,
        };
        let selected = emulebb_metadata::JobToken {
            generation: owner.token().generation + 1,
            ..owner.token()
        };
        assert!(owner.rebind(selected));
        assert!(
            core.rebind_prepared_source(&mut reservation, selected)
                .await
        );
        let permit = match core.ed2k_transfers.try_admit_source_connection() {
            Ed2kSourceConnectionAdmission::Admitted { permit, .. } => permit,
            _ => panic!("initial native admission refused"),
        };
        let result = core
            .run_prepared_source(&reservation, async move {
                let _permit = permit;
                tokio::task::yield_now().await;
                Err(error.context("prepared source persistence refused"))
            })
            .await;
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<LocalMutationError>()
                .is_some(),
            immediate
        );
        assert_eq!(
            core.ed2k_transfers.download_resource_snapshot().connections,
            0
        );
        assert!(
            core.state
                .lock()
                .await
                .active_download_peer_endpoints
                .is_empty()
        );
        let (leased, _, retry) = core
            .acquire_direct_download_source_leases(
                owner.token(),
                &file,
                std::slice::from_ref(&source),
            )
            .await;
        assert_eq!(leased.len(), usize::from(immediate));
        if immediate {
            assert!(retry.is_none());
            let replacement = core
                .capture_download_probe_lease(owner.token(), &source, &file)
                .await
                .unwrap();
            assert_ne!(replacement, reservation.lease);
            core.settle_source_reservation(&reservation, true, None)
                .await;
            assert!(
                !core
                    .rebind_prepared_source(&mut reservation, selected)
                    .await
            );
            assert_eq!(
                core.capture_download_probe_lease(owner.token(), &source, &file)
                    .await,
                Some(replacement)
            );
            core.finish_download_probe_lease(owner.token(), &source, &file, replacement, true)
                .await;
        } else {
            assert!(retry.unwrap() > Duration::from_secs(1190));
        }
        drop(owner);
        drop(core);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn prepared_udp_detachment_survives_completion_read_refusal() {
    use crate::download_preparation::PreparedSourceReservation;
    use emulebb_ed2k::ed2k_transfer::LocalMutationError;
    let root = unique_runtime_dir("core-prepared-detached-read-refusal");
    let (core, network) = local_preparation_core(&root, [0x65; 16], None);
    let hash = Ed2kHash::from_bytes([0x66; 16]);
    let file = hash.to_string();
    let owner = a4af_test_owner(&core, &file);
    let token = owner.token();
    let source = direct_test_source(hash, Ipv4Addr::LOCALHOST, 41012);
    core.state
        .lock()
        .await
        .download_source_registry
        .add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file.clone(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    let (leased, _, _) = core
        .acquire_direct_download_source_leases(token, &file, std::slice::from_ref(&source))
        .await;
    assert_eq!(leased.len(), 1);
    let lease = core
        .capture_download_probe_lease(token, &source, &file)
        .await
        .unwrap();
    let reservation = PreparedSourceReservation {
        source: source.clone(),
        token,
        hash,
        lease,
    };
    let permit = match core.ed2k_transfers.try_admit_source_connection() {
        Ed2kSourceConnectionAdmission::Admitted { permit, .. } => permit,
        _ => panic!("initial admission refused"),
    };
    let mut options = direct_download_options(
        token,
        Arc::clone(&core.ed2k_transfers),
        Arc::clone(&network.secure_ident),
        file.clone(),
        "Sample.bin".into(),
        1024,
        Vec::new(),
    );
    options.completion_read_busy = true;
    let producer = core.clone();
    let captured = reservation.clone();
    options.prepared = Some(crate::ed2k_direct_download_types::PreparedDirectDownload {
        source: source.clone(),
        download: Box::pin(async move {
            producer
                .run_prepared_source(&captured, async move {
                    let _permit = permit;
                    Ok(Ed2kPeerDownloadReport::single(
                        token,
                        hash,
                        Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask,
                    ))
                })
                .await
        }),
    });
    let outcome = run_ed2k_direct_downloads(options, |_, _, _, _, _, _, _, _, _| async {
        panic!("prepared source must not be redialed")
    })
    .await;
    assert!(matches!(
        outcome
            .as_ref()
            .unwrap()
            .last_error
            .as_ref()
            .unwrap()
            .downcast_ref(),
        Some(LocalMutationError::Busy)
    ));
    core.settle_prepared_round(&reservation, &outcome).await;
    assert_eq!(
        core.ed2k_transfers.download_resource_snapshot().connections,
        0
    );
    assert_eq!(
        core.capture_download_probe_lease(token, &source, &file)
            .await,
        Some(lease)
    );
    let (leased, _, _) = core
        .acquire_direct_download_source_leases(token, &file, std::slice::from_ref(&source))
        .await;
    assert!(
        leased.is_empty(),
        "UDP still owns this peer even though completion metadata was busy"
    );
    core.release_direct_download_source_leases(token, &[source_endpoint_key(&source)])
        .await;
    assert!(
        core.capture_download_probe_lease(token, &source, &file)
            .await
            .is_none()
    );
    drop(owner);
    drop(core);
    std::fs::remove_dir_all(root).unwrap();
}

async fn prepared_source_pair(
    root: &std::path::Path,
) -> (
    EmulebbCore,
    EmulebbCore,
    Ed2kNetworkConfig,
    String,
    Vec<u8>,
    emulebb_metadata::JobToken,
) {
    let library = root.join("library");
    std::fs::create_dir_all(&library).unwrap();
    let payload = vec![0x61; 2048];
    std::fs::write(library.join("Sample.bin"), &payload).unwrap();
    let (seed, network) = local_preparation_core(&root.join("seed"), [0x61; 16], None);
    seed.create_library_root(&library.to_string_lossy(), false)
        .await
        .unwrap()
        .unwrap();
    let shares = seed.reload_shared_directories().await.unwrap();
    let hash_hex = shares
        .iter()
        .find(|share| share.name == "Sample.bin")
        .unwrap()
        .hash
        .clone();
    drop(shares);
    seed.connect_ed2k().await.unwrap();
    let (download, _) = local_preparation_core(&root.join("download"), [0x62; 16], None);
    let (_, created) = download
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: hash_hex.clone(),
                name: "Sample.bin".into(),
                size_bytes: Some(payload.len() as u64),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        })
        .await
        .unwrap();
    let id = created.id;
    drop(created);
    let job = download
        .ed2k_transfers
        .download_job(id)
        .await
        .unwrap()
        .unwrap();
    let original = job.token;
    drop(job);
    download
        .ed2k_transfers
        .remember_source(
            original,
            Ed2kSourceHint {
                ip: Ipv4Addr::LOCALHOST.to_string(),
                tcp_port: network.listen_port,
                user_hash: Some(hex::encode(network.user_hash)),
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();
    (seed, download, network, hash_hex, payload, original)
}

#[tokio::test]
async fn prepared_connection_survives_local_hydration_busy_and_delivers_without_reask() {
    let root = unique_runtime_dir("core-prepared-hydration-recovery");
    let (seed, download, network, hash_hex, payload, original) = prepared_source_pair(&root).await;
    let id = original.job_id;
    let baseline = download
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    let hash = hash_hex.parse().unwrap();
    let guard = download
        .download_attempts
        .try_prepare(original, hash)
        .unwrap();
    let shutdown = CancellationToken::new();
    let DownloadPreparation::Direct(ready) = download
        .prepare_download_sources(&guard, &shutdown)
        .await
        .unwrap()
    else {
        panic!("live seed must supply a prepared connection");
    };
    // Own the retry clock so the injected refusal stays observable until the
    // fixture releases it. The seed and payload session still use a live socket.
    let (retry, clock) = tokio::sync::watch::channel(());
    download
        .download_hydration_busy
        .store(true, Ordering::Release);
    let execution = tokio::spawn({
        let download = download.clone();
        async move {
            download
                .run_selected_download(guard, DownloadPreparation::Direct(ready), clock, shutdown)
                .await;
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while download.download_hydration_busy.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let job = download
        .ed2k_transfers
        .download_job(id)
        .await
        .unwrap()
        .unwrap();
    let selected = job.token;
    assert_eq!(selected.generation, original.generation + 1);
    assert!(
        job.storage
            .as_ref()
            .is_some_and(|storage| storage.identity.is_none() && !storage.path.exists())
    );
    assert!(job.storage_failure.is_none());
    drop(job);
    assert_eq!(
        download
            .ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        baseline
    );

    assert_eq!(
        download
            .ed2k_transfers
            .download_resource_snapshot()
            .connections,
        1,
        "the prepared socket must remain owned during the local wait"
    );
    let source = direct_test_source(hash, Ipv4Addr::LOCALHOST, network.listen_port);
    let cooldown = crate::ed2k_download_retry::ED2K_DIRECT_SOURCE_RETRY_COOLDOWN;
    assert!(
        download
            .state
            .lock()
            .await
            .download_source_registry
            .endpoint_retry_delay(Instant::now(), cooldown, &source, &hash_hex,)
            .unwrap()
            > Duration::from_secs(19 * 60)
    );
    retry
        .send(())
        .expect("selected owner is waiting for local retry");
    // This checks eventual publication and checkpointing, not a delivery SLA.
    let delivered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(share) = download.share(&hash_hex).await {
                // Publication can precede the final job checkpoint. Wait for
                // both outcomes before asserting the recovery is complete.
                let job = download
                    .ed2k_transfers
                    .download_job(id)
                    .await
                    .unwrap()
                    .unwrap();
                if job.completed_at_s.is_some() {
                    break share;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let delivered = match delivered {
        Ok(share) => share,
        Err(_) => {
            let job = download.ed2k_transfers.download_job(id).await.unwrap();
            let resources = download.ed2k_transfers.download_resource_snapshot();
            panic!(
                "prepared transfer did not settle after local hydration resumed: \
                 job={:?}, connections={}, resident_bytes={}",
                job.as_ref().map(|job| (
                    job.token,
                    job.checkpointed_bytes,
                    job.storage_failure.as_ref(),
                )),
                resources.connections,
                resources.resident_bytes,
            );
        }
    };
    assert_eq!(std::fs::read(&delivered.path).unwrap(), payload);
    assert!(
        download
            .state
            .lock()
            .await
            .download_source_registry
            .endpoint_retry_delay(Instant::now(), cooldown, &source, &hash_hex,)
            .unwrap()
            > Duration::from_secs(19 * 60),
        "recovery must not erase the network cooldown"
    );
    let job = download
        .ed2k_transfers
        .download_job(id)
        .await
        .unwrap()
        .unwrap();
    assert!(job.completed_at_s.is_some());
    assert!(job.storage_failure.is_none());
    assert!(
        job.token.generation <= selected.generation + 1,
        "only final retirement may follow the single begin"
    );
    drop(job);
    tokio::time::timeout(Duration::from_secs(10), execution)
        .await
        .unwrap()
        .unwrap();
    download.disconnect_ed2k().await.unwrap();
    seed.disconnect_ed2k().await.unwrap();
}

#[tokio::test]
async fn expired_prepared_sources_settle_before_and_after_begin_handoff() {
    for stage in 0..3 {
        let root = unique_runtime_dir("core-prepared-expiry-handoff");
        let (seed, download, network, hash_hex, _, original) = prepared_source_pair(&root).await;
        let hash = hash_hex.parse().unwrap();
        let mut guard = download
            .download_attempts
            .try_prepare(original, hash)
            .unwrap();
        let DownloadPreparation::Direct(mut ready) = download
            .prepare_download_sources(&guard, &CancellationToken::new())
            .await
            .unwrap()
        else {
            panic!("live seed must supply a prepared connection");
        };
        if stage != 0 {
            assert!(guard.promote());
            assert!(
                download
                    .begin_selected_download(&mut guard)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_ne!(guard.token(), original);
            if stage == 1 {
                assert!(
                    download
                        .rebind_prepared_source(&mut ready.reservation, guard.token())
                        .await
                );
            }
        }
        // Stage 2 mirrors a Begin that advances its guard then is cancelled
        // before transferring the source. Its actual reservation still owns original.
        assert_eq!(
            ready.reservation.token,
            if stage == 1 { guard.token() } else { original }
        );
        ready.admission_deadline = tokio::time::Instant::now() - Duration::from_millis(1);
        let (_sender, clock) = tokio::sync::watch::channel(());
        download
            .run_selected_download(
                guard,
                DownloadPreparation::Direct(ready),
                clock,
                CancellationToken::new(),
            )
            .await;
        let source = direct_test_source(hash, Ipv4Addr::LOCALHOST, network.listen_port);
        let state = download.state.lock().await;
        assert!(state.active_download_peer_endpoints.is_empty());
        assert!(
            state
                .download_source_registry
                .endpoint_retry_delay(
                    Instant::now(),
                    Duration::from_secs(20 * 60),
                    &source,
                    &hash_hex,
                )
                .is_none(),
            "unused connection expiry must not penalize its peer at stage {stage}"
        );
        drop(state);
        assert_eq!(
            download
                .ed2k_transfers
                .download_resource_snapshot()
                .connections,
            0
        );
        download.disconnect_ed2k().await.unwrap();
        seed.disconnect_ed2k().await.unwrap();
    }
}

#[tokio::test]
async fn known_size_waiting_preparation_never_hydrates_without_a_useful_source() {
    let root = unique_runtime_dir("core-waiting-source-preparation");
    let mut network = test_network_config_with_store(
        &root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.p2p_bind_ip = Some(Ipv4Addr::LOCALHOST);
    network.ed2k.server_entries.clear();
    network.ed2k.server_endpoints.clear();
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &root,
        Some(network),
    )
    .unwrap();
    let (_, created) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: "94949494949494949494949494949494".into(),
                name: "Sample.bin".into(),
                size_bytes: Some(0x4000000000),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        })
        .await
        .unwrap();
    let id = created.id;
    drop(created);
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    let token = job.token;
    let guard = core
        .download_attempts
        .try_prepare(token, job.file_hash.parse().unwrap())
        .unwrap();
    drop(job);
    let baseline = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    assert!(matches!(
        core.prepare_download_sources(&guard, &CancellationToken::new())
            .await
            .unwrap(),
        DownloadPreparation::Waiting
    ));
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    assert_eq!(
        job.token, token,
        "source preparation must not begin another execution"
    );
    assert!(job.storage.is_none());
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        baseline
    );
    assert!(!core.download_attempts.owns(token));
    assert!(core.state.lock().await.transfers.is_empty());
}

#[tokio::test]
async fn ready_admission_keeps_preparation_bounded_and_selects_smaller_remaining_work() {
    assert_ready_admission_order(false).await;
}

#[tokio::test]
async fn ready_admission_prefers_unique_reporter_part_over_smaller_remaining_work() {
    assert_ready_admission_order(true).await;
}

async fn assert_ready_admission_order(prefer_rare: bool) {
    let root = unique_runtime_dir(if prefer_rare {
        "core-ready-rare-order"
    } else {
        "core-ready-admission-order"
    });
    let mut seeds = Vec::new();
    let mut files = Vec::new();
    for (index, size) in [(0u8, 4096), (1u8, 2048)] {
        let library = root.join(format!("library-{index}"));
        std::fs::create_dir_all(&library).unwrap();
        std::fs::write(library.join("Sample.bin"), vec![0x64 + index; size]).unwrap();
        let (seed, network) = local_preparation_core(
            &root.join(format!("seed-{index}")),
            [0x64 + index; 16],
            None,
        );
        seed.create_library_root(&library.to_string_lossy(), false)
            .await
            .unwrap()
            .unwrap();
        let shares = seed.reload_shared_directories().await.unwrap();
        let hash = shares
            .iter()
            .find(|share| share.name == "Sample.bin")
            .unwrap()
            .hash
            .clone();
        drop(shares);
        seed.connect_ed2k().await.unwrap();
        files.push((hash, size as u64, network.listen_port, network.user_hash));
        seeds.push(seed);
    }
    let (download, _) = local_preparation_core(&root.join("download"), [0x66; 16], Some(1));
    // Occupy the full 1 + ceil(1/4) ceiling before preparing the ready cohort.
    // Lowering a limit retains existing owners, as it does during real drains.
    download.download_attempts.apply_concurrency_limit(Some(2));
    let mut active = Vec::new();
    let mut victim = None;
    for byte in [0x67, 0x68] {
        let (_, blocker) = download
            .create_download(DownloadCreate {
                source: DownloadCreateSource::Content {
                    hash: Ed2kHash::from_bytes([byte; 16]).to_string(),
                    name: "Active.bin".into(),
                    size_bytes: Some(16),
                },
                category: None,
                intent: emulebb_metadata::DownloadIntent::Started,
                redownload: false,
            })
            .await
            .unwrap();
        let blocker_id = blocker.id;
        drop(blocker);
        if byte == 0x67 {
            let header = download
                .ed2k_transfers
                .download_job(blocker_id)
                .await
                .unwrap()
                .unwrap();
            let token = header.token;
            let temp = download.download_temp_selection(&header).await.unwrap();
            drop(header);
            let selected = download
                .ed2k_transfers
                .begin_download_job_execution(token, Some(&temp))
                .await
                .unwrap();
            let token = selected.as_ref().unwrap().token;
            drop(selected);
            let execution = emulebb_ed2k::ed2k_transfer::new_transfer_job(
                token,
                Ed2kHash::from_bytes([byte; 16]),
                "Active.bin".into(),
                16,
            );
            drop(
                download
                    .ed2k_transfers
                    .ensure_job(&execution)
                    .await
                    .unwrap(),
            );
            victim = Some(token);
        }
        let header = download
            .ed2k_transfers
            .download_job(blocker_id)
            .await
            .unwrap()
            .unwrap();
        active.push(
            download
                .download_attempts
                .try_enter(header.token, header.file_hash.parse().unwrap())
                .unwrap(),
        );
        drop(header);
    }
    download.download_attempts.apply_concurrency_limit(Some(1));
    let mut ids = Vec::new();
    for (hash, size, port, user_hash) in &files {
        let (_, created) = download
            .create_download(DownloadCreate {
                source: DownloadCreateSource::Content {
                    hash: hash.clone(),
                    name: "Sample.bin".into(),
                    size_bytes: Some(*size),
                },
                category: None,
                intent: emulebb_metadata::DownloadIntent::Started,
                redownload: false,
            })
            .await
            .unwrap();
        let id = created.id;
        drop(created);
        let header = download
            .ed2k_transfers
            .download_job(id)
            .await
            .unwrap()
            .unwrap();
        let token = header.token;
        drop(header);
        download
            .ed2k_transfers
            .remember_source(
                token,
                Ed2kSourceHint {
                    ip: Ipv4Addr::LOCALHOST.to_string(),
                    tcp_port: *port,
                    user_hash: Some(hex::encode(user_hash)),
                    connect_options: None,
                    file_comment: String::new(),
                    file_rating: 0,
                },
            )
            .await
            .unwrap();
        ids.push((id, token));
        if prefer_rare && *size == 2048 {
            // The smaller file has a second independently observed reporter.
            // Discovery hints alone must not change the scarcity decision.
            download
                .ed2k_transfers
                .remember_source_availability(
                    token,
                    Ed2kSourceHint {
                        ip: "192.0.2.254".into(),
                        tcp_port: 4662,
                        user_hash: Some("79".repeat(16)),
                        connect_options: None,
                        file_comment: String::new(),
                        file_rating: 0,
                    },
                    *size,
                    vec![true],
                )
                .await
                .unwrap();
        }
    }
    download.connect_ed2k().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if download.download_ready_count.load(Ordering::Acquire) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for (id, token) in &ids {
        let detail = download.download_detail(*id).await.unwrap().unwrap();
        assert_eq!(detail.summary.state, crate::DownloadState::Queued);
        assert_eq!(
            detail.summary.waiting_reason,
            Some(crate::DownloadWaitingReason::Resources)
        );
        drop(detail);
        let header = download
            .ed2k_transfers
            .download_job(*id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header.token, *token);
        assert!(
            header.storage.is_none(),
            "ready connections must not hydrate while the payload slot is occupied"
        );
    }
    download
        .download_hydration_busy
        .store(true, Ordering::Release);
    let victim = victim.unwrap();
    assert!(
        download.ed2k_transfers.download_yield_requested(victim),
        "the blocked rare cohort requests an ordinary yield"
    );
    assert_eq!(
        download.download_attempts.admission_counts().1,
        2,
        "a yield request does not release its owner's capacity"
    );
    download
        .ed2k_transfers
        .release_download_job_execution(victim)
        .await
        .unwrap();
    assert_eq!(
        download.download_attempts.admission_counts().1,
        2,
        "Native retirement precedes guard release"
    );
    drop(active.remove(0));
    tokio::time::timeout(Duration::from_secs(10), async {
        while download.download_hydration_busy.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let expected_first = usize::from(!prefer_rare);
    let waiting = download
        .ed2k_transfers
        .download_job(ids[1 - expected_first].0)
        .await
        .unwrap()
        .unwrap();
    let started = download
        .ed2k_transfers
        .download_job(ids[expected_first].0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        waiting.token,
        ids[1 - expected_first].1,
        "ready ordering must honor reporter scarcity before remaining bytes"
    );
    assert!(waiting.storage.is_none());
    assert_eq!(
        started.token.generation,
        ids[expected_first].1.generation + 1
    );
    assert_eq!(
        download.download_attempts.admission_counts().1,
        2,
        "the ready rare file starts in the burst slot while the ordinary owner remains"
    );
    drop((waiting, started));
    drop(active);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if download.share(&files[0].0).await.is_some()
                && download.share(&files[1].0).await.is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    download.disconnect_ed2k().await.unwrap();
    assert_eq!(
        download
            .ed2k_transfers
            .download_resource_snapshot()
            .connections,
        0
    );
    for seed in seeds {
        seed.disconnect_ed2k().await.unwrap();
    }
}
