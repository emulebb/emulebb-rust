use super::*;

#[tokio::test]
async fn prepared_execution_reuses_a_full_connection_budget_and_deduplicates_the_peer() {
    let (runtime, secure, hash_hex, name, size, token) =
        completed_ed2k_transfer_runtime("prepared-core-budget").await;
    runtime.apply_download_coordinator_config(
        emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig {
            max_connections: 1,
            max_connections_per_window: 0,
            ..Default::default()
        },
    );
    let permit = match runtime.try_admit_source_connection() {
        Ed2kSourceConnectionAdmission::Admitted { permit, .. } => permit,
        _ => panic!("initial admission refused"),
    };
    let hash: Ed2kHash = hash_hex.parse().unwrap();
    let source = direct_test_source(hash, Ipv4Addr::new(192, 0, 2, 1), 41001);
    let mut options = direct_download_options(
        token,
        Arc::clone(&runtime),
        secure,
        hash_hex,
        name,
        size,
        vec![source.clone(), source.clone()],
    );
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&ran);
    options.prepared = Some(crate::ed2k_direct_download_types::PreparedDirectDownload {
        source,
        download: Box::pin(async move {
            let _permit = permit;
            observed.store(true, std::sync::atomic::Ordering::Release);
            Ok(Ed2kPeerDownloadReport::single(
                token,
                hash,
                Ed2kPeerDownloadOutcome::AcceptedButIncomplete,
            ))
        }),
    });
    let outcome = run_ed2k_direct_downloads(options, |_, _, _, _, _, _, _, _, _| async {
        panic!("prepared peer must not be dialed again")
    })
    .await
    .unwrap();
    assert!(ran.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(outcome.accepted_incomplete_peers, 1);
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
}

#[tokio::test]
async fn prepared_worker_panic_drains_other_workers_and_their_permits() {
    let (runtime, secure, hash_hex, name, size, token) =
        completed_ed2k_transfer_runtime("prepared-core-panic").await;
    runtime.apply_download_coordinator_config(
        emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig {
            max_connections: 2,
            max_connections_per_window: 0,
            ..Default::default()
        },
    );
    let permit = match runtime.try_admit_source_connection() {
        Ed2kSourceConnectionAdmission::Admitted { permit, .. } => permit,
        _ => panic!("initial admission refused"),
    };
    let hash: Ed2kHash = hash_hex.parse().unwrap();
    let source = direct_test_source(hash, Ipv4Addr::new(192, 0, 2, 1), 41001);
    let other = direct_test_source(hash, Ipv4Addr::new(192, 0, 2, 2), 41002);
    let mut options = direct_download_options(
        token,
        Arc::clone(&runtime),
        secure,
        hash_hex,
        name,
        size,
        vec![other],
    );
    options.max_parallel_download_peers = 2;
    let started = Arc::new(tokio::sync::Notify::new());
    let normal_started = Arc::clone(&started);
    options.prepared = Some(crate::ed2k_direct_download_types::PreparedDirectDownload {
        source,
        download: Box::pin(async move {
            let _permit = permit;
            started.notified().await;
            panic!("synthetic prepared worker failure")
        }),
    });
    let result = run_ed2k_direct_downloads(options, move |_, _, _, _, _, _, _, _, _| {
        let started = Arc::clone(&normal_started);
        async move {
            started.notify_one();
            std::future::pending::<Result<Ed2kPeerDownloadReport>>().await
        }
    })
    .await;
    assert!(result.is_err());
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
}

#[tokio::test]
async fn prepared_content_mismatch_refuses_before_execution_and_drops_its_permit() {
    let (runtime, secure, hash_hex, name, size, token) =
        completed_ed2k_transfer_runtime("prepared-core-content").await;
    let permit = match runtime.try_admit_source_connection() {
        Ed2kSourceConnectionAdmission::Admitted { permit, .. } => permit,
        _ => panic!("initial admission refused"),
    };
    let source = direct_test_source(Ed2kHash([0x59; 16]), Ipv4Addr::new(192, 0, 2, 1), 41001);
    let mut options = direct_download_options(
        token,
        Arc::clone(&runtime),
        secure,
        hash_hex,
        name,
        size,
        Vec::new(),
    );
    options.prepared = Some(crate::ed2k_direct_download_types::PreparedDirectDownload {
        source,
        download: Box::pin(async move {
            let _permit = permit;
            panic!("mismatched prepared content must not execute")
        }),
    });
    assert!(
        run_ed2k_direct_downloads(options, |_, _, _, _, _, _, _, _, _| async {
            panic!("mismatched content must not dial")
        })
        .await
        .is_err()
    );
    assert_eq!(runtime.download_resource_snapshot().connections, 0);
}

#[tokio::test]
async fn direct_download_scheduler_releases_all_slots_on_worker_panic() {
    // A panicking download worker must not leak the connection-budget slots
    // held by the other in-flight workers: the error path drains and releases
    // every remaining slot before returning (FIX B1).
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size, job_token) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-panic").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let mut options = direct_download_options(
        job_token,
        Arc::clone(&transfer_runtime),
        secure_ident,
        file_hash_hex,
        file_name,
        file_size,
        vec![
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 12), 41003),
        ],
    );
    // Spawn all sources at once so several slots are in flight when one panics.
    options.max_parallel_download_peers = 3;

    let result = run_ed2k_direct_downloads(
        options,
        move |_bind_ip,
              _source,
              _hello_identity,
              _secure_ident,
              _transfer_runtime,
              _job_token,
              _file_name,
              _file_size,
              _connect_timeout| async move {
            // Yield first so all three workers are spawned (and hold a slot)
            // before the panic unwinds, exercising the drain path.
            tokio::task::yield_now().await;
            panic!("simulated download worker panic");
        },
    )
    .await;

    assert!(result.is_err(), "a worker panic propagates as an error");

    // Every acquired connection-budget slot must have been released; if a
    // slot leaked, active_connections would be non-zero. Probe via a fresh
    // admission and inspect the reported occupancy before dropping its permit.
    let admission = transfer_runtime.try_admit_source_connection();
    let decision = admission.decision();
    // active_connections counts AFTER this probe acquired one slot, so it must
    // be exactly 1 (the probe itself) with no leaked predecessors.
    assert_eq!(
        decision.active_connections, 1,
        "all worker slots were released after the panic (no budget leak)"
    );
    drop(admission);
}

#[tokio::test]
async fn disconnect_drains_download_tasks_and_releases_connection_budget() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.ed2k_transfers.apply_download_coordinator_config(
        emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig {
            max_connections: 1,
            max_connections_per_window: 0,
            ..emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig::default()
        },
    );

    let admission = core.ed2k_transfers.try_admit_source_connection();
    let permit = match admission {
        Ed2kSourceConnectionAdmission::Admitted { decision, permit } => {
            assert_eq!(decision.active_connections, 1);
            permit
        }
        Ed2kSourceConnectionAdmission::Denied { decision } => {
            panic!("initial source connection was denied: {decision:?}")
        }
    };
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    core.ed2k_download_tasks.spawn(move |quiesce| async move {
        let _permit = permit;
        let _ = started_tx.send(());
        quiesce.cancelled().await;
    });
    started_rx.await.unwrap();

    core.disconnect_ed2k().await.unwrap();

    assert!(core.ed2k_download_tasks.is_empty());
    let next_admission = core.ed2k_transfers.try_admit_source_connection();
    match next_admission {
        Ed2kSourceConnectionAdmission::Admitted { decision, .. } => {
            assert_eq!(decision.active_connections, 1);
            assert_eq!(decision.connection_cap, 1);
        }
        Ed2kSourceConnectionAdmission::Denied { decision } => {
            panic!("disconnect leaked the prior connection budget: {decision:?}")
        }
    }
}

#[tokio::test]
async fn direct_download_scheduler_retries_other_peer_after_failure() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size, job_token) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-retry").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            job_token,
            transfer_runtime,
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
            ],
        ),
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  _transfer_runtime,
                  job_token,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        anyhow::bail!("simulated first peer failure");
                    }
                    Ok(Ed2kPeerDownloadReport::single(
                        job_token,
                        source.file_hash,
                        Ed2kPeerDownloadOutcome::Completed,
                    ))
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 0);
    assert!(outcome.last_error.is_some());
    assert_eq!(*attempts.lock().await, vec![41001, 41002]);
}

#[tokio::test]
async fn direct_download_scheduler_attributes_a4af_results_to_the_switched_file() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size, job_token) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-a4af-attribution").await;
    let primary_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let alternate_hash = Ed2kHash::from_bytes([0xA4; 16]);
    let alternate = transfer_runtime
        .admit_download_job(
            &emulebb_metadata::DownloadJobRequest {
                file_hash: alternate_hash.to_string(),
                display_name: "Alternate.bin".into(),
                expected_size_bytes: Some(16),
                category_id: None,
                intent: emulebb_metadata::DownloadIntent::Started,
                piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
            },
            false,
            None,
            &Default::default(),
        )
        .await
        .unwrap();
    let alternate_token = alternate.job.token;
    drop(alternate);
    let source = direct_test_source(primary_hash, Ipv4Addr::new(192, 0, 2, 20), 41020);

    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            job_token,
            transfer_runtime,
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![source],
        ),
        move |_bind_ip,
              source,
              _hello_identity,
              _secure_ident,
              _transfer_runtime,
              job_token,
              _file_name,
              _file_size,
              _connect_timeout| async move {
            Ok(Ed2kPeerDownloadReport {
                file_outcomes: vec![
                    emulebb_ed2k::ed2k_tcp::Ed2kPeerFileDownloadOutcome {
                        observed_peer: None,
                        job_token,
                        file_hash: source.file_hash,
                        outcome: Ed2kPeerDownloadOutcome::Completed,
                    },
                    emulebb_ed2k::ed2k_tcp::Ed2kPeerFileDownloadOutcome {
                        observed_peer: None,
                        job_token: alternate_token,
                        file_hash: alternate_hash,
                        outcome: Ed2kPeerDownloadOutcome::FileNotFound,
                    },
                ],
                terminal_error: None,
            })
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert!(outcome.file_not_found_sources.is_empty());
    assert_eq!(outcome.alternate_file_outcomes.len(), 1);
    assert_eq!(
        outcome.alternate_file_outcomes[0].job_token,
        alternate_token
    );
    let alternate = &outcome.alternate_file_outcomes[0];
    assert_eq!(alternate.file_hash, alternate_hash.to_string());
    assert_eq!(alternate.source.file_hash, alternate_hash);
    assert_eq!(alternate.outcome, Ed2kPeerDownloadOutcome::FileNotFound);
}

#[tokio::test]
async fn direct_download_scheduler_retries_loopback_peer_after_connection_refused() {
    let runtime_dir = unique_runtime_dir("emulebb-core-loopback-refused-retry");
    let transfer_runtime =
        Arc::new(Ed2kTransferRuntime::load_or_create(&runtime_dir.join("transfers")).unwrap());
    let secure_ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&runtime_dir.join("secure-ident.der")).unwrap());
    let payload = Arc::new(b"captured small file payload".repeat(32));
    let file_name = "captured.epub".to_string();
    let payload_path = runtime_dir.join("payload.bin");
    std::fs::write(&payload_path, payload.as_slice()).unwrap();
    let hash_runtime =
        Ed2kTransferRuntime::load_or_create(&runtime_dir.join("hash-transfers")).unwrap();
    let summary = hash_runtime
        .ingest_local_file(&payload_path, &file_name)
        .await
        .unwrap();
    let file_hash: Ed2kHash = summary.file_hash.parse().unwrap();
    let file_hash_hex = summary.file_hash;
    let file_size = summary.file_size;
    let job_token = admit_scheduler_test_job(
        &transfer_runtime,
        &runtime_dir.join("transfers"),
        file_hash,
        file_name.clone(),
        file_size,
    )
    .await;
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let success_after_attempt = 3usize;
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            job_token,
            transfer_runtime,
            secure_ident,
            file_hash_hex.clone(),
            file_name,
            file_size,
            vec![direct_test_source(file_hash, Ipv4Addr::LOCALHOST, 41001)],
        ),
        {
            let attempts = Arc::clone(&attempts);
            let payload = Arc::clone(&payload);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  transfer_runtime,
                  job_token,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if attempts.lock().await.len() < success_after_attempt {
                        return Err(anyhow::Error::new(std::io::Error::from(
                            std::io::ErrorKind::ConnectionRefused,
                        )));
                    }
                    transfer_runtime
                        .store_md4_hashset(job_token, Vec::new())
                        .await?;
                    transfer_runtime
                        .store_piece_data(job_token, 0, payload.as_slice())
                        .await?;
                    Ok(Ed2kPeerDownloadReport::single(
                        job_token,
                        source.file_hash,
                        Ed2kPeerDownloadOutcome::Completed,
                    ))
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 0);
    assert!(outcome.last_error.is_some());
    assert_eq!(*attempts.lock().await, vec![41001, 41001, 41001]);
}

#[tokio::test]
async fn direct_download_scheduler_tracks_accepted_incomplete_peer() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size, job_token) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-incomplete").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            job_token,
            transfer_runtime,
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
                direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002),
            ],
        ),
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  _transfer_runtime,
                  job_token,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        return Ok(Ed2kPeerDownloadReport::single(
                            job_token,
                            source.file_hash,
                            Ed2kPeerDownloadOutcome::AcceptedButIncomplete,
                        ));
                    }
                    Ok(Ed2kPeerDownloadReport::single(
                        job_token,
                        source.file_hash,
                        Ed2kPeerDownloadOutcome::Completed,
                    ))
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 1);
    assert!(outcome.last_error.is_none());
    assert_eq!(*attempts.lock().await, vec![41001, 41002]);
}

#[tokio::test]
async fn direct_download_scheduler_does_not_downgrade_failed_obfuscated_peer() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size, job_token) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-no-plaintext-downgrade")
            .await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let mut source = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    source.obfuscated = true;
    source.obfuscation_options = Some(0x03);
    source.user_hash = Some([0x22; 16]);
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
            job_token,
            transfer_runtime,
            secure_ident,
            file_hash_hex,
            file_name,
            file_size,
            vec![source],
        ),
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  _transfer_runtime,
                  job_token,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push((
                        source.tcp_port,
                        source.obfuscated,
                        source.user_hash.is_some(),
                    ));
                    if source.obfuscated {
                        anyhow::bail!("simulated obfuscated peer close");
                    }
                    Ok(Ed2kPeerDownloadReport::single(
                        job_token,
                        source.file_hash,
                        Ed2kPeerDownloadOutcome::Completed,
                    ))
                }
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(
        outcome
            .last_error
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("simulated obfuscated peer close")
    );
    assert_eq!(*attempts.lock().await, vec![(41001, true, true)]);
}

#[test]
fn direct_download_candidates_deduplicate_same_endpoint_in_one_round() {
    let file_hash = Ed2kHash::from_bytes([0x45; 16]);
    let mut obfuscated = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    obfuscated.obfuscated = true;
    obfuscated.obfuscation_options = Some(0x03);
    obfuscated.user_hash = Some([0x11; 16]);
    let plaintext = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);

    let candidates =
        direct_download_candidate_sources(&[obfuscated.clone(), plaintext], &HashSet::new());

    assert_eq!(candidates, vec![obfuscated]);
}

#[test]
fn direct_download_candidates_skip_attempted_endpoint_family() {
    let file_hash = Ed2kHash::from_bytes([0x47; 16]);
    let mut attempted_endpoints = HashSet::new();
    attempted_endpoints.insert((Ipv4Addr::new(192, 0, 2, 10), 41001));
    let mut obfuscated = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    obfuscated.obfuscated = true;
    obfuscated.obfuscation_options = Some(0x03);
    obfuscated.user_hash = Some([0x11; 16]);
    let next_endpoint = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002);

    let candidates = direct_download_candidate_sources(
        &[
            obfuscated,
            direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001),
            next_endpoint.clone(),
        ],
        &attempted_endpoints,
    );

    assert_eq!(candidates, vec![next_endpoint]);
}

#[test]
fn direct_download_candidates_skip_required_obfuscation_without_user_hash() {
    let file_hash = Ed2kHash::from_bytes([0x50; 16]);
    let mut hashless_required = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    hashless_required.obfuscated = true;
    hashless_required.obfuscation_options = Some(0x07);
    hashless_required.user_hash = None;
    let mut hashed_required = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 11), 41002);
    hashed_required.obfuscated = true;
    hashed_required.obfuscation_options = Some(0x07);
    hashed_required.user_hash = Some([0x11; 16]);

    let candidates = direct_download_candidate_sources(
        &[hashless_required, hashed_required.clone()],
        &HashSet::new(),
    );

    assert_eq!(candidates, vec![hashed_required]);
}

#[tokio::test]
async fn direct_download_source_leases_allow_selected_file_without_double_engaging_peer() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let lower_hash = Ed2kHash::from_bytes([0x48; 16]).to_string();
    let lower_hash_owner = a4af_test_owner(&core, &lower_hash.to_string());
    let higher_hash = Ed2kHash::from_bytes([0x49; 16]).to_string();
    let higher_hash_owner = a4af_test_owner(&core, &higher_hash.to_string());
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x48; 16]),
        Ipv4Addr::new(192, 0, 2, 12),
        41003,
    );
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: lower_hash.clone(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: higher_hash.clone(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    let (lower_sources, lower_deferred, lower_delay) = core
        .acquire_direct_download_source_leases(
            lower_hash_owner.token(),
            &lower_hash,
            std::slice::from_ref(&source),
        )
        .await;
    let (higher_sources, higher_deferred, higher_delay) = core
        .acquire_direct_download_source_leases(
            higher_hash_owner.token(),
            &higher_hash,
            std::slice::from_ref(&source),
        )
        .await;

    assert_eq!(lower_sources, vec![source.clone()]);
    assert_eq!(lower_deferred, 0);
    assert!(lower_delay.is_none());
    assert!(higher_sources.is_empty());
    assert_eq!(higher_deferred, 1);
    assert!(higher_delay.is_none());
    core.release_direct_download_source_leases(
        lower_hash_owner.token(),
        &[source_endpoint_key(&source)],
    )
    .await;
    let (sources, deferred, retry) = core
        .acquire_direct_download_source_leases(
            higher_hash_owner.token(),
            &higher_hash,
            std::slice::from_ref(&source),
        )
        .await;
    assert_eq!(sources, vec![source.clone()]);
    assert_eq!(deferred, 0);
    assert!(retry.is_none());
    core.release_direct_download_source_leases(
        higher_hash_owner.token(),
        &[source_endpoint_key(&source)],
    )
    .await;
}

#[tokio::test]
async fn disconnect_releases_detached_reask_source_leases_and_re_engages() {
    // A detached source held on the UDP reask loop keeps its lease
    // (active_download_peer_endpoints + the registry leased_peers). When the
    // reask loop breaks on shutdown without emitting SourceReleased, the lease
    // would leak; disconnect_ed2k must reset it so the source is re-engageable
    // after a reconnect.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x4a; 16]).to_string();
    let file_hash_owner = a4af_test_owner(&core, &file_hash.to_string());
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x4a; 16]),
        Ipv4Addr::new(192, 0, 2, 50),
        41020,
    );
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file_hash.clone(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    // Engage (lease) the source, as a download attempt would before detaching
    // it onto the reask loop.
    let (engaged, deferred, retry_delay) = core
        .acquire_direct_download_source_leases(
            file_hash_owner.token(),
            &file_hash,
            std::slice::from_ref(&source),
        )
        .await;
    assert_eq!(engaged, vec![source.clone()]);
    assert_eq!(deferred, 0);
    assert!(retry_delay.is_none());
    {
        let state = core.state.lock().await;
        assert_eq!(state.active_download_peer_endpoints.len(), 1);
        assert_eq!(state.download_source_registry.leased_peer_count(), 1);
    }

    // The reask loop breaks on shutdown without emitting SourceReleased; the
    // lease would leak. disconnect_ed2k must release it.
    core.disconnect_ed2k().await.unwrap();
    {
        let state = core.state.lock().await;
        assert!(
            state.active_download_peer_endpoints.is_empty(),
            "disconnect must clear active download peer endpoints"
        );
        assert_eq!(
            state.download_source_registry.leased_peer_count(),
            0,
            "disconnect must release detached source leases"
        );
    }

    // The lease is gone, but the endpoint retry cooldown still gates redial.
    let (re_engaged, re_deferred, re_retry_delay) = core
        .acquire_direct_download_source_leases(
            file_hash_owner.token(),
            &file_hash,
            std::slice::from_ref(&source),
        )
        .await;
    assert!(re_engaged.is_empty());
    assert_eq!(re_deferred, 1);
    assert!(re_retry_delay.is_some());
}

#[tokio::test]
async fn lease_release_is_tcp_keyed_so_a_udp_endpoint_never_matches() {
    // RUST-PAR-017 DL-11: core's lease sets (active_download_peer_endpoints +
    // the registry leased peers) are keyed by (ip, tcp_port), while the UDP
    // reask loop routes sources by (ip, udp_port). A SourceReleased carrying
    // the UDP endpoint therefore releases NOTHING — the lease leaks and the
    // source can never be re-engaged. This pins the constraint that forced
    // the loop to carry the TCP lease key in its release events.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x5b; 16]).to_string();
    let file_hash_owner = a4af_test_owner(&core, &file_hash.to_string());
    let ip = Ipv4Addr::new(192, 0, 2, 60);
    let tcp_port = 4662u16;
    let udp_port = 4672u16;
    let source = direct_test_source(Ed2kHash::from_bytes([0x5b; 16]), ip, tcp_port);
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file_hash.clone(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }
    let (engaged, _, _) = core
        .acquire_direct_download_source_leases(
            file_hash_owner.token(),
            &file_hash,
            std::slice::from_ref(&source),
        )
        .await;
    assert_eq!(engaged, vec![source.clone()]);

    // Releasing by the peer's UDP endpoint (what the reask loop routes on)
    // must not free the TCP-keyed lease — the endpoints live in different
    // keyspaces, so this is a no-op by construction.
    core.release_direct_download_source_leases(file_hash_owner.token(), &[(ip, udp_port)])
        .await;
    {
        let state = core.state.lock().await;
        assert_eq!(
            state.active_download_peer_endpoints.len(),
            1,
            "a UDP endpoint must not match the TCP-keyed active set"
        );
        assert_eq!(
            state.download_source_registry.leased_peer_count(),
            1,
            "a UDP endpoint must not match the TCP-keyed registry lease"
        );
    }

    // Releasing by the TCP lease key (what SourceReleased now carries) frees it.
    core.release_direct_download_source_leases(
        file_hash_owner.token(),
        &[source_endpoint_key(&source)],
    )
    .await;
    {
        let state = core.state.lock().await;
        assert!(state.active_download_peer_endpoints.is_empty());
        assert_eq!(state.download_source_registry.leased_peer_count(), 0);
    }
}

#[tokio::test]
async fn run_attempt_stops_immediately_when_pre_cancelled() {
    // The requery loop checks the per-hash cancel token at the top of each
    // round (and the function checks it before any work). A pre-cancelled token
    // makes the attempt a no-op that returns Ok(None) so the queued-attempt
    // wrapper neither rewrites the transfer state nor re-queues a retry.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let transfer = a4af_test_transfer(
        &core,
        &Ed2kHash::from_bytes([0x80; 16]).to_string(),
        "downloading",
    );
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = core
        .run_ed2k_download_attempt(&transfer, transfer.job_token(), &cancel, None)
        .await
        .unwrap();
    assert!(
        result.is_none(),
        "a cancelled attempt must return Ok(None) so it neither restates nor retries"
    );
}

#[test]
fn queued_jobs_remain_retryable() {
    assert!(should_retry_download_attempt_state("downloading"));
    assert!(should_retry_download_attempt_state("queued"));
    assert!(!should_retry_download_attempt_state("stopped"));
    assert!(!should_retry_download_attempt_state("completed"));
    assert!(!should_retry_download_attempt_state("failed"));
}

#[test]
fn hash_only_transfer_without_sources_remains_queued() {
    assert_eq!(ed2k_download_state_without_sources(0), "queued");
    assert_eq!(ed2k_download_state_without_sources(1), "downloading");
}

#[tokio::test]
async fn explicit_link_source_dials_without_server_config() {
    let runtime_dir = unique_runtime_dir("emulebb-core-hash-only-explicit-source");
    let mut network = test_network_config_with_store(
        &runtime_dir,
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
        &runtime_dir,
        Some(network),
    )
    .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let source_port = listener.local_addr().unwrap().port();
    let hash = Ed2kHash::from_bytes([0x81; 16]).to_string();
    let (_, download) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Ed2kLink {
                link: format!(
                    "ed2k://|file|Sample.bin|4096|{hash}|sources,127.0.0.1:{source_port}|/"
                ),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        })
        .await
        .unwrap();
    let id = download.id;
    drop(download);
    let (guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    let cancel = CancellationToken::new();
    let attempt_core = core.clone();
    let attempt_cancel = cancel.clone();
    let attempt = tokio::spawn(async move {
        let _guard = guard;
        attempt_core
            .run_ed2k_download_attempt(&transfer, transfer.job_token(), &attempt_cancel, None)
            .await
    });

    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("explicit source should be dialed")
        .unwrap();
    drop(stream);
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .expect("cancelled source attempt should stop");
}

#[tokio::test]
async fn removal_cancels_but_retains_peer_ownership_until_worker_retirement() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let request = DownloadCreate {
        source: DownloadCreateSource::Content {
            hash: "00112233445566778899aabbccddeeff".into(),
            name: "Sample.bin".into(),
            size_bytes: Some(4096),
        },
        category: None,
        intent: emulebb_metadata::DownloadIntent::Started,
        redownload: false,
    };
    let (_, download) = core.create_download(request.clone()).await.unwrap();
    let id = download.id;
    drop(download);
    let (guard, transfer) = core.select_download_execution(id).await.unwrap().unwrap();
    let token = guard.token();
    let hash = transfer.hash;
    let source = direct_test_source(hash.parse().unwrap(), Ipv4Addr::new(192, 0, 2, 60), 41030);
    let endpoint = source_endpoint_key(&source);
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: hash.clone(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
        assert!(
            state
                .download_source_registry
                .lease_best_for_file(Instant::now(), Duration::ZERO, &source, &hash)
                .is_some()
        );
        state.active_download_peer_endpoints.insert(endpoint, token);
    }
    assert_eq!(
        core.remove_download(id, false).await.unwrap(),
        DownloadChange::Changed
    );
    assert!(guard.cancellation().is_cancelled());
    assert_eq!(
        core.state
            .lock()
            .await
            .active_download_peer_endpoints
            .get(&endpoint),
        Some(&token)
    );
    let (_, next) = core.create_download(request).await.unwrap();
    let next_id = next.id;
    drop(next);
    assert_ne!(next_id, id);
    assert!(
        core.select_download_execution(next_id)
            .await
            .unwrap()
            .is_none()
    );
    core.release_download_source_file(token, &hash).await;
    drop(guard);
    assert!(
        core.state
            .lock()
            .await
            .active_download_peer_endpoints
            .is_empty()
    );
    assert!(
        core.select_download_execution(next_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn stop_cancels_an_admitted_execution_before_returning() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let (_, download) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: "00112233445566778899aabbccddeeff".into(),
                name: "Sample.bin".into(),
                size_bytes: Some(4096),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        })
        .await
        .unwrap();
    let id = download.id;
    drop(download);
    let (guard, _) = core.select_download_execution(id).await.unwrap().unwrap();
    assert_eq!(
        core.stop_download(id).await.unwrap(),
        DownloadChange::Changed
    );
    assert!(guard.cancellation().is_cancelled());
}

#[tokio::test]
async fn late_peer_release_cannot_release_a_new_execution_lease() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let hash = "00112233445566778899aabbccddeeff";
    let old = a4af_test_owner(&core, hash);
    let old_token = old.token();
    core.stop_download(old_token.job_id).await.unwrap();
    drop(old);
    core.start_download(old_token.job_id).await.unwrap();
    let current = core
        .ed2k_transfers
        .download_job(old_token.job_id)
        .await
        .unwrap()
        .unwrap()
        .token;
    let _guard = core
        .download_attempts
        .try_enter(current, hash.parse().unwrap())
        .unwrap();
    let source = direct_test_source(hash.parse().unwrap(), Ipv4Addr::new(192, 0, 2, 61), 41031);
    let endpoint = source_endpoint_key(&source);
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: hash.into(),
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
        assert!(
            state
                .download_source_registry
                .lease_best_for_file(Instant::now(), Duration::ZERO, &source, hash)
                .is_some()
        );
        state
            .active_download_peer_endpoints
            .insert(endpoint, current);
    }
    core.release_direct_download_source_leases(old_token, &[endpoint])
        .await;
    assert_eq!(
        core.state
            .lock()
            .await
            .active_download_peer_endpoints
            .get(&endpoint),
        Some(&current)
    );
    assert_eq!(
        core.state
            .lock()
            .await
            .download_source_registry
            .leased_peer_count(),
        1
    );
    core.release_direct_download_source_leases(current, &[endpoint])
        .await;
    assert!(
        core.state
            .lock()
            .await
            .active_download_peer_endpoints
            .is_empty()
    );
    assert_eq!(
        core.state
            .lock()
            .await
            .download_source_registry
            .leased_peer_count(),
        0
    );
}
