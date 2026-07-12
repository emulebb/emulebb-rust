use super::*;

#[tokio::test]
async fn direct_download_scheduler_releases_all_slots_on_worker_panic() {
    // A panicking download worker must not leak the connection-budget slots
    // held by the other in-flight workers: the error path drains and releases
    // every remaining slot before returning (FIX B1).
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-panic").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let mut options = direct_download_options(
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
    // acquire and inspect the reported occupancy before the probe.
    let decision = transfer_runtime.try_acquire_source_connection_detailed();
    // active_connections counts AFTER this probe acquired one slot, so it must
    // be exactly 1 (the probe itself) with no leaked predecessors.
    assert_eq!(
        decision.active_connections, 1,
        "all worker slots were released after the panic (no budget leak)"
    );
    transfer_runtime.release_source_connection();
}

#[tokio::test]
async fn direct_download_scheduler_retries_other_peer_after_failure() {
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-retry").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
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
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        anyhow::bail!("simulated first peer failure");
                    }
                    Ok(Ed2kPeerDownloadOutcome::Completed)
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
    transfer_runtime
        .ensure_job(&new_transfer_job(file_hash, file_name.clone(), file_size))
        .await
        .unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let success_after_attempt = 3usize;
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
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
            let file_hash_hex = file_hash_hex.clone();
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                let file_hash_hex = file_hash_hex.clone();
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if attempts.lock().await.len() < success_after_attempt {
                        return Err(anyhow::Error::new(std::io::Error::from(
                            std::io::ErrorKind::ConnectionRefused,
                        )));
                    }
                    transfer_runtime
                        .store_md4_hashset(&file_hash_hex, Vec::new())
                        .await?;
                    transfer_runtime
                        .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                        .await?;
                    Ok(Ed2kPeerDownloadOutcome::Completed)
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
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
        completed_ed2k_transfer_runtime("emulebb-core-direct-download-incomplete").await;
    let file_hash: Ed2kHash = file_hash_hex.parse().unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let outcome = run_ed2k_direct_downloads(
        direct_download_options(
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
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    Ok(Ed2kPeerDownloadOutcome::Completed)
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
    let (transfer_runtime, secure_ident, file_hash_hex, file_name, file_size) =
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
                    Ok(Ed2kPeerDownloadOutcome::Completed)
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
async fn direct_download_source_leases_defer_peer_to_better_file_candidate() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let lower_hash = Ed2kHash::from_bytes([0x48; 16]).to_string();
    let higher_hash = Ed2kHash::from_bytes([0x49; 16]).to_string();
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
                file_priority: 1,
                needed_parts: 8,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: higher_hash.clone(),
                file_priority: 9,
                needed_parts: 1,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    let (lower_sources, lower_deferred, lower_delay) = core
        .acquire_direct_download_source_leases(&lower_hash, std::slice::from_ref(&source))
        .await;
    let (higher_sources, higher_deferred, higher_delay) = core
        .acquire_direct_download_source_leases(&higher_hash, std::slice::from_ref(&source))
        .await;

    assert!(lower_sources.is_empty());
    assert_eq!(lower_deferred, 1);
    assert!(lower_delay.is_none());
    assert_eq!(higher_sources, vec![source.clone()]);
    assert_eq!(higher_deferred, 0);
    assert!(higher_delay.is_none());
    core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
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
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    // Engage (lease) the source, as a download attempt would before detaching
    // it onto the reask loop.
    let (engaged, deferred, retry_delay) = core
        .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
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
    core.disconnect_ed2k().await;
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
        .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
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
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }
    let (engaged, _, _) = core
        .acquire_direct_download_source_leases(&file_hash, std::slice::from_ref(&source))
        .await;
    assert_eq!(engaged, vec![source.clone()]);

    // Releasing by the peer's UDP endpoint (what the reask loop routes on)
    // must not free the TCP-keyed lease — the endpoints live in different
    // keyspaces, so this is a no-op by construction.
    core.release_direct_download_source_leases(&[(ip, udp_port)])
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
    core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
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
    let transfer = a4af_test_transfer(&Ed2kHash::from_bytes([0x80; 16]).to_string(), "downloading");
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = core
        .run_ed2k_download_attempt(&transfer, &cancel)
        .await
        .unwrap();
    assert!(
        result.is_none(),
        "a cancelled attempt must return Ok(None) so it neither restates nor retries"
    );
}

#[test]
fn queued_active_download_attempts_remain_retryable() {
    assert!(should_retry_download_attempt_state("downloading"));
    assert!(should_retry_download_attempt_state("queued"));
    assert!(!should_retry_download_attempt_state("paused"));
    assert!(!should_retry_download_attempt_state("stopped"));
    assert!(!should_retry_download_attempt_state("completed"));
    assert!(!should_retry_download_attempt_state("error"));
}

#[tokio::test]
async fn delete_transfer_files_cancels_attempt_and_releases_hash_leases() {
    // Delete must promptly free everything the running attempt holds for the
    // hash: cancel its in-flight token, release the hash's leases + the
    // matching active endpoints, and clear the dedup + cancel slots so a
    // re-create can immediately re-download (it no longer early-returns on a
    // stale dedup slot or finds the peer deferred by a leaked lease).
    let runtime_dir = unique_runtime_dir("emulebb-core-delete-cancels-attempt");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    // Create paused so no background attempt is queued to race the simulated
    // running-attempt state we install below.
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Cancel.Me.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();
    let hash = transfer.hash.clone();
    let source = direct_test_source(hash.parse().unwrap(), Ipv4Addr::new(192, 0, 2, 60), 41030);
    let endpoint = source_endpoint_key(&source);

    // Simulate a running attempt for this hash: a registered + leased source
    // (active endpoint), the dedup slot, and an installed cancel token.
    let cancel = CancellationToken::new();
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: hash.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
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
        state.active_download_peer_endpoints.insert(endpoint);
        state.active_download_attempts.insert(hash.clone());
        state
            .download_cancels
            .insert(hash.clone(), (0, cancel.clone()));
    }

    let deleted = core.delete_transfer_files(&hash).await.unwrap().unwrap();
    assert_eq!(deleted.hash, hash);

    // The in-flight attempt is signalled to stop.
    assert!(
        cancel.is_cancelled(),
        "delete must cancel the in-flight attempt for the hash"
    );
    let state = core.state.lock().await;
    assert_eq!(
        state.download_source_registry.leased_peer_count(),
        0,
        "delete must release the hash's leases"
    );
    assert_eq!(
        state
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &hash),
        0,
        "delete must forget the hash's source candidates"
    );
    assert!(
        !state.active_download_peer_endpoints.contains(&endpoint),
        "delete must drop the matching active download endpoint"
    );
    assert!(
        !state.active_download_attempts.contains(&hash),
        "delete must clear the dedup slot so a re-create can re-download"
    );
    assert!(
        !state.download_cancels.contains_key(&hash),
        "delete must clear the cancel slot"
    );
}

#[tokio::test]
async fn pause_transfer_cancels_in_flight_attempt() {
    // Pause must stop the transfer now: the driver does not read control_state
    // mid-attempt, so pause cancels the in-flight attempt's token (the loop
    // then stops at its next cancel check) rather than only suppressing the
    // next retry.
    let runtime_dir = unique_runtime_dir("emulebb-core-pause-cancels-attempt");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap();
    // Create paused so no background attempt is queued to race our manually
    // installed token (the attempt's own token would otherwise overwrite it).
    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Pause.Me.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();
    let hash = transfer.hash.clone();

    // Simulate a running attempt's cancel token for this hash.
    let cancel = CancellationToken::new();
    core.state
        .lock()
        .await
        .download_cancels
        .insert(hash.clone(), (0, cancel.clone()));

    let paused = core.pause_transfer(&hash).await.unwrap().unwrap();
    assert_eq!(paused.state, "paused");
    assert!(
        cancel.is_cancelled(),
        "pause must cancel the in-flight attempt so it stops now, not at next retry"
    );
}
