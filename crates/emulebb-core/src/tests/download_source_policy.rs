use super::*;

#[tokio::test]
async fn a4af_multi_file_peer_is_reused_and_not_double_engaged() {
    // A4AF-lite leg 1: a peer registered for two of our files is engaged for
    // exactly one file at a time; the second file defers the same peer
    // (one active relationship per peer, like eMule) rather than opening a
    // redundant second engagement.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file_a = Ed2kHash::from_bytes([0x71; 16]).to_string();
    let file_b = Ed2kHash::from_bytes([0x72; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x71; 16]),
        Ipv4Addr::new(192, 0, 2, 31),
        41010,
    );
    {
        let mut state = core.state.lock().await;
        // File A is the peer's best (higher priority), so it wins the single
        // per-peer relationship; file B is the lower-priority other file.
        for (hash, priority) in [(&file_a, 9u32), (&file_b, 3u32)] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: hash.clone(),
                    file_priority: priority,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    let (a_sources, a_deferred, a_delay) = core
        .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
        .await;
    let (b_sources, b_deferred, b_delay) = core
        .acquire_direct_download_source_leases(&file_b, std::slice::from_ref(&source))
        .await;

    // Engaged once (file A, the peer's best), deferred (NOT double-engaged)
    // for file B: one active relationship per peer, like eMule.
    assert_eq!(a_sources, vec![source.clone()]);
    assert_eq!(a_deferred, 0);
    assert!(a_delay.is_none());
    assert!(b_sources.is_empty());
    assert_eq!(b_deferred, 1);
    assert!(b_delay.is_none());

    // The peer holds exactly one active engagement across both files (no
    // double-engage / one relationship per peer).
    assert_eq!(
        core.state.lock().await.active_download_peer_endpoints.len(),
        1
    );

    // After the peer is released, the same endpoint remains cooldown-deferred
    // until the MFC-style retry window expires instead of being redialed.
    core.release_direct_download_source_leases(&[source_endpoint_key(&source)])
        .await;
    let (a_again, a_again_deferred, a_again_delay) = core
        .acquire_direct_download_source_leases(&file_a, std::slice::from_ref(&source))
        .await;
    assert!(a_again.is_empty());
    assert_eq!(a_again_deferred, 1);
    assert!(a_again_delay.is_some());
}

#[tokio::test]
async fn fnf_dead_listed_source_is_dropped_and_blocked_from_readmission() {
    // DL-2 (oracle CPartFile::m_DeadSourceList, ListenSocket.cpp:645-661): a
    // source that answered OP_FILEREQANSNOFIL is dead-listed for 45 minutes —
    // its registry candidate is dropped, re-registration is refused
    // (DownloadQueue.cpp:1420/:1530 IsDeadSource admission gates), and lease
    // acquisition skips it WITHOUT deferring (the transfer must not wait on a
    // dead source). The same peer's relationship with another file is
    // untouched (the list is per-(file, source)).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let dead_file = Ed2kHash::from_bytes([0x74; 16]).to_string();
    let other_file = Ed2kHash::from_bytes([0x75; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x74; 16]),
        Ipv4Addr::new(192, 0, 2, 32),
        41011,
    );
    {
        let mut state = core.state.lock().await;
        for hash in [&dead_file, &other_file] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: (*hash).clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 0,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    core.dead_list_file_not_found_sources(&dead_file, std::slice::from_ref(&source))
        .await;
    {
        let now = Instant::now();
        let state = core.state.lock().await;
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &dead_file),
            0,
            "the FNF source's candidate for the dead file must be dropped"
        );
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &other_file),
            1,
            "the same peer's candidate for another file is untouched"
        );
    }

    // Re-registration is refused while the 45-minute block runs.
    let transfer = a4af_test_transfer(&dead_file, "downloading");
    core.register_download_source_candidates(&transfer, std::slice::from_ref(&source))
        .await;
    {
        let now = Instant::now();
        let state = core.state.lock().await;
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &dead_file),
            0,
            "a dead-listed source must not be re-admitted to the registry"
        );
    }

    // Lease acquisition skips the dead source without deferring: no retry
    // wait is owed to a dead source.
    let (engaged, deferred, retry_delay) = core
        .acquire_direct_download_source_leases(&dead_file, std::slice::from_ref(&source))
        .await;
    assert!(engaged.is_empty());
    assert_eq!(deferred, 0);
    assert!(retry_delay.is_none());
}

#[tokio::test]
async fn udp_fnf_dead_lists_the_sole_registered_source_by_ip() {
    // UDP reask FNF (oracle UDPReaskFNF): the loop only knows the peer's UDP
    // endpoint, so core recovers the full identity from the registry by
    // (ip, file), dead-lists it, and drops the candidate — after which the
    // admission gate refuses re-registration. With TWO distinct peers at the
    // same IP serving the file the resolution is ambiguous and nothing is
    // dead-listed (better than blocking the wrong client behind a NAT).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file = Ed2kHash::from_bytes([0x76; 16]).to_string();
    let peer_ip = Ipv4Addr::new(192, 0, 2, 33);
    let source = direct_test_source(Ed2kHash::from_bytes([0x76; 16]), peer_ip, 41012);
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: file.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 0,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    core.dead_list_udp_fnf_source(&file, peer_ip).await;
    {
        let now = Instant::now();
        let state = core.state.lock().await;
        assert_eq!(
            state
                .download_source_registry
                .candidate_count_for_file(now, &file),
            0,
            "the UDP-FNF source's candidate must be dropped"
        );
    }
    let transfer = a4af_test_transfer(&file, "downloading");
    core.register_download_source_candidates(&transfer, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        core.state
            .lock()
            .await
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &file),
        0,
        "a UDP-FNF dead-listed source must not be re-admitted"
    );

    // Ambiguity guard: two distinct peers at one IP -> no dead-listing.
    let ambiguous_file = Ed2kHash::from_bytes([0x77; 16]).to_string();
    let ambiguous_ip = Ipv4Addr::new(192, 0, 2, 34);
    {
        let mut state = core.state.lock().await;
        for tcp_port in [41013u16, 41014] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: ambiguous_file.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 0,
                    source: direct_test_source(
                        Ed2kHash::from_bytes([0x77; 16]),
                        ambiguous_ip,
                        tcp_port,
                    ),
                    last_seen: Instant::now(),
                },
            );
        }
    }
    core.dead_list_udp_fnf_source(&ambiguous_file, ambiguous_ip)
        .await;
    assert_eq!(
        core.state
            .lock()
            .await
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &ambiguous_file),
        2,
        "an ambiguous IP match must not dead-list either candidate"
    );
}

#[tokio::test]
async fn a4af_nnp_source_is_swapped_to_another_wanted_file() {
    // A4AF-lite leg 2: a source with No Needed Parts for the current file but
    // registered for another WANTED file is swapped to that file (its attempt
    // is queued) instead of being dropped (master SwapToAnotherFile).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let current = Ed2kHash::from_bytes([0x73; 16]).to_string();
    let other = Ed2kHash::from_bytes([0x74; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x73; 16]),
        Ipv4Addr::new(192, 0, 2, 32),
        41011,
    );
    {
        let mut state = core.state.lock().await;
        // The other file is a wanted (downloading) transfer.
        state
            .transfers
            .insert(other.clone(), a4af_test_transfer(&other, "downloading"));
        for hash in [&current, &other] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: hash.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    let swapped = core
        .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        swapped, 1,
        "NNP source must be swapped to the other wanted file"
    );
}

#[tokio::test]
async fn a4af_nnp_source_without_other_wanted_file_is_dropped() {
    // A4AF-lite leg 2 negative: a source with No Needed Parts that serves no
    // OTHER wanted file is not swapped (it stays dropped, as before).
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let current = Ed2kHash::from_bytes([0x75; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x75; 16]),
        Ipv4Addr::new(192, 0, 2, 33),
        41012,
    );
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            Instant::now(),
            DownloadSourceCandidate {
                file_hash: current.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 1,
                source: source.clone(),
                last_seen: Instant::now(),
            },
        );
    }

    let swapped = core
        .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        swapped, 0,
        "NNP source with no other wanted file must not be swapped"
    );
}

#[tokio::test]
async fn a4af_nnp_source_other_file_completed_is_not_swapped() {
    // A4AF-lite leg 2 guard: the swap target must still be a wanted transfer;
    // a completed/paused other file is not a valid swap target.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let current = Ed2kHash::from_bytes([0x76; 16]).to_string();
    let other = Ed2kHash::from_bytes([0x77; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x76; 16]),
        Ipv4Addr::new(192, 0, 2, 34),
        41013,
    );
    {
        let mut state = core.state.lock().await;
        state
            .transfers
            .insert(other.clone(), a4af_test_transfer(&other, "completed"));
        for hash in [&current, &other] {
            state.download_source_registry.add_candidate(
                Instant::now(),
                DownloadSourceCandidate {
                    file_hash: hash.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: Instant::now(),
                },
            );
        }
    }

    let swapped = core
        .swap_no_needed_parts_sources(&current, std::slice::from_ref(&source))
        .await;
    assert_eq!(
        swapped, 0,
        "completed other file is not a valid swap target"
    );
}

#[tokio::test]
async fn nnp_source_is_held_for_the_doubled_reask_cycle_not_dropped_or_dead_listed() {
    // RUST-PAR-017 DL-3: an NNP source stays in the download source registry
    // in an NNP-held state (oracle DS_NONEEDEDPARTS keeps the source in the
    // srclist, DownloadClient.cpp:848-852) — it is neither dropped nor
    // dead-listed (NNP is not FNF), and its next re-ask is deferred by the
    // 58-minute hold rather than the 20-minute endpoint cooldown.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let file = Ed2kHash::from_bytes([0x78; 16]).to_string();
    let source = direct_test_source(
        Ed2kHash::from_bytes([0x78; 16]),
        Ipv4Addr::new(192, 0, 2, 35),
        41014,
    );
    let now = Instant::now();
    {
        let mut state = core.state.lock().await;
        state.download_source_registry.add_candidate(
            now,
            DownloadSourceCandidate {
                file_hash: file.clone(),
                file_priority: 5,
                needed_parts: 4,
                rare_parts: 1,
                source: source.clone(),
                last_seen: now,
            },
        );
    }

    let held = core
        .hold_no_needed_parts_sources(&file, std::slice::from_ref(&source))
        .await;
    assert_eq!(held, 1, "the NNP source must be held");

    let mut state = core.state.lock().await;
    assert_eq!(
        state
            .download_source_registry
            .candidate_count_for_file(now, &file),
        1,
        "the held source stays a candidate (kept, not dropped)"
    );
    assert!(
        !state.ed2k_dead_sources.is_dead_source(now, &file, &source),
        "an NNP source is never dead-listed (that is the FNF path)"
    );
    assert_eq!(state.download_source_registry.nnp_source_count(now), 1);
    // The hold (not the attempt cooldown) gates the redial: even with a zero
    // cooldown the lease defers for the full doubled reask interval.
    assert!(
        state
            .download_source_registry
            .lease_best_for_file(
                now + Duration::from_secs(25 * 60),
                Duration::ZERO,
                &source,
                &file
            )
            .is_none(),
        "NNP-held source must not be redialed before the 58-minute hold"
    );
    assert!(
        state
            .download_source_registry
            .lease_best_for_file(
                now + crate::download_source_registry::NNP_REASK_HOLD + Duration::from_secs(1),
                Duration::ZERO,
                &source,
                &file
            )
            .is_some(),
        "the held source is re-asked after FILEREASKTIME * 2"
    );
}

#[tokio::test]
async fn nnp_hold_purges_one_source_per_window_under_source_cap_pressure() {
    // Oracle retention bound (PartFile.cpp:3056-3062): once the file holds
    // >= maxSources * 4/5 sources, an NNP source is dropped instead of held
    // — but at most one per 40-second purge window; the rest stay held.
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.ed2k_transfers.apply_download_coordinator_config(
        emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig {
            // Threshold = 5 * 4/5 = 4 live sources.
            max_sources_per_file: 5,
            ..emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig::default()
        },
    );
    let file = Ed2kHash::from_bytes([0x79; 16]).to_string();
    let now = Instant::now();
    let sources: Vec<Ed2kFoundSource> = (0..5u8)
        .map(|index| {
            direct_test_source(
                Ed2kHash::from_bytes([0x79; 16]),
                Ipv4Addr::new(192, 0, 2, 40 + index),
                41020 + u16::from(index),
            )
        })
        .collect();
    {
        let mut state = core.state.lock().await;
        for source in &sources {
            state.download_source_registry.add_candidate(
                now,
                DownloadSourceCandidate {
                    file_hash: file.clone(),
                    file_priority: 5,
                    needed_parts: 4,
                    rare_parts: 1,
                    source: source.clone(),
                    last_seen: now,
                },
            );
        }
    }

    // Two NNP verdicts in one round: the first is purged (5 >= 4 with the
    // purge window open), the second is held (the 40-second window is spent).
    let held = core
        .hold_no_needed_parts_sources(&file, &sources[0..2])
        .await;
    assert_eq!(held, 1, "only one NNP source is purged per 40s window");

    let mut state = core.state.lock().await;
    assert_eq!(
        state
            .download_source_registry
            .candidate_count_for_file(Instant::now(), &file),
        4,
        "exactly one NNP source was dropped under cap pressure"
    );
    assert_eq!(
        state
            .download_source_registry
            .nnp_source_count(Instant::now()),
        1,
        "the non-purged NNP source is held"
    );
    // The purged source is gone entirely; the held one keeps its candidate.
    assert!(
        state
            .download_source_registry
            .lease_best_for_file(Instant::now(), Duration::ZERO, &sources[0], &file)
            .is_none(),
        "the purged source has no candidate left to lease"
    );
}

#[test]
fn source_requery_skip_waits_for_one_refresh_round_without_progress() {
    assert!(!should_skip_no_progress_source_requery(true, false, 0, 0));
    assert!(should_skip_no_progress_source_requery(true, false, 0, 1));
    assert!(!should_skip_no_progress_source_requery(true, true, 0, 1));
    assert!(!should_skip_no_progress_source_requery(true, false, 1, 1));
    assert!(!should_skip_no_progress_source_requery(false, false, 0, 1));
}

#[test]
fn ed2k_server_source_refresh_is_initial_round_only() {
    assert!(should_refresh_ed2k_server_sources(0));
    assert!(!should_refresh_ed2k_server_sources(1));
    assert!(!should_refresh_ed2k_server_sources(2));
}

#[test]
fn global_udp_source_search_skips_connected_server_only_when_background_is_available() {
    let connected_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));

    assert_eq!(
        global_udp_source_search_excluded_endpoint(false, Some(connected_server)),
        None
    );
    assert_eq!(global_udp_source_search_excluded_endpoint(true, None), None);
    assert_eq!(
        global_udp_source_search_excluded_endpoint(true, Some(connected_server)),
        Some(connected_server)
    );
}

#[test]
fn server_udp_source_supplement_runs_below_the_udp_source_cap() {
    // Oracle: GetMaxSourcePerFileUDP() > GetSourceCount() (default cap 100).
    assert!(should_query_server_udp_source_supplement(0, 100));
    assert!(should_query_server_udp_source_supplement(99, 100));
    assert!(!should_query_server_udp_source_supplement(100, 100));
    assert!(!should_query_server_udp_source_supplement(150, 100));
    // 0 = uncapped.
    assert!(should_query_server_udp_source_supplement(10_000, 0));
}

#[test]
fn callback_route_uses_only_matching_connected_server() {
    let connected_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
    let other_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 4661));

    assert_eq!(
        ed2k_server_callback_route(Some(connected_server), Some(connected_server)),
        Ed2kServerCallbackRoute::BackgroundSession
    );
    assert_eq!(
        ed2k_server_callback_route(Some(other_server), Some(connected_server)),
        Ed2kServerCallbackRoute::Unavailable
    );
    assert_eq!(
        ed2k_server_callback_route(None, Some(connected_server)),
        Ed2kServerCallbackRoute::Unavailable
    );
    assert_eq!(
        ed2k_server_callback_route(Some(connected_server), None),
        Ed2kServerCallbackRoute::Unavailable
    );
}

#[test]
fn manifest_progress_includes_hashset_and_partial_piece_bytes() {
    let file_hash = Ed2kHash::from_bytes([0x48; 16]);
    let job = new_transfer_job(file_hash, "partial.bin".to_string(), 4096);
    let mut manifest = Ed2kResumeManifest::new(&job);
    assert!(!manifest_has_ed2k_transfer_progress(&manifest));

    manifest.md4_hashset_acquired = true;
    assert!(manifest_has_ed2k_transfer_progress(&manifest));
    manifest.md4_hashset_acquired = false;

    manifest.pieces[0].bytes_written = 512;
    assert!(manifest_has_ed2k_transfer_progress(&manifest));
}

#[test]
fn kad_source_supplement_runs_below_the_udp_source_cap() {
    // Same GetMaxSourcePerFileUDP gate as the server UDP walk.
    assert!(should_query_kad_source_supplement(0, 100));
    assert!(should_query_kad_source_supplement(99, 100));
    assert!(!should_query_kad_source_supplement(100, 100));
    // 0 = uncapped.
    assert!(should_query_kad_source_supplement(10_000, 0));
}

#[test]
fn kad_source_result_maps_to_direct_ed2k_source() {
    let file_hash = Ed2kHash::from_bytes([0x49; 16]);
    let source_id = Ed2kHash::from_bytes([0x4a; 16]);
    let source = kad_source_result_to_ed2k_found_source(SourceResult {
        file_hash,
        source_id,
        ip: Ipv4Addr::new(192, 0, 2, 55),
        tcp_port: 4662,
        udp_port: 4672,
        obfuscation_options: Some(0x03),
        source_type: 1,
        buddy_id: None,
        buddy_ip: None,
        buddy_port: 0,
    })
    .expect("mapped source");

    assert_eq!(source.file_hash, file_hash);
    assert_eq!(source.ip, Ipv4Addr::new(192, 0, 2, 55));
    assert_eq!(source.tcp_port, 4662);
    assert_eq!(source.client_id, u32::from(Ipv4Addr::new(192, 0, 2, 55)));
    assert!(!source.low_id);
    assert!(source.obfuscated);
    assert_eq!(source.obfuscation_options, Some(0x03));
    assert_eq!(source.user_hash, Some(source_id.0));
    assert_eq!(source.source_server, None);
    assert_eq!(source.buddy_id, None);
    assert_eq!(source.buddy_endpoint, None);
}

#[test]
fn merge_download_sources_preserves_later_server_provenance() {
    let file_hash = Ed2kHash::from_bytes([0x46; 16]);
    let source_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
    let mut sources = vec![direct_test_source(
        file_hash,
        Ipv4Addr::new(192, 0, 2, 10),
        41001,
    )];
    let mut sourced = direct_test_source(file_hash, Ipv4Addr::new(192, 0, 2, 10), 41001);
    sourced.source_server = Some(source_server);

    merge_download_sources(&mut sources, vec![sourced]);

    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_server, Some(source_server));
}

#[test]
fn drop_self_sources_removes_own_endpoint_and_user_hash() {
    let file_hash = Ed2kHash::from_bytes([0x47; 16]);
    let own_ip = Ipv4Addr::new(203, 0, 113, 7);
    let own_port = 4662u16;
    let own_user_hash = [0xAB; 16];
    let identity = OwnSourceIdentity {
        user_hash: own_user_hash,
        endpoints: vec![(Ipv4Addr::new(192, 168, 50, 2), 4662), (own_ip, own_port)],
    };

    // (1) self by advertised public endpoint, (2) self by local bind endpoint,
    // (3) self by user-hash on a different endpoint, (4) a real foreign source.
    let mut self_by_endpoint = direct_test_source(file_hash, own_ip, own_port);
    self_by_endpoint.user_hash = None;
    let self_by_bind = direct_test_source(file_hash, Ipv4Addr::new(192, 168, 50, 2), 4662);
    let mut self_by_hash = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 9), 5000);
    self_by_hash.user_hash = Some(own_user_hash);
    let foreign = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 22), 4662);

    let mut sources = vec![
        self_by_endpoint,
        self_by_bind,
        self_by_hash,
        foreign.clone(),
    ];
    let dropped = drop_self_sources(&mut sources, &identity);

    assert_eq!(dropped, 3);
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].ip, foreign.ip);
    assert_eq!(sources[0].tcp_port, foreign.tcp_port);
}

#[test]
fn drop_self_sources_keeps_foreign_when_only_port_collides() {
    let file_hash = Ed2kHash::from_bytes([0x48; 16]);
    let identity = OwnSourceIdentity {
        user_hash: [0x01; 16],
        endpoints: vec![(Ipv4Addr::new(203, 0, 113, 7), 4662)],
    };
    // Same port, different IP, different user-hash: a genuine peer, kept.
    let foreign = direct_test_source(file_hash, Ipv4Addr::new(198, 51, 100, 30), 4662);
    let mut sources = vec![foreign];
    assert_eq!(drop_self_sources(&mut sources, &identity), 0);
    assert_eq!(sources.len(), 1);
}

#[test]
fn remembered_source_hint_becomes_direct_dial_source() {
    let file_hash: Ed2kHash = "00112233445566778899aabbccddeeff".parse().unwrap();
    let source = found_source_from_hint(
        file_hash,
        &Ed2kSourceHint {
            ip: "192.0.2.10".to_string(),
            tcp_port: 4662,
            user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
        },
    )
    .unwrap();

    assert_eq!(source.file_hash, file_hash);
    assert_eq!(source.ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
    assert_eq!(source.tcp_port, 4662);
    assert!(source.is_direct_dialable());
    assert!(source.obfuscated);
    assert_eq!(
        source.user_hash,
        Some([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    );
}
