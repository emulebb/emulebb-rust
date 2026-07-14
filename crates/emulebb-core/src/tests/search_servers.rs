use super::*;

#[test]
fn split_stock_search_responses_keeps_pages_under_fragment_limit() {
    let sender_id = NodeId::from_bytes([1; 16]);
    let target = NodeId::from_bytes([2; 16]);
    let results = (0..12)
        .map(|index| SearchResultEntry {
            entry_id: Ed2kHash::from_bytes([index; 16]),
            tags: vec![Tag::filename(format!(
                "ubuntu-linux-parity-result-{index:02}-{}",
                "x".repeat(220)
            ))],
        })
        .collect::<Vec<_>>();
    let response = SearchRes {
        sender_id,
        target,
        results: results.clone(),
    };

    let pages = split_stock_search_responses(response, 1420);

    assert!(pages.len() > 1);
    assert_eq!(
        pages.iter().map(|page| page.results.len()).sum::<usize>(),
        results.len()
    );
    assert!(
        pages
            .iter()
            .all(|page| { KadPacket::SearchRes(page.clone()).encode().unwrap().len() <= 1420 })
    );
    assert_eq!(
        pages
            .into_iter()
            .flat_map(|page| page.results)
            .map(|result| result.entry_id)
            .collect::<Vec<_>>(),
        results
            .into_iter()
            .map(|result| result.entry_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn split_stock_search_responses_keeps_single_oversized_result_like_stock() {
    let sender_id = NodeId::from_bytes([1; 16]);
    let target = NodeId::from_bytes([2; 16]);
    let response = SearchRes {
        sender_id,
        target,
        results: vec![SearchResultEntry {
            entry_id: Ed2kHash::from_bytes([3; 16]),
            tags: vec![Tag::filename("x".repeat(1600))],
        }],
    };

    let pages = split_stock_search_responses(response, 1420);

    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].results.len(), 1);
    assert!(
        KadPacket::SearchRes(pages[0].clone())
            .encode()
            .unwrap()
            .len()
            > 1420
    );
}

#[tokio::test]
async fn search_uses_local_index() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.index_file(IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
        name: "Local.Indexed.File.iso".to_string(),
        size_bytes: 2048,
        content_type: "iso".to_string(),
        availability_score: 3,
    })
    .await
    .unwrap();

    let search = core
        .create_search(SearchCreate {
            query: "indexed file".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();
    // Local index results are present immediately while the search starts
    // "running"; it flips to "completed" once the background pass finishes.
    assert_eq!(search.id, "1");
    assert_eq!(search.status, "running");
    assert_eq!(search.results.len(), 1);
    let mut completed = search;
    for _ in 0..100 {
        if completed.status == "completed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        completed = core.search(&completed.id).await.unwrap();
    }
    assert_eq!(completed.status, "completed");
    assert_eq!(completed.results.len(), 1);
}

// Operator directive 2026-07-06: a network search submitted while the
// backend is still connecting/absent must surface an honest "queued"
// status with a reason and wait for readiness — never complete instantly
// with local-only results — and identical queued queries are rejected
// explicitly instead of amassing wire traffic for later.
#[tokio::test]
async fn network_search_queues_with_honest_status_and_rejects_duplicates() {
    let transfer_root = unique_runtime_dir("emulebb-core-search-queue");
    let network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::open(transfer_root.join("metadata.sqlite")).unwrap(),
        transfer_root.join("transfers"),
        Some(network),
    )
    .unwrap();

    let request = SearchCreate {
        query: "queued query".to_string(),
        method: "server".to_string(),
        ..Default::default()
    };
    let search = core.create_search(request.clone()).await.unwrap();
    assert_eq!(search.status, "queued");
    assert_eq!(
        search.status_reason.as_deref(),
        Some("waiting-for-server-connection")
    );

    // No server session ever connects: the search stays honestly queued
    // (drain ticks run but the backend never becomes ready).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let still_queued = core.search(&search.id).await.unwrap();
    assert_eq!(still_queued.status, "queued");

    // An identical queued query on the same lane is rejected explicitly.
    let error = core
        .create_search(request)
        .await
        .expect_err("duplicate queued query must be rejected");
    assert!(error.to_string().contains("already queued"));

    // A different query queues fine alongside it.
    let other = core
        .create_search(SearchCreate {
            query: "another queued query".to_string(),
            method: "server".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(other.status, "queued");
}

#[tokio::test]
async fn import_server_met_bytes_adds_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // version 0x0E + count 1 + (ip 45.82.80.155, port 5687, 0 tags)
    let mut met = vec![0x0Eu8];
    met.extend_from_slice(&1u32.to_le_bytes());
    met.extend_from_slice(&[45, 82, 80, 155]);
    met.extend_from_slice(&5687u16.to_le_bytes());
    met.extend_from_slice(&0u32.to_le_bytes());

    let added = core.import_server_met_bytes(&met).await.unwrap();
    assert_eq!(added, 1);
    let servers = core.servers().await;
    assert!(
        servers
            .iter()
            .any(|server| server.address == "45.82.80.155" && server.port == 5687)
    );
}

#[tokio::test]
async fn effective_ed2k_config_includes_runtime_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let base = Ed2kRuntimeConfig {
        server_endpoints: vec!["203.0.113.10:4661".to_string()],
        ..Ed2kRuntimeConfig::default()
    };
    core.add_server(ServerCreate {
        address: "203.0.113.20".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();

    let config = core.effective_ed2k_config(&base, None).await.unwrap();

    assert!(
        config
            .server_endpoints
            .iter()
            .any(|endpoint| endpoint == "203.0.113.10:4661")
    );
    assert!(
        config
            .server_entries
            .iter()
            .any(|entry| entry.host == "203.0.113.20" && entry.port == 4661)
    );
}

#[tokio::test]
async fn effective_ed2k_config_excludes_disabled_runtime_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.20".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();
    core.remove_server("203.0.113.20:4661").await.unwrap();

    let servers = core.servers().await;
    let server = servers
        .iter()
        .find(|server| server.endpoint == "203.0.113.20:4661")
        .expect("disabled server remains visible");
    assert!(!server.enabled);

    let config = core
        .effective_ed2k_config(&Ed2kRuntimeConfig::default(), None)
        .await
        .unwrap();
    assert!(config.server_entries.is_empty());
    assert!(config.server_endpoints.is_empty());
}

#[tokio::test]
async fn server_update_reenables_disabled_runtime_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.21".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();
    core.remove_server("203.0.113.21:4661").await.unwrap();

    let updated = core
        .update_server(
            "203.0.113.21:4661",
            ServerUpdate {
                enabled: Some(true),
                ..ServerUpdate::default()
            },
        )
        .await
        .unwrap()
        .expect("server is visible while disabled");

    assert!(updated.enabled);
    let config = core
        .effective_ed2k_config(&Ed2kRuntimeConfig::default(), None)
        .await
        .unwrap();
    assert!(
        config
            .server_entries
            .iter()
            .any(|entry| entry.host == "203.0.113.21" && entry.port == 4661)
    );
}

#[tokio::test]
async fn effective_ed2k_config_honors_reconnect_preference() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.update_preferences(PreferencesUpdate {
        reconnect: Some(false),
        ..PreferencesUpdate::default()
    })
    .await
    .unwrap();

    let config = core
        .effective_ed2k_config(&Ed2kRuntimeConfig::default(), None)
        .await
        .unwrap();

    assert!(!config.reconnect_enabled);
}

#[tokio::test]
async fn effective_ed2k_config_honors_safe_server_connect_preference() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.update_preferences(PreferencesUpdate {
        safe_server_connect: Some(false),
        ..PreferencesUpdate::default()
    })
    .await
    .unwrap();

    let config = core
        .effective_ed2k_config(&Ed2kRuntimeConfig::default(), None)
        .await
        .unwrap();

    assert!(!config.safe_server_connect);
}

#[tokio::test]
async fn udp_server_description_metadata_updates_the_persisted_server() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "192.0.2.44".to_string(),
        port: 4661,
        name: Some("Old Name".to_string()),
        priority: None,
        static_server: None,
        connect: None,
    })
    .await
    .unwrap();

    core.note_ed2k_server_metadata(
        "192.0.2.44:4661",
        Some("New Name".to_string()),
        Some("New Description".to_string()),
    )
    .await;

    let server = core.server("192.0.2.44:4661").await.expect("server");
    assert_eq!(server.name, "New Name");
    assert_eq!(server.description, "New Description");
}

#[tokio::test]
async fn explicit_server_connect_targets_running_server_loop() {
    let transfer_root = unique_runtime_dir("emulebb-core-target-running-server-loop");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.config.server_endpoints = vec![
        "203.0.113.10:4661".to_string(),
        "203.0.113.20:4661".to_string(),
    ];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();
    let target_server_endpoint = Arc::new(RwLock::new(None));
    let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());

    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
        dht,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_reconnect_signal: Arc::clone(&server_reconnect_signal),
        target_server_endpoint: Arc::clone(&target_server_endpoint),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
        download_tasks: Arc::clone(&core.ed2k_download_tasks),
    });

    let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

    assert!(result.is_some());
    assert_eq!(
        target_server_endpoint.read().await.as_deref(),
        Some("203.0.113.20:4661")
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            server_reconnect_signal.notified()
        )
        .await
        .is_ok(),
        "retargeting a running server loop must signal reconnect"
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn explicit_server_connect_to_live_endpoint_is_idempotent() {
    let transfer_root = unique_runtime_dir("emulebb-core-same-server-connect-noop");
    let mut network = test_network_config_with_store(
        &transfer_root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.config.server_endpoints = vec!["203.0.113.20:4661".to_string()];
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &transfer_root,
        Some(network),
    )
    .unwrap();
    let (search_handle, _search_inbox) = new_ed2k_server_search_channel(1);
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some("0.0.0.0:0".parse().unwrap()),
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let dht_task = dht.start();
    let target_server_endpoint = Arc::new(RwLock::new(None));
    let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());
    let server_state = Arc::new(RwLock::new(Ed2kServerState {
        endpoint: Some("203.0.113.20:4661".parse().unwrap()),
        connected: true,
        ..Ed2kServerState::default()
    }));

    *core.ed2k_runtime.lock().await = Some(Ed2kRuntime {
        search_handle,
        server_state,
        dht,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        nat: Arc::new(NatManager::default()),
        shutdown: Arc::clone(&shutdown),
        server_reconnect_signal: Arc::clone(&server_reconnect_signal),
        target_server_endpoint: Arc::clone(&target_server_endpoint),
        kad_firewall_recheck: None,
        tasks: vec![dht_task],
        download_tasks: Arc::clone(&core.ed2k_download_tasks),
    });

    let result = core.connect_ed2k_server("203.0.113.20:4661").await.unwrap();

    assert!(result.is_some());
    assert_eq!(
        target_server_endpoint.read().await.as_deref(),
        Some("203.0.113.20:4661")
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            server_reconnect_signal.notified()
        )
        .await
        .is_err(),
        "same-endpoint connect must not drop a live server session"
    );
    shutdown.store(true, Ordering::SeqCst);
    let _ = core.disconnect_ed2k().await;
}

#[tokio::test]
async fn merge_discovered_servers_adds_new_dedups_existing() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "45.82.80.155".to_string(),
        port: 5687,
        name: None,
        priority: None,
        static_server: Some(true),
        connect: None,
    })
    .await
    .unwrap();

    core.merge_discovered_ed2k_servers(vec![
        (Ipv4Addr::new(45, 82, 80, 155), 5687), // duplicate of existing
        (Ipv4Addr::new(203, 0, 113, 9), 4661),  // new
        (Ipv4Addr::new(203, 0, 113, 9), 4661),  // duplicate within batch
    ])
    .await;

    let servers = core.servers().await;
    let lugd = servers
        .iter()
        .filter(|s| s.address == "45.82.80.155" && s.port == 5687)
        .count();
    assert_eq!(lugd, 1, "existing server is not duplicated");
    let new_server = servers
        .iter()
        .find(|s| s.address == "203.0.113.9" && s.port == 4661)
        .expect("discovered server added");
    assert_eq!(new_server.priority, "low");
    assert!(!new_server.static_server);
}

#[tokio::test]
async fn merge_discovered_servers_respects_add_servers_from_server_preference() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    // eMule GetAddServersFromServer default is on; turning it off must stop
    // OP_SERVERLIST auto-add.
    core.update_preferences(PreferencesUpdate {
        add_servers_from_server: Some(false),
        ..PreferencesUpdate::default()
    })
    .await
    .unwrap();
    core.merge_discovered_ed2k_servers(vec![(Ipv4Addr::new(203, 0, 113, 9), 4661)])
        .await;
    assert!(
        !core
            .servers()
            .await
            .iter()
            .any(|s| s.address == "203.0.113.9" && s.port == 4661),
        "auto-add disabled: a discovered server must not be added"
    );
}

#[tokio::test]
async fn connect_failed_drops_non_static_dead_server_at_threshold() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.5".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.5:4661";

    // Default dead_server_retries = 1: first failure drops the server.
    core.note_ed2k_server_connect_failed(endpoint, 1).await;
    let server = core
        .server(endpoint)
        .await
        .expect("dead server remains visible");
    assert!(
        !server.enabled,
        "non-static dead server is disabled at the threshold"
    );
}

#[tokio::test]
async fn explicit_server_connect_ignores_disabled_servers() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.8".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();
    core.remove_server("203.0.113.8:4661").await.unwrap();

    let result = core.connect_ed2k_server("203.0.113.8:4661").await.unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn connect_failed_never_drops_static_server() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.6".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(true),
        connect: None,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.6:4661";

    // Even far past the threshold, a static server is kept (eMule keeps
    // static servers); the fail-count is still tracked.
    for _ in 0..5 {
        core.note_ed2k_server_connect_failed(endpoint, 1).await;
    }
    let server = core.server(endpoint).await.expect("static server kept");
    assert!(server.failed_count >= 1);
}

#[tokio::test]
async fn connect_succeeded_clears_fail_count() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    core.add_server(ServerCreate {
        address: "203.0.113.7".to_string(),
        port: 4661,
        name: None,
        priority: None,
        static_server: Some(false),
        connect: None,
    })
    .await
    .unwrap();
    let endpoint = "203.0.113.7:4661";

    // With a higher threshold, accumulate failures, then a success clears them.
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    assert_eq!(core.server(endpoint).await.unwrap().failed_count, 2);
    core.note_ed2k_server_connect_succeeded(endpoint).await;
    assert_eq!(core.server(endpoint).await.unwrap().failed_count, 0);
    // The cleared count means it now takes the full threshold again to drop.
    core.note_ed2k_server_connect_failed(endpoint, 3).await;
    assert!(core.server(endpoint).await.is_some());
}

#[test]
fn exact_ed2k_hash_query_token_extracts_hash_only_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        exact_ed2k_hash_query_token(&format!("ed2k::{exact_hash}")),
        Some(exact_hash.clone())
    );
    assert_eq!(
        exact_ed2k_hash_query_token(&exact_hash.to_ascii_uppercase()),
        Some(exact_hash)
    );
    assert_eq!(exact_ed2k_hash_query_token("ed2k::torino train"), None);
}

#[test]
fn significant_words_ignore_short_tokens() {
    assert_eq!(
        significant_keyword_words("A torino x train"),
        vec!["torino".to_string(), "train".to_string()]
    );
}

#[test]
fn significant_words_keep_in_word_symbols_matching_getwords_separators() {
    // `INV_KAD_KEYWORD_CHARS` does not include `&`, `+`, `'` or `#`, so the
    // oracle keeps them inside the word instead of over-splitting.
    assert_eq!(
        significant_keyword_words("AT&T Wireless"),
        vec!["at&t".to_string(), "wireless".to_string()]
    );
    assert_eq!(
        significant_keyword_words("C++ Tutorial"),
        vec!["c++".to_string(), "tutorial".to_string()]
    );
    assert_eq!(
        significant_keyword_words("rock'n'roll live"),
        vec!["rock'n'roll".to_string(), "live".to_string()]
    );
}

#[test]
fn significant_words_drop_trailing_three_char_extension() {
    // GetWords pops a trailing 3-char/3-byte token (SearchManager.cpp:284-286)
    // when more than one word survived; the drop applies to publish keywords
    // and to search queries alike because both share this tokenizer.
    assert_eq!(
        significant_keyword_words("ubuntu.iso"),
        vec!["ubuntu".to_string()]
    );
    assert_eq!(
        significant_keyword_words("AT&T.avi"),
        vec!["at&t".to_string()]
    );
    assert_eq!(
        significant_keyword_words("C++ Tutorial.pdf"),
        vec!["c++".to_string(), "tutorial".to_string()]
    );
    // A search query tokenizes identically: the trailing extension is dropped.
    assert_eq!(
        significant_keyword_words("ubuntu iso"),
        vec!["ubuntu".to_string()]
    );
    // The extension drop only fires when more than one word survives, so a
    // lone 3-char word is kept ("a.b.mp3" leaves only "mp3").
    assert_eq!(
        significant_keyword_words("a.b.mp3"),
        vec!["mp3".to_string()]
    );
    // A trailing token longer than 3 chars is not an extension: "#1" is under
    // the 3-byte minimum and drops out, "flac" is kept.
    assert_eq!(
        significant_keyword_words("R&B #1.flac"),
        vec!["r&b".to_string(), "flac".to_string()]
    );
}

#[test]
fn kad_keyword_lowercase_matches_oracle_frozen_table() {
    // ASCII A-Z lower-cases exactly as before (the common case).
    assert_eq!(
        kad_keyword_lowercase("Ubuntu ISO"),
        "ubuntu iso".to_string()
    );
    // Latin-1 / Greek / Cyrillic uppercase letters that the oracle's
    // `LANG_ENGLISH` map lowers are still lowered (À->à, Β->β, А->а).
    assert_eq!(kad_keyword_lowercase("À"), "à".to_string());
    assert_eq!(kad_keyword_lowercase("Β"), "β".to_string());
    assert_eq!(kad_keyword_lowercase("А"), "а".to_string());
    // Code points the oracle's frozen table leaves UNCHANGED but Rust's
    // `str::to_lowercase()` would alter: U+0130 (İ, which Rust expands to two
    // chars), U+1E9E (ẞ, Rust -> ß), the U+212A Kelvin sign (Rust -> k) and
    // the U+00B5 micro sign (Rust -> μ). Keeping them verbatim is what makes
    // the md4 keyword hash match eMule for these words.
    assert_eq!(kad_keyword_lowercase("\u{0130}"), "\u{0130}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{1E9E}"), "\u{1E9E}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{212A}"), "\u{212A}".to_string());
    assert_eq!(kad_keyword_lowercase("\u{00B5}"), "\u{00B5}".to_string());
    // Already-lower and astral (identity-mapped surrogate) code points pass
    // through untouched.
    assert_eq!(kad_keyword_lowercase("café"), "café".to_string());
    assert_eq!(kad_keyword_lowercase("\u{1F600}"), "\u{1F600}".to_string());
}

#[test]
fn significant_words_lowercase_uses_oracle_table_for_non_ascii() {
    // The tokenizer lower-cases through the oracle table: "Café.İşi" keeps
    // U+0130 verbatim (Rust's full lower-casing would expand it) so the
    // produced keyword — and thus its md4 target — matches eMule's.
    assert_eq!(
        significant_keyword_words("Café İyi"),
        vec!["café".to_string(), "\u{0130}yi".to_string()]
    );
}

#[test]
fn significant_words_dedup_keeps_last_occurrence() {
    // GetWords de-duplicates with `remove` + `push_back` (SearchManager.cpp:
    // 277-278), moving a repeated word to the END of the list. "ubuntu"
    // repeats, so it lands after "python" rather than staying at the front.
    assert_eq!(
        significant_keyword_words_unique("Ubuntu Python ubuntu programming Apache Camel"),
        vec![
            "python".to_string(),
            "ubuntu".to_string(),
            "programming".to_string(),
            "apache".to_string(),
            "camel".to_string(),
        ]
    );
}

#[test]
fn significant_words_repeated_first_token_shifts_primary_keyword() {
    // When the first token repeats, the oracle's remove+push_back moves it to
    // the end, so the primary keyword (GetWords `front()`, hashed by
    // `keyword_target`) becomes the next distinct word. "love song love"
    // dedups to ["song", "love"], not ["love", "song"].
    assert_eq!(
        significant_keyword_words("love song love"),
        vec!["song".to_string(), "love".to_string()]
    );
    // The Kad keyword target therefore hashes "song", not "love".
    assert_eq!(keyword_target("love song love"), keyword_target("song"));
    assert_ne!(keyword_target("love song love"), keyword_target("love"));
}
