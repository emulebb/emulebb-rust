use super::*;

#[test]
fn keyword_publish_entries_batch_matching_files_up_to_stock_limit() {
    let mut shared_files = (0..160)
        .map(|index| {
            KadKeywordPublishCandidate::new(
                Ed2kHash::from_bytes([index as u8; 16]).to_string(),
                format!("Ubuntu Python Sample {index}.iso"),
                1000 + index,
                None,
            )
            .expect("test hash is valid")
        })
        .collect::<Vec<_>>();
    shared_files.push(
        KadKeywordPublishCandidate::new(
            Ed2kHash::from_bytes([0xFE; 16]).to_string(),
            "Apache Camel Sample.iso".to_string(),
            1,
            None,
        )
        .expect("test hash is valid"),
    );

    let entries = kad_keyword_publish_entries_for_keyword(
        &shared_files,
        "ubuntu",
        KAD_KEYWORD_PUBLISH_FILE_LIMIT,
        0,
    );

    assert_eq!(entries.len(), KAD_KEYWORD_PUBLISH_FILE_LIMIT);
    assert_eq!(entries[0].1.file_hash, Ed2kHash::from_bytes([0_u8; 16]));
    assert_eq!(entries[149].1.file_hash, Ed2kHash::from_bytes([149_u8; 16]));
    assert!(
        entries
            .iter()
            .all(|(_, entry)| entry.tags.iter().any(|tag| tag == &Tag::sources(1)))
    );
}

#[test]
fn keyword_publish_entries_start_at_triggering_file_and_wrap() {
    let shared_files = (0..160)
        .map(|index| {
            KadKeywordPublishCandidate::new(
                Ed2kHash::from_bytes([index as u8; 16]).to_string(),
                format!("Ubuntu Python Sample {index}.iso"),
                1000 + index,
                None,
            )
            .expect("test hash is valid")
        })
        .collect::<Vec<_>>();

    let entries = kad_keyword_publish_entries_for_keyword(
        &shared_files,
        "ubuntu",
        KAD_KEYWORD_PUBLISH_FILE_LIMIT,
        155,
    );

    assert_eq!(entries.len(), KAD_KEYWORD_PUBLISH_FILE_LIMIT);
    assert_eq!(entries[0].1.file_hash, Ed2kHash::from_bytes([155_u8; 16]));
    assert_eq!(entries[4].1.file_hash, Ed2kHash::from_bytes([159_u8; 16]));
    assert_eq!(entries[5].1.file_hash, Ed2kHash::from_bytes([0_u8; 16]));
    assert_eq!(entries[149].1.file_hash, Ed2kHash::from_bytes([144_u8; 16]));
}

#[test]
fn keyword_publish_source_count_is_self_inclusive() {
    // Oracle `CKnownFile::m_nCompleteSourcesCount` counts ourselves as one
    // complete source and adds any other known complete sources on top
    // (KnownFile.cpp:126,313). A file with no other known complete sources
    // publishes SOURCES = 1; N others publish SOURCES = N + 1.
    assert_eq!(keyword_publish_complete_source_count(0), 1);
    assert_eq!(keyword_publish_complete_source_count(4), 5);
}

#[test]
fn keyword_publish_entry_publishes_self_inclusive_source_count() {
    // rust tracks no other complete sources for shared files, so the built
    // keyword entry carries the self-only TAG_SOURCES value of 1 rather than
    // a hardcoded constant divorced from the oracle semantics.
    let shared_files = vec![
        KadKeywordPublishCandidate::new(
            Ed2kHash::from_bytes([7_u8; 16]).to_string(),
            "Ubuntu Sample.iso".to_string(),
            4096,
            None,
        )
        .expect("test hash is valid"),
    ];

    let entries = kad_keyword_publish_entries_for_keyword(
        &shared_files,
        "ubuntu",
        KAD_KEYWORD_PUBLISH_FILE_LIMIT,
        0,
    );

    assert_eq!(entries.len(), 1);
    assert!(entries[0].1.tags.iter().any(|tag| tag == &Tag::sources(1)));
}

#[test]
fn kad_shared_publish_active_counts_follow_mfc_store_caps() {
    let mut counts = KadSharedPublishActiveCounts::default();
    assert_eq!(
        kad_shared_publish_kind_cap(KadSharedPublishKind::Keyword),
        KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP
    );
    assert_eq!(
        kad_shared_publish_kind_cap(KadSharedPublishKind::Source),
        KAD_SOURCE_PUBLISH_IN_FLIGHT_CAP
    );
    assert_eq!(
        kad_shared_publish_kind_cap(KadSharedPublishKind::Notes),
        KAD_NOTES_PUBLISH_IN_FLIGHT_CAP
    );

    for _ in 0..KAD_KEYWORD_PUBLISH_IN_FLIGHT_CAP {
        assert!(counts.can_start(KadSharedPublishKind::Keyword));
        counts.started(KadSharedPublishKind::Keyword);
    }
    assert!(!counts.can_start(KadSharedPublishKind::Keyword));
    counts.finished(KadSharedPublishKind::Keyword);
    assert!(counts.can_start(KadSharedPublishKind::Keyword));

    counts.started(KadSharedPublishKind::Notes);
    assert!(!counts.can_start(KadSharedPublishKind::Notes));
    counts.finished(KadSharedPublishKind::Notes);
    assert!(counts.can_start(KadSharedPublishKind::Notes));
}

#[test]
fn kad_shared_publish_budget_reserves_search_capacity() {
    assert_eq!(kad_shared_file_publish_in_flight_budget_for(1), 1);
    assert_eq!(kad_shared_file_publish_in_flight_budget_for(2), 1);
    assert_eq!(kad_shared_file_publish_in_flight_budget_for(5), 4);
    assert_eq!(
        kad_shared_file_publish_in_flight_budget_for(KAD_SHARED_FILE_PUBLISH_DHT_SEARCH_CAP),
        KAD_SHARED_FILE_PUBLISH_KIND_CAP_TOTAL
    );
}

#[test]
fn kad_rpc_class_budgets_give_publish_traversals_room_to_converge() {
    let budgets = kad_rpc_class_budgets();
    assert_eq!(
        budgets.publish_max_outbound_pps,
        KAD_PUBLISH_MAX_OUTBOUND_PPS
    );
    assert!(
        budgets.publish_max_outbound_pps > RpcClassBudgetConfig::default().publish_max_outbound_pps
    );
}

#[test]
fn kad_outbound_publish_schedule_advances_when_store_search_starts() {
    let store = MetadataStore::in_memory().unwrap();
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    let started_at = Instant::now();
    let published_at_ms = 12_345;
    let keyword = "ubuntu";
    let keyword_hashes = vec![
        Ed2kHash::from_bytes([0x11; 16]).to_string(),
        Ed2kHash::from_bytes([0x22; 16]).to_string(),
    ];
    let source_hash = Ed2kHash::from_bytes([0x33; 16]).to_string();
    let notes_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    mark_kad_keyword_publish_started(
        &store,
        &mut schedule,
        &keyword_hashes,
        keyword,
        started_at,
        published_at_ms,
    );
    mark_kad_file_publish_started(
        &store,
        &mut schedule,
        &source_hash,
        MetadataKadOutboundPublishKind::Source,
        started_at,
        published_at_ms,
        None,
    );
    mark_kad_file_publish_started(
        &store,
        &mut schedule,
        &notes_hash,
        MetadataKadOutboundPublishKind::Notes,
        started_at,
        published_at_ms,
        None,
    );

    for file_hash in &keyword_hashes {
        assert!(!schedule.keyword_due(file_hash, keyword, started_at));
    }
    assert!(!schedule.source_due(&source_hash, started_at, None));
    assert!(!schedule.notes_due(&notes_hash, started_at));

    let persisted = store.load_kad_outbound_publish_schedule().unwrap();
    assert_eq!(persisted.publishes.len(), 4);
    assert!(persisted.publishes.iter().any(|publish| {
        publish.file_hash == keyword_hashes[0]
            && publish.publish_kind == MetadataKadOutboundPublishKind::Keyword
            && publish.keyword == keyword
            && publish.published_at_ms == published_at_ms
    }));
    assert!(persisted.publishes.iter().any(|publish| {
        publish.file_hash == source_hash
            && publish.publish_kind == MetadataKadOutboundPublishKind::Source
            && publish.keyword.is_empty()
            && publish.published_at_ms == published_at_ms
    }));
    assert!(persisted.publishes.iter().any(|publish| {
        publish.file_hash == notes_hash
            && publish.publish_kind == MetadataKadOutboundPublishKind::Notes
            && publish.keyword.is_empty()
            && publish.published_at_ms == published_at_ms
    }));
}

#[test]
fn busy_rollback_makes_publish_due_again_while_timeout_keeps_it_advanced() {
    // Publish-G2: a `Busy` outcome (store search could not be created, no
    // packet sent -> oracle PrepareLookup==NULL) rolls the admission-advanced
    // clock back to due so the file retries next tick; a `TimedOut`/`Failed`
    // outcome does NOT roll back (the search WAS created and sent), so that
    // file keeps waiting its interval.
    let store = MetadataStore::in_memory().unwrap();
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    let started_at = Instant::now();
    let published_at_ms = 42;
    let keyword = "ubuntu";
    let busy_keyword_hash = Ed2kHash::from_bytes([0x11; 16]).to_string();
    let busy_source_hash = Ed2kHash::from_bytes([0x22; 16]).to_string();
    let busy_notes_hash = Ed2kHash::from_bytes([0x33; 16]).to_string();
    let timeout_source_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    // Admission advances every clock (keyword/source/notes).
    mark_kad_keyword_publish_started(
        &store,
        &mut schedule,
        std::slice::from_ref(&busy_keyword_hash),
        keyword,
        started_at,
        published_at_ms,
    );
    for (hash, kind) in [
        (&busy_source_hash, MetadataKadOutboundPublishKind::Source),
        (&timeout_source_hash, MetadataKadOutboundPublishKind::Source),
        (&busy_notes_hash, MetadataKadOutboundPublishKind::Notes),
    ] {
        mark_kad_file_publish_started(
            &store,
            &mut schedule,
            hash,
            kind,
            started_at,
            published_at_ms,
            None,
        );
    }
    assert!(!schedule.keyword_due(&busy_keyword_hash, keyword, started_at));
    assert!(!schedule.source_due(&busy_source_hash, started_at, None));
    assert!(!schedule.source_due(&timeout_source_hash, started_at, None));
    assert!(!schedule.notes_due(&busy_notes_hash, started_at));

    // Busy rollback on the keyword/source/notes stores that never sent a packet.
    rollback_kad_publish_admission_on_busy(
        &store,
        &mut schedule,
        KadSharedPublishKind::Keyword,
        std::slice::from_ref(&busy_keyword_hash),
        Some(keyword),
    );
    rollback_kad_publish_admission_on_busy(
        &store,
        &mut schedule,
        KadSharedPublishKind::Source,
        std::slice::from_ref(&busy_source_hash),
        None,
    );
    rollback_kad_publish_admission_on_busy(
        &store,
        &mut schedule,
        KadSharedPublishKind::Notes,
        std::slice::from_ref(&busy_notes_hash),
        None,
    );

    // Busy targets are due again immediately (re-selectable next tick).
    assert!(schedule.keyword_due(&busy_keyword_hash, keyword, started_at));
    assert!(schedule.source_due(&busy_source_hash, started_at, None));
    assert!(schedule.notes_due(&busy_notes_hash, started_at));
    // The timed-out source (created + sent, no rollback) keeps its clock.
    assert!(!schedule.source_due(&timeout_source_hash, started_at, None));

    // Persistence mirrors the in-memory rollback: busy rows are cleared, the
    // timed-out source row survives.
    let persisted = store.load_kad_outbound_publish_schedule().unwrap();
    assert_eq!(persisted.publishes.len(), 1);
    assert_eq!(persisted.publishes[0].file_hash, timeout_source_hash);
    assert_eq!(
        persisted.publishes[0].publish_kind,
        MetadataKadOutboundPublishKind::Source
    );
}
