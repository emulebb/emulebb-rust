use super::*;
use crate::MetadataStore;

fn fingerprint(size_bytes: u64, sequence: u64) -> NativeFileFingerprint {
    NativeFileFingerprint {
        identity: crate::NativeFileIdentity::Unix {
            device_id: 7,
            inode_number: 11 + sequence,
        },
        size_bytes,
        modified: crate::NativeFileTimestamp::new(
            1_700_000_000 + i64::try_from(sequence).unwrap(),
            123_456_789,
        )
        .unwrap(),
        changed: Some(
            crate::NativeFileTimestamp::new(
                1_700_000_001 + i64::try_from(sequence).unwrap(),
                234_567_890,
            )
            .unwrap(),
        ),
    }
}

#[test]
fn transfer_manifest_roundtrips_sql_tables() {
    let store = MetadataStore::in_memory().unwrap();
    store
        .upsert_category(&crate::MetadataCategory {
            id: 2,
            name: "Samples".to_string(),
            path: None,
            comment: String::new(),
            sort_order: 1,
            color: None,
        })
        .unwrap();
    let mut manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Sample.Transfer.bin".to_string(),
        file_size: 1024,
        piece_size: 1024,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: true,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: true,
        aich_root: Some("1111111111111111111111111111111111111111".to_string()),
        aich_hashset: vec!["2222222222222222222222222222222222222222".to_string()],
        verified_ranges: vec![MetadataTransferRange {
            start: 0,
            end: 1024,
        }],
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            bytes_written: 1024,
            block_bitmap: Some("ab".to_string()),
            ich_corrupted: true,
        }],
        sources: vec![MetadataTransferSource {
            ip: "192.0.2.10".to_string(),
            tcp_port: 4662,
            user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
            connect_options: Some(0x07),
            file_comment: "useful source".to_string(),
            file_rating: 4,
        }],
        upload_priority: "high".to_string(),
        auto_upload_priority: true,
        comment: "synthetic comment".to_string(),
        rating: 4,
        category_id: 2,
        control_state: Some("paused".to_string()),
        transfer_row_removed: false,
        delivered_path: Some("/incoming/Sample.Transfer.bin".into()),
        source_path: Some("/library/Sample.Transfer.bin".into()),
        source_fingerprint: Some(fingerprint(1024, 0)),
    };

    store.upsert_transfer_manifest(&manifest).unwrap();
    let restored = store
        .transfer_manifest_by_hash("00112233445566778899aabbccddeeff")
        .unwrap()
        .unwrap();

    assert_eq!(restored, manifest);
    assert_eq!(
        store.completed_transfer_catalog_entries().unwrap(),
        vec![MetadataTransferCatalogEntry {
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            file_size: manifest.file_size,
            aich_root: manifest.aich_root.clone(),
            upload_priority: manifest.upload_priority.clone(),
            auto_upload_priority: manifest.auto_upload_priority,
            comment: manifest.comment.clone(),
            rating: manifest.rating,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
            media_path: manifest.source_path.clone(),
            media: MetadataTransferMediaMetadata::default(),
        }]
    );
    assert_eq!(
        store.share_in_place_reload_entries().unwrap(),
        vec![MetadataShareInPlaceReloadEntry {
            file_hash: manifest.file_hash.clone(),
            file_size: manifest.file_size,
            source_path: manifest.source_path.clone().unwrap(),
            source_fingerprint: manifest.source_fingerprint.clone(),
        }]
    );
    assert_eq!(
        store.transfer_counts().unwrap(),
        MetadataTransferCounts {
            active: 0,
            completed: 1,
            total: 1,
        }
    );
    assert_eq!(
        store.completed_transfer_publish_entries().unwrap(),
        vec![MetadataTransferPublishEntry {
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            file_size: manifest.file_size,
            aich_root: manifest.aich_root.clone(),
            upload_priority: manifest.upload_priority.clone(),
            auto_upload_priority: manifest.auto_upload_priority,
            session_uploaded_bytes: 0,
            session_request_count: 0,
            session_accept_count: 0,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
            comment: manifest.comment.clone(),
            rating: manifest.rating,
        }]
    );
    assert_eq!(
        store.completed_transfer_share_entries().unwrap(),
        vec![MetadataTransferShareEntry {
            file_hash: manifest.file_hash.clone(),
            display_name: manifest.display_name.clone(),
            file_size: manifest.file_size,
            part_count: 1,
            source_path: manifest.source_path.clone(),
            aich_root: manifest.aich_root.clone(),
            upload_priority: manifest.upload_priority.clone(),
            auto_upload_priority: manifest.auto_upload_priority,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            comment: manifest.comment.clone(),
            rating: manifest.rating,
        }]
    );
    assert_eq!(
        store
            .completed_transfer_share_entry(&manifest.file_hash.to_uppercase())
            .unwrap(),
        store.completed_transfer_share_entries().unwrap().pop()
    );
    assert_eq!(
        store
            .completed_transfer_share_entry("ffeeddccbbaa99887766554433221100")
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .completed_transfer_share_entries_after(None, 1)
            .unwrap(),
        (store.completed_transfer_share_entries().unwrap(), 1, false)
    );
    assert_eq!(
        store
            .completed_transfer_share_entries_after(Some(&manifest.file_hash), 1)
            .unwrap(),
        (Vec::new(), 1, false)
    );
    let media = MetadataTransferMediaMetadata {
        artist: "Artist".to_string(),
        album: "Album".to_string(),
        title: "Title".to_string(),
        length_seconds: 123,
        bitrate_kbps: 320,
        codec: "MP3".to_string(),
        extractor_version: 1,
    };
    assert!(
        store
            .update_transfer_media_metadata(&manifest.file_hash, &media)
            .unwrap()
    );
    assert_eq!(
        store.transfer_media_metadata(&manifest.file_hash).unwrap(),
        Some(media.clone())
    );
    assert_eq!(
        store
            .completed_transfer_catalog_entries()
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .media,
        media
    );
    assert_eq!(
        store.completed_transfer_share_entries_page(0, 1).unwrap(),
        (
            vec![MetadataTransferShareEntry {
                file_hash: manifest.file_hash.clone(),
                display_name: manifest.display_name.clone(),
                file_size: manifest.file_size,
                part_count: 1,
                source_path: manifest.source_path.clone(),
                aich_root: manifest.aich_root.clone(),
                upload_priority: manifest.upload_priority.clone(),
                auto_upload_priority: manifest.auto_upload_priority,
                all_time_uploaded_bytes: 0,
                all_time_upload_requests: 0,
                all_time_upload_accepts: 0,
                comment: manifest.comment.clone(),
                rating: manifest.rating,
            }],
            1
        )
    );
    let old_source_path = manifest.source_path.clone().unwrap();
    let new_source_path = "/library/renamed/Renamed.Sample.bin";
    let renamed_fingerprint = fingerprint(manifest.file_size, 123);
    assert!(
        store
            .relocate_shared_file_source(
                &manifest.file_hash,
                &old_source_path,
                Path::new(new_source_path),
                manifest.file_size,
                Some(&renamed_fingerprint),
                "Renamed.Sample.bin",
                "document",
            )
            .unwrap()
    );
    manifest.source_path = Some(new_source_path.into());
    manifest.source_fingerprint = Some(renamed_fingerprint);
    manifest.display_name = "Renamed.Sample.bin".to_string();
    assert_eq!(
        store.share_in_place_reload_entries().unwrap(),
        vec![MetadataShareInPlaceReloadEntry {
            file_hash: manifest.file_hash.clone(),
            file_size: manifest.file_size,
            source_path: new_source_path.into(),
            source_fingerprint: manifest.source_fingerprint.clone(),
        }]
    );
    let renamed_share = store
        .completed_transfer_share_entry(&manifest.file_hash)
        .unwrap()
        .unwrap();
    assert_eq!(
        renamed_share.source_path.as_deref(),
        Some(Path::new(new_source_path))
    );
    assert_eq!(renamed_share.display_name, manifest.display_name);
    assert!(
        !store
            .relocate_shared_file_source(
                &manifest.file_hash,
                &old_source_path,
                Path::new("/library/unused.bin"),
                manifest.file_size,
                manifest.source_fingerprint.as_ref(),
                "unused.bin",
                "document",
            )
            .unwrap(),
        "the old source row must be gone after relocation",
    );
    store
        .mark_unshared_file(&manifest.file_hash, "manual")
        .unwrap();
    assert_eq!(store.completed_transfer_publish_entries().unwrap(), vec![]);
    assert_eq!(store.completed_transfer_share_entries().unwrap(), vec![]);
    assert_eq!(
        store
            .completed_transfer_share_entry(&manifest.file_hash)
            .unwrap(),
        None
    );
    store.unmark_unshared_file(&manifest.file_hash).unwrap();
    assert_eq!(store.transfer_manifests().unwrap(), vec![manifest.clone()]);

    manifest.completed = false;
    manifest.final_rehash_pending = true;
    manifest.control_state = None;
    manifest.delivered_path = None;
    manifest.source_path = None;
    manifest.source_fingerprint = None;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(
        store
            .transfer_manifest_by_hash(&manifest.file_hash)
            .unwrap(),
        Some(manifest.clone())
    );
    assert_eq!(
        store.transfer_counts().unwrap(),
        MetadataTransferCounts {
            active: 1,
            completed: 0,
            total: 1,
        }
    );
    let catalog = store.completed_transfer_catalog_entries().unwrap();
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog[0].file_hash, manifest.file_hash);
    assert_eq!(
        catalog[0].media_path.as_deref(),
        Some(Path::new("/library/renamed/Renamed.Sample.bin"))
    );
}

#[test]
fn upload_demand_counters_persist_on_known_files() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Demand.Sample.bin".to_string(),
        file_size: 1024,
        piece_size: 1024,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: vec![MetadataTransferRange {
            start: 0,
            end: 1024,
        }],
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            bytes_written: 1024,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivered_path: None,
        source_path: None,
        source_fingerprint: None,
    };

    store.upsert_transfer_manifest(&manifest).unwrap();
    assert!(
        store
            .add_file_upload_request(&manifest.file_hash, 1_700_000_001_000)
            .unwrap()
    );
    assert!(
        store
            .add_file_upload_request(&manifest.file_hash, 1_700_000_000_000)
            .unwrap()
    );
    assert!(store.add_file_upload_accept(&manifest.file_hash).unwrap());

    let publish = store.completed_transfer_publish_entries().unwrap();
    assert_eq!(publish.len(), 1);
    assert_eq!(publish[0].all_time_upload_requests, 2);
    assert_eq!(publish[0].all_time_upload_accepts, 1);
    assert_eq!(publish[0].last_upload_request_ms, 1_700_000_001_000);

    let catalog = store.completed_transfer_catalog_entries().unwrap();
    assert_eq!(catalog[0].all_time_upload_requests, 2);
    assert_eq!(catalog[0].all_time_upload_accepts, 1);
    assert_eq!(catalog[0].last_upload_request_ms, 1_700_000_001_000);
}

#[test]
fn share_in_place_reload_entries_remember_duplicate_source_paths() {
    let store = MetadataStore::in_memory().unwrap();
    let mut manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Duplicate.Payload.bin".to_string(),
        file_size: 1024,
        piece_size: 1024,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: true,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: true,
        aich_root: Some("1111111111111111111111111111111111111111".to_string()),
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            bytes_written: 1024,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: true,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivered_path: None,
        source_path: Some("/library/Alpha.bin".into()),
        source_fingerprint: Some(fingerprint(1024, 0)),
    };

    store.upsert_transfer_manifest(&manifest).unwrap();
    manifest.source_path = Some("/library/Beta.bin".into());
    manifest.source_fingerprint = Some(fingerprint(1024, 1));
    store.upsert_transfer_manifest(&manifest).unwrap();

    assert_eq!(
        store.share_in_place_reload_entries().unwrap(),
        vec![
            MetadataShareInPlaceReloadEntry {
                file_hash: manifest.file_hash.clone(),
                file_size: manifest.file_size,
                source_path: "/library/Alpha.bin".into(),
                source_fingerprint: Some(fingerprint(1024, 0)),
            },
            MetadataShareInPlaceReloadEntry {
                file_hash: manifest.file_hash.clone(),
                file_size: manifest.file_size,
                source_path: "/library/Beta.bin".into(),
                source_fingerprint: Some(fingerprint(1024, 1)),
            },
        ]
    );
    assert_eq!(store.completed_transfer_publish_entries().unwrap().len(), 1);
    assert_eq!(store.completed_transfer_share_entries().unwrap().len(), 1);
}

#[test]
fn shared_source_failures_roundtrip_update_and_clear() {
    let store = MetadataStore::in_memory().unwrap();
    let initial_fingerprint = fingerprint(1024, 0);

    store
        .upsert_shared_source_failure(
            Path::new("/library/Broken.Source.bin"),
            1024,
            Some(&initial_fingerprint),
            "ingest failed",
        )
        .unwrap();
    let initial = store.shared_source_failures().unwrap();
    assert_eq!(initial.len(), 1);
    assert_eq!(
        initial[0].source_path,
        Path::new("/library/Broken.Source.bin")
    );
    assert_eq!(initial[0].file_size, 1024);
    assert_eq!(
        initial[0].source_fingerprint,
        Some(initial_fingerprint.clone())
    );
    assert_eq!(initial[0].reason, "ingest failed");

    let updated_fingerprint = fingerprint(2048, 1);
    store
        .upsert_shared_source_failure(
            Path::new("/library/Broken.Source.bin"),
            2048,
            Some(&updated_fingerprint),
            "changed identity failed",
        )
        .unwrap();
    let updated = store.shared_source_failures().unwrap();
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].file_size, 2048);
    assert_eq!(updated[0].source_fingerprint, Some(updated_fingerprint));
    assert_eq!(updated[0].reason, "changed identity failed");
    assert_eq!(updated[0].created_at_ms, initial[0].created_at_ms);
    assert!(updated[0].updated_at_ms >= initial[0].updated_at_ms);

    assert!(
        store
            .clear_shared_source_failure(Path::new("/library/Broken.Source.bin"))
            .unwrap()
    );
    assert!(store.shared_source_failures().unwrap().is_empty());
    assert!(
        !store
            .clear_shared_source_failure(Path::new("/library/Broken.Source.bin"))
            .unwrap()
    );
}

#[test]
fn transfer_manifest_clears_matching_shared_source_failure() {
    let store = MetadataStore::in_memory().unwrap();
    let recovered_fingerprint = fingerprint(1024, 0);
    store
        .upsert_shared_source_failure(
            Path::new("/library/Recovered.Source.bin"),
            1024,
            Some(&recovered_fingerprint),
            "ingest failed",
        )
        .unwrap();
    let manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Recovered.Source.bin".to_string(),
        file_size: 1024,
        piece_size: 1024,
        completed: true,
        final_rehash_pending: false,
        md4_hashset_acquired: true,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: true,
        aich_root: Some("1111111111111111111111111111111111111111".to_string()),
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Verified".to_string(),
            bytes_written: 1024,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: true,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivered_path: None,
        source_path: Some("/library/Recovered.Source.bin".into()),
        source_fingerprint: Some(recovered_fingerprint),
    };

    store.upsert_transfer_manifest(&manifest).unwrap();

    assert!(store.shared_source_failures().unwrap().is_empty());
    assert_eq!(store.share_in_place_reload_entries().unwrap().len(), 1);
}

#[test]
fn imported_known_file_identity_matches_roundtrip_pathless_stock_rows() {
    let store = MetadataStore::in_memory().unwrap();
    let entry = MetadataImportedKnownFileEntry {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Known.Payload.bin".to_string(),
        file_size: 1024,
        modified_s: 1_700_000_000,
        md4_hashset: vec!["11111111111111111111111111111111".to_string()],
        aich_root: Some("2222222222222222222222222222222222222222".to_string()),
        aich_hashset: vec!["3333333333333333333333333333333333333333".to_string()],
        upload_priority: "high".to_string(),
        auto_upload_priority: false,
        all_time_uploaded_bytes: 1234,
        all_time_upload_requests: 9,
        all_time_upload_accepts: 4,
        last_upload_request_ms: 1_700_000_001_000,
    };

    store.upsert_imported_known_file(&entry).unwrap();

    assert_eq!(
        store
            .imported_known_file_identity_matches("Known.Payload.bin", 1024, 1_700_000_000)
            .unwrap(),
        vec![entry]
    );
    assert!(
        store
            .imported_known_file_identity_matches("known.payload.bin", 1024, 1_700_000_000)
            .unwrap()
            .is_empty(),
        "stock FindKnownFile uses exact file-name equality"
    );
}

#[test]
fn imported_known_file_identity_matches_returns_ambiguous_rows() {
    let store = MetadataStore::in_memory().unwrap();
    for hash in [
        "00112233445566778899aabbccddeeff",
        "ffeeddccbbaa99887766554433221100",
    ] {
        store
            .upsert_imported_known_file(&MetadataImportedKnownFileEntry {
                file_hash: hash.to_string(),
                display_name: "Ambiguous.Payload.bin".to_string(),
                file_size: 1024,
                modified_s: 1_700_000_000,
                md4_hashset: Vec::new(),
                aich_root: None,
                aich_hashset: Vec::new(),
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                all_time_uploaded_bytes: 0,
                all_time_upload_requests: 0,
                all_time_upload_accepts: 0,
                last_upload_request_ms: 0,
            })
            .unwrap();
    }

    let matches = store
        .imported_known_file_identity_matches("Ambiguous.Payload.bin", 1024, 1_700_000_000)
        .unwrap();

    assert_eq!(matches.len(), 2);
}

#[test]
fn delete_transfer_manifest_removes_transfer_rows() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "Sample.Transfer.bin".to_string(),
        file_size: 1,
        piece_size: 1,
        completed: false,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            bytes_written: 0,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivered_path: None,
        source_path: None,
        source_fingerprint: None,
    };
    store.upsert_transfer_manifest(&manifest).unwrap();

    assert!(
        store
            .delete_transfer_manifest("00112233445566778899aabbccddeeff")
            .unwrap()
    );
    assert!(
        store
            .transfer_manifest_by_hash("00112233445566778899aabbccddeeff")
            .unwrap()
            .is_none()
    );
}

#[test]
fn delete_transfer_manifest_clears_soft_known_file_references() {
    // A search result links to the known file by hash. Deleting the transfer
    // (and its known_files row) must not fail the foreign key check; the soft
    // reference is set to NULL so the search result row survives.
    let store = MetadataStore::in_memory().unwrap();
    let hash = "00112233445566778899aabbccddeeff";
    let manifest = MetadataTransferManifest {
        file_hash: hash.to_string(),
        display_name: "Scenario.File.bin".to_string(),
        file_size: 1,
        piece_size: 1,
        completed: false,
        final_rehash_pending: false,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: Vec::new(),
        pieces: vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            bytes_written: 0,
            block_bitmap: None,
            ich_corrupted: false,
        }],
        sources: Vec::new(),
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
        delivered_path: None,
        source_path: None,
        source_fingerprint: None,
    };
    store.upsert_transfer_manifest(&manifest).unwrap();
    store
        .upsert_search(&crate::MetadataSearch {
            public_id: "search-one".to_string(),
            normalized_query: "scenario file".to_string(),
            spec: crate::MetadataSearchSpec {
                query: "scenario file".to_string(),
                method: "automatic".to_string(),
                file_type: String::new(),
                extension: String::new(),
                min_size_bytes: None,
                max_size_bytes: None,
                min_availability: None,
                min_complete_sources: None,
                min_bitrate_kbps: None,
                min_length_seconds: None,
                codec: String::new(),
                title: String::new(),
                album: String::new(),
                artist: String::new(),
            },
            resolved_method: None,
            status: "completed".to_string(),
            status_reason: None,
            created_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: Some(2),
            results: vec![crate::MetadataSearchResult {
                file_hash: hash.to_string(),
                name: "Scenario.File.bin".to_string(),
                size_bytes: 1,
                source_count: 1,
                complete_source_count: 1,
                file_type: String::new(),
                media_artist: String::new(),
                media_album: String::new(),
                media_title: String::new(),
                media_length_seconds: 0,
                media_bitrate_kbps: 0,
                media_codec: String::new(),
                rating: 0,
                aich_hash: String::new(),
                complete: false,
                directory: String::new(),
                observations: vec![crate::MetadataSearchResultObservation {
                    origin: "local_index".to_string(),
                    server_endpoint: None,
                    name: "Scenario.File.bin".to_string(),
                    size_bytes: 1,
                    source_count: 1,
                    complete_source_count: 1,
                    source_client_id: None,
                    source_client_port: None,
                    file_type: String::new(),
                    media_artist: String::new(),
                    media_album: String::new(),
                    media_title: String::new(),
                    media_length_seconds: 0,
                    media_bitrate_kbps: 0,
                    media_codec: String::new(),
                    rating: 0,
                    aich_hash: String::new(),
                    complete: false,
                    directory: String::new(),
                    observed_at_ms: 2,
                }],
            }],
        })
        .unwrap();

    assert!(store.delete_transfer_manifest(hash).unwrap());
    // The search result row is retained with its known-file link cleared.
    assert_eq!(store.table_count("search_results").unwrap(), 1);
}

#[test]
fn completed_catalog_supports_hash_keyset_pages() {
    let store = MetadataStore::in_memory().unwrap();
    for sequence in 1..=3u128 {
        let file_hash = format!("{sequence:032x}");
        store
            .upsert_transfer_manifest(&MetadataTransferManifest {
                file_hash: file_hash.clone(),
                display_name: format!("catalog-{sequence}.bin"),
                file_size: sequence as u64,
                piece_size: 1,
                completed: true,
                final_rehash_pending: false,
                md4_hashset_acquired: true,
                md4_hashset: Vec::new(),
                aich_hashset_acquired: false,
                aich_root: None,
                aich_hashset: Vec::new(),
                verified_ranges: vec![MetadataTransferRange {
                    start: 0,
                    end: sequence as u64,
                }],
                pieces: Vec::new(),
                sources: Vec::new(),
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
                category_id: 0,
                control_state: None,
                transfer_row_removed: false,
                delivered_path: None,
                source_path: Some(format!("/library/catalog-{sequence}.bin").into()),
                source_fingerprint: Some(fingerprint(sequence as u64, sequence as u64)),
            })
            .unwrap();
    }

    let first = store
        .completed_transfer_catalog_entries_after(None, 2)
        .unwrap();
    assert_eq!(
        first
            .iter()
            .map(|entry| entry.file_hash.as_str())
            .collect::<Vec<_>>(),
        vec![
            "00000000000000000000000000000001",
            "00000000000000000000000000000002",
        ]
    );
    let second = store
        .completed_transfer_catalog_entries_after(Some(&first[1].file_hash), 2)
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].file_hash, "00000000000000000000000000000003");
    assert!(
        store
            .completed_transfer_catalog_entries_after(Some(&second[0].file_hash), 2)
            .unwrap()
            .is_empty()
    );
}
