use super::*;
use crate::MetadataStore;

#[test]
fn transfer_manifest_roundtrips_sql_tables() {
    let store = MetadataStore::in_memory().unwrap();
    store
        .upsert_category(&crate::MetadataCategory {
            id: 2,
            name: "Samples".to_string(),
            path: None,
            comment: String::new(),
            priority: 1,
            color: None,
        })
        .unwrap();
    let manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        canonical_name: "Sample.Transfer.bin".to_string(),
        file_size: 1024,
        piece_size: 1024,
        completed: true,
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
        }],
        sources: vec![MetadataTransferSource {
            ip: "192.0.2.10".to_string(),
            tcp_port: 4662,
            user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
        }],
        upload_priority: "high".to_string(),
        auto_upload_priority: true,
        comment: "synthetic comment".to_string(),
        rating: 4,
        category_id: 2,
        control_state: Some("paused".to_string()),
        transfer_row_removed: false,
        delivered_path: Some("/incoming/Sample.Transfer.bin".to_string()),
        source_path: Some("/library/Sample.Transfer.bin".to_string()),
    };

    store.upsert_transfer_manifest(&manifest).unwrap();
    let restored = store
        .transfer_manifest_by_hash("00112233445566778899aabbccddeeff")
        .unwrap()
        .unwrap();

    assert_eq!(restored, manifest);
    assert_eq!(store.transfer_manifests().unwrap(), vec![manifest]);
}

#[test]
fn delete_transfer_manifest_removes_transfer_rows() {
    let store = MetadataStore::in_memory().unwrap();
    let manifest = MetadataTransferManifest {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        canonical_name: "Sample.Transfer.bin".to_string(),
        file_size: 1,
        piece_size: 1,
        completed: false,
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
        canonical_name: "Scenario.File.bin".to_string(),
        file_size: 1,
        piece_size: 1,
        completed: false,
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
    };
    store.upsert_transfer_manifest(&manifest).unwrap();
    store
        .upsert_search(&crate::MetadataSearch {
            public_id: "search-one".to_string(),
            query: "scenario file".to_string(),
            normalized_query: "scenario file".to_string(),
            method: "automatic".to_string(),
            search_type: String::new(),
            status: "completed".to_string(),
            created_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: Some(2),
            results: vec![crate::MetadataSearchResult {
                source_method: "automatic".to_string(),
                file_hash: hash.to_string(),
                name: "Scenario.File.bin".to_string(),
                size_bytes: 1,
                source_count: 1,
                complete_source_count: 1,
                file_type: String::new(),
                complete: false,
                known_type: String::new(),
                directory: String::new(),
                observed_at_ms: 2,
            }],
        })
        .unwrap();

    assert!(store.delete_transfer_manifest(hash).unwrap());
    // The search result row is retained with its known-file link cleared.
    assert_eq!(store.table_count("search_results").unwrap(), 1);
}
