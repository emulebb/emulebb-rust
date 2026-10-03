use super::*;
use crate::config::Ed2kRuntimeConfig;
use emulebb_metadata::{
    MetadataStore, MetadataTransferManifest, MetadataTransferMediaMetadata, MetadataTransferRange,
};

#[tokio::test]
async fn progressive_catalog_exposes_first_cohort_before_full_hydration() {
    let root = unique_test_dir("progressive-catalog");
    let metadata = MetadataStore::in_memory().unwrap();
    for sequence in 1..=3u128 {
        let file_hash = format!("{sequence:032x}");
        metadata
            .upsert_transfer_manifest(&MetadataTransferManifest {
                file_hash: file_hash.clone(),
                display_name: format!("catalog-{sequence}.bin"),
                file_size: sequence as u64,
                piece_size: 1,
                completed: true,
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
                source_path: Some(
                    root.join(format!("catalog-{sequence}.bin"))
                        .display()
                        .to_string(),
                ),
                source_mtime_ms: Some(sequence as i64),
            })
            .unwrap();
        metadata
            .update_transfer_media_metadata(
                &file_hash,
                &MetadataTransferMediaMetadata {
                    extractor_version: super::super::transfer_sql::MEDIA_METADATA_EXTRACTOR_VERSION,
                    ..MetadataTransferMediaMetadata::default()
                },
            )
            .unwrap();
    }

    let runtime = Ed2kTransferRuntime::load_or_create_with_metadata_and_config_catalog_limit(
        &root,
        metadata,
        &Ed2kRuntimeConfig::default(),
        Some(2),
    )
    .unwrap();

    assert_eq!(runtime.shared_catalog_count().await, 2);
    assert_eq!(runtime.hydrate_shared_catalog().await.unwrap(), 1);
    assert_eq!(runtime.shared_catalog_count().await, 3);
    assert_eq!(runtime.hydrate_shared_catalog().await.unwrap(), 0);
    std::fs::remove_dir_all(root).ok();
}
