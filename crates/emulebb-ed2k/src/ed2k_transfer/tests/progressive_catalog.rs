use super::*;
use crate::config::Ed2kRuntimeConfig;
use emulebb_metadata::{MetadataSharedDirectoryRoot, MetadataStore, MetadataVerifiedLocalContent};

#[tokio::test]
async fn progressive_catalog_requires_explicit_initial_hydration() {
    let root = unique_test_dir("progressive-catalog");
    std::fs::create_dir_all(&root).unwrap();
    let database_path = root.join("metadata.sqlite");
    let mut metadata = MetadataStore::open(&database_path).unwrap();
    metadata
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    for sequence in 1..=3u128 {
        let file_hash = format!("{sequence:032x}");
        let file_name = format!("catalog-{sequence}.bin");
        let path = root.join(&file_name);
        std::fs::write(&path, vec![sequence as u8; sequence as usize]).unwrap();
        let fingerprint = super::super::ingest::native_file_fingerprint(&path).unwrap();
        metadata
            .upsert_verified_local_content(&MetadataVerifiedLocalContent {
                file_hash: file_hash.clone(),
                display_name: file_name.clone(),
                file_size: sequence as u64,
                part_size: ED2K_PART_SIZE,
                md4_hashset: vec![file_hash],
                aich_root: "00".repeat(20),
                aich_hashset: vec!["00".repeat(20)],
                path: path.clone(),
                fingerprint: fingerprint.clone(),
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
            })
            .unwrap();
        assert!(
            metadata
                .admit_local_path_to_root(
                    &root,
                    &path,
                    std::path::Path::new(&file_name),
                    &fingerprint
                )
                .unwrap()
        );
    }

    let copy_path = root.join("catalog-2-copy.bin");
    std::fs::write(&copy_path, [2, 2]).unwrap();
    let mut copy = metadata
        .active_local_content_by_hash(&format!("{:032x}", 2))
        .unwrap()
        .unwrap();
    copy.path = copy_path.clone();
    copy.fingerprint = super::super::ingest::native_file_fingerprint(&copy_path).unwrap();
    metadata.upsert_verified_local_content(&copy).unwrap();
    assert!(
        metadata
            .admit_local_path_to_root(
                &root,
                &copy_path,
                std::path::Path::new("catalog-2-copy.bin"),
                &copy.fingerprint,
            )
            .unwrap()
    );

    // Simulate same-size replacement while the daemon is offline. The second
    // hash has another intact path and must remain publishable through it.
    for sequence in 1..=2u128 {
        let path = root.join(format!("catalog-{sequence}.bin"));
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![9; sequence as usize]).unwrap();
    }
    drop(metadata);
    let metadata = MetadataStore::open(&database_path).unwrap();

    let runtime = Ed2kTransferRuntime::load_or_create_with_metadata_and_config_catalog_mode(
        &root,
        metadata,
        &Ed2kRuntimeConfig::default(),
        true,
    )
    .unwrap();

    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert!(runtime.share_entries().await.unwrap().is_empty());
    assert!(
        runtime
            .servable_manifest(&format!("{:032x}", 1))
            .await
            .is_err()
    );
    assert_eq!(
        runtime
            .servable_manifest(&format!("{:032x}", 2))
            .await
            .unwrap()
            .source_path
            .as_deref(),
        Some(crate::long_path::long_path(&copy_path).as_path())
    );
    let visible = runtime.share_entries().await.unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].display_name, "catalog-2-copy.bin");
    assert_eq!(
        runtime
            .hydrate_initial_shared_catalog_page(1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert_eq!(runtime.hydrate_shared_catalog().await.unwrap(), 2);
    assert_eq!(runtime.shared_catalog_count().await, 2);
    let page = runtime
        .query_share_entries(emulebb_metadata::MetadataSharedFileQuery {
            limit: 10,
            count_total: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.entries.len(), 2);
    let (first, total, has_more) = runtime.share_entries_after(None, 1).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(total, 2);
    assert!(has_more);
    let publish = runtime.publish_entries().await.unwrap();
    assert_eq!(publish.len(), 2);
    assert_eq!(
        runtime.try_publish_entries().await.unwrap().unwrap(),
        publish
    );
    let catalog = runtime.shared_catalog();
    let guard = catalog.read().await;
    assert!(
        guard
            .entry_by_hash(&format!("{:032x}", 1).parse().unwrap())
            .is_none()
    );
    assert_eq!(
        guard
            .entry_by_hash(&format!("{:032x}", 2).parse().unwrap())
            .unwrap()
            .display_name,
        "catalog-2-copy.bin"
    );
    drop(guard);
    assert_eq!(runtime.hydrate_shared_catalog().await.unwrap(), 0);
    drop(runtime);
    std::fs::remove_dir_all(root).ok();
}
