use super::*;
use crate::config::Ed2kRuntimeConfig;
use emulebb_metadata::{
    MetadataSharedDirectoryRoot, MetadataStore, MetadataVerifiedLocalContent,
    NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp,
};

#[tokio::test]
async fn progressive_catalog_requires_explicit_initial_hydration() {
    let root = unique_test_dir("progressive-catalog");
    let mut metadata = MetadataStore::in_memory().unwrap();
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
        let fingerprint = NativeFileFingerprint {
            identity: NativeFileIdentity::WindowsHighResolution {
                volume_serial_number: 1,
                file_id: sequence,
            },
            size_bytes: sequence as u64,
            modified: NativeFileTimestamp::new(sequence as i64, 1).unwrap(),
            changed: Some(NativeFileTimestamp::new(sequence as i64, 2).unwrap()),
        };
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

    let runtime = Ed2kTransferRuntime::load_or_create_with_metadata_and_config_catalog_mode(
        &root,
        metadata,
        &Ed2kRuntimeConfig::default(),
        true,
    )
    .unwrap();

    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert_eq!(
        runtime
            .hydrate_initial_shared_catalog_page(2)
            .await
            .unwrap(),
        2
    );
    assert_eq!(runtime.shared_catalog_count().await, 2);
    assert_eq!(runtime.hydrate_shared_catalog().await.unwrap(), 1);
    assert_eq!(runtime.shared_catalog_count().await, 3);
    assert_eq!(runtime.hydrate_shared_catalog().await.unwrap(), 0);
    std::fs::remove_dir_all(root).ok();
}
