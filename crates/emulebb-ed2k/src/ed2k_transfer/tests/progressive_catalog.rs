use super::*;
use crate::config::Ed2kRuntimeConfig;
use emulebb_metadata::{MetadataSharedDirectoryRoot, MetadataStore, MetadataVerifiedLocalContent};
use std::sync::atomic::Ordering;

fn path_evidence(
    path: &std::path::Path,
) -> (
    emulebb_metadata::NativeFileFingerprint,
    Option<emulebb_metadata::NativeFileIdentity>,
) {
    let file = super::super::ingest::open_regular_file_without_follow(path).unwrap();
    let metadata = file.metadata().unwrap();
    let fingerprint =
        super::super::ingest::native_file_fingerprint_from_handle(&file, &metadata).unwrap();
    let evidence = super::super::ingest::native_file_identity_evidence_from_handle(
        &file,
        &metadata,
        &fingerprint,
    )
    .unwrap();
    (fingerprint, evidence.secondary())
}

#[tokio::test]
async fn progressive_catalog_requires_explicit_initial_hydration() {
    let root = unique_test_dir("progressive-catalog");
    std::fs::create_dir_all(&root).unwrap();
    let database_path = root.join("metadata.sqlite");
    let mut metadata = MetadataStore::open(&database_path).unwrap();
    metadata
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            watch_enabled: false,
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
        let (fingerprint, secondary_identity) = path_evidence(&path);
        metadata
            .upsert_verified_local_content(&MetadataVerifiedLocalContent {
                secondary_identity,
                file_hash: file_hash.clone(),
                display_name: file_name.clone(),
                file_size: sequence as u64,
                part_size: ED2K_PART_SIZE,
                md4_hashset: vec![file_hash],
                aich_root: Some("00".repeat(20)),
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
    (copy.fingerprint, copy.secondary_identity) = path_evidence(&copy_path);
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
    assert!(runtime.serving_view(&format!("{:032x}", 1)).await.is_err());
    assert_eq!(
        runtime
            .serving_view(&format!("{:032x}", 2))
            .await
            .unwrap()
            .local_path
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
    let publish = runtime
        .publish_entries_after(None, 200)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(publish.len(), 2);
    assert_eq!(
        &*runtime
            .publish_entries_after(None, 200)
            .await
            .unwrap()
            .unwrap(),
        &*publish
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

#[tokio::test]
async fn byte_capped_catalog_pages_advance_past_rejected_candidate_without_skipping() {
    use md4::{Digest, Md4};
    let root = unique_test_dir("catalog-byte-capped-frontiers");
    std::fs::create_dir_all(&root).unwrap();
    let database_path = root.join("metadata.sqlite");
    let mut metadata = MetadataStore::open(&database_path).unwrap();
    metadata
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let mut files = Vec::new();
    for index in 0..24u8 {
        let payload = [index; 16];
        let hash = hex::encode(Md4::digest(payload));
        let name = format!("candidate-{index}.bin");
        let path = root.join(&name);
        std::fs::write(&path, payload).unwrap();
        let (fingerprint, secondary_identity) = path_evidence(&path);
        metadata
            .upsert_verified_local_content(&MetadataVerifiedLocalContent {
                secondary_identity,
                file_hash: hash.clone(),
                display_name: name.clone(),
                file_size: payload.len() as u64,
                part_size: ED2K_PART_SIZE,
                md4_hashset: Vec::new(),
                aich_root: None,
                aich_hashset: Vec::new(),
                path: path.clone(),
                fingerprint: fingerprint.clone(),
                upload_priority: "normal".into(),
                auto_upload_priority: false,
                comment: "c".repeat(65_536),
                rating: 0,
            })
            .unwrap();
        assert!(
            metadata
                .admit_local_path_to_root(&root, &path, std::path::Path::new(&name), &fingerprint)
                .unwrap()
        );
        files.push((hash, path, fingerprint));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    drop(metadata);
    // Keep the stale row as the first lexical candidate, but never renew its
    // session verification; the cursor must pass it despite no publication.
    std::fs::remove_file(&files[0].1).unwrap();
    std::fs::write(&files[0].1, [0xff; 16]).unwrap();
    let metadata = MetadataStore::open(&database_path).unwrap();
    for (_, path, fingerprint) in &files[1..] {
        assert!(
            metadata
                .mark_session_verified_local_path(path, fingerprint)
                .unwrap()
        );
    }
    let short = metadata
        .completed_transfer_catalog_entries_after(None, 200)
        .unwrap();
    assert!(!short.is_empty() && short.len() < files.len() - 1);
    drop(short);
    let mut after = None;
    let mut hashes = Vec::new();
    let mut exhausted = false;
    for _ in 0..=files.len() {
        let page = super::super::transfer_sql::completed_catalog_page_from_metadata_store(
            &metadata,
            after.as_deref(),
            200,
        )
        .unwrap();
        hashes.extend(page.entries.into_iter().map(|entry| entry.file_hash));
        if !page.has_more {
            exhausted = true;
            break;
        }
        assert!(
            page.cursor > after,
            "even a rejected candidate must advance"
        );
        after = page.cursor;
    }
    assert!(
        exhausted,
        "bounded traversal must reach the final empty page"
    );
    assert_eq!(
        hashes,
        files[1..]
            .iter()
            .map(|file| file.0.clone())
            .collect::<Vec<_>>()
    );
    let runtime = Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata).unwrap();
    assert_eq!(runtime.shared_catalog_count().await, files.len() - 1);
    let generation = runtime.shared_catalog_generation.load(Ordering::Acquire);
    let checkpoints = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_checkpoints = std::sync::Arc::clone(&checkpoints);
    assert_eq!(
        runtime
            .refresh_complete_shared_catalog_while(move || {
                worker_checkpoints.fetch_add(1, Ordering::AcqRel) < 3
            })
            .await
            .unwrap(),
        None
    );
    assert!(checkpoints.load(Ordering::Acquire) > 1);
    assert_eq!(runtime.shared_catalog_count().await, files.len() - 1);
    assert_eq!(
        runtime.shared_catalog_generation.load(Ordering::Acquire),
        generation
    );
    assert_eq!(
        runtime.refresh_complete_shared_catalog().await.unwrap(),
        files.len() - 1
    );
    let catalog = runtime.shared_catalog();
    let catalog = catalog.read().await;
    assert!(
        catalog
            .entry_by_hash(&files[0].0.parse().unwrap())
            .is_none()
    );
    assert_eq!(catalog.len(), files.len() - 1);
}
