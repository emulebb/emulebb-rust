use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_transfer::{Ed2kSourceHint, Ed2kTransferRuntime, new_transfer_job},
    paths::unique_test_dir,
};

#[tokio::test]
async fn remembered_source_plaintext_fallback_preserves_single_endpoint_hint() {
    let root = unique_test_dir("ed2k-transfer-source-fallback-dedup");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x65; 16]);
    let job = new_transfer_job(file_hash, "source-fallback.bin".to_string(), 1024);
    runtime.ensure_job(&job).await.unwrap();

    runtime
        .remember_source(
            &job.file_hash,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: Some(hex::encode([0x44; 16])),
            },
        )
        .await
        .unwrap();
    runtime
        .remember_source(
            &job.file_hash,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: None,
            },
        )
        .await
        .unwrap();

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.sources.len(), 1);
    assert_eq!(manifest.sources[0].ip, "198.51.100.44");
    assert_eq!(manifest.sources[0].tcp_port, 4662);
    assert_eq!(
        manifest.sources[0].user_hash.as_deref(),
        Some(hex::encode([0x44; 16]).as_str())
    );
}

#[tokio::test]
async fn remembered_source_late_user_hash_upgrades_endpoint_hint() {
    let root = unique_test_dir("ed2k-transfer-source-hash-upgrade");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x66; 16]);
    let job = new_transfer_job(file_hash, "source-hash-upgrade.bin".to_string(), 1024);
    runtime.ensure_job(&job).await.unwrap();

    runtime
        .remember_source(
            &job.file_hash,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: None,
            },
        )
        .await
        .unwrap();
    runtime
        .remember_source(
            &job.file_hash,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: Some(hex::encode([0x45; 16])),
            },
        )
        .await
        .unwrap();

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.sources.len(), 1);
    assert_eq!(
        manifest.sources[0].user_hash.as_deref(),
        Some(hex::encode([0x45; 16]).as_str())
    );
}
