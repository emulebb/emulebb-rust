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
                connect_options: Some(0x07),
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
                connect_options: None,
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
    assert_eq!(manifest.sources[0].connect_options, Some(0x07));
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
                connect_options: None,
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
                connect_options: Some(0x05),
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
    assert_eq!(manifest.sources[0].connect_options, Some(0x05));
}

#[tokio::test]
async fn remembered_source_roundtrips_every_crypt_bit_combination() {
    let root = unique_test_dir("ed2k-transfer-source-connect-options");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x67; 16]);
    let job = new_transfer_job(file_hash, "source-connect-options.bin".to_string(), 1024);
    runtime.ensure_job(&job).await.unwrap();

    for connect_options in 0u8..=0x07 {
        runtime
            .remember_source(
                &job.file_hash,
                Ed2kSourceHint {
                    ip: format!("198.51.100.{}", 50 + connect_options),
                    tcp_port: 4662,
                    user_hash: Some(hex::encode([connect_options; 16])),
                    connect_options: Some(connect_options),
                },
            )
            .await
            .unwrap();
    }

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.sources.len(), 8);
    for connect_options in 0u8..=0x07 {
        assert!(manifest.sources.iter().any(|source| {
            source.ip == format!("198.51.100.{}", 50 + connect_options)
                && source.connect_options == Some(connect_options)
        }));
    }
}
