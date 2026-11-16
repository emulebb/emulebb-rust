use crate::ed2k_transfer::test_support::admit_download_job;
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::MetadataStore;
use md4::{Digest, Md4};

use crate::{
    ed2k_transfer::{Ed2kRuntimeConfig, Ed2kSourceHint, Ed2kTransferRuntime},
    paths::unique_test_dir,
};

#[tokio::test]
async fn remembered_source_plaintext_fallback_preserves_single_endpoint_hint() {
    let root = unique_test_dir("ed2k-transfer-source-fallback-dedup");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x65; 16]);
    let job = admit_download_job(&runtime, file_hash, "source-fallback.bin".to_string(), 1024);
    runtime.ensure_job(&job).await.unwrap();

    runtime
        .remember_source(
            job.token,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: Some(hex::encode([0x44; 16])),
                connect_options: Some(0x07),
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();
    runtime
        .remember_source(
            job.token,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();

    let sources = runtime
        .download_sources_after(job.token, 0, 256)
        .await
        .unwrap()
        .map(|page| {
            page.into_iter()
                .map(|entry| entry.source)
                .collect::<Vec<_>>()
        });
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].ip, "198.51.100.44");
    assert_eq!(sources[0].tcp_port, 4662);
    assert_eq!(
        sources[0].user_hash.as_deref(),
        Some(hex::encode([0x44; 16]).as_str())
    );
    assert_eq!(sources[0].connect_options, Some(0x07));
}

#[tokio::test]
async fn remembered_source_late_user_hash_upgrades_endpoint_hint() {
    let root = unique_test_dir("ed2k-transfer-source-hash-upgrade");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x66; 16]);
    let job = admit_download_job(
        &runtime,
        file_hash,
        "source-hash-upgrade.bin".to_string(),
        1024,
    );
    runtime.ensure_job(&job).await.unwrap();

    runtime
        .remember_source(
            job.token,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();
    runtime
        .remember_source(
            job.token,
            Ed2kSourceHint {
                ip: "198.51.100.44".to_string(),
                tcp_port: 4662,
                user_hash: Some(hex::encode([0x45; 16])),
                connect_options: Some(0x05),
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();

    let sources = runtime
        .download_sources_after(job.token, 0, 256)
        .await
        .unwrap()
        .map(|page| {
            page.into_iter()
                .map(|entry| entry.source)
                .collect::<Vec<_>>()
        });
    assert_eq!(sources.len(), 1);
    assert_eq!(
        sources[0].user_hash.as_deref(),
        Some(hex::encode([0x45; 16]).as_str())
    );
    assert_eq!(sources[0].connect_options, Some(0x05));
}

#[tokio::test]
async fn protocol_drop_removes_only_the_exact_remembered_source() {
    let root = unique_test_dir("ed2k-transfer-source-protocol-drop");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x6A; 16]);
    let job = admit_download_job(
        &runtime,
        file_hash,
        "source-protocol-drop.bin".to_string(),
        1024,
    );
    runtime.ensure_job(&job).await.unwrap();

    for (tcp_port, user_hash) in [(4662, [0x51; 16]), (4663, [0x52; 16])] {
        runtime
            .remember_source(
                job.token,
                Ed2kSourceHint {
                    ip: "198.51.100.44".to_string(),
                    tcp_port,
                    user_hash: Some(hex::encode(user_hash)),
                    connect_options: None,
                    file_comment: String::new(),
                    file_rating: 0,
                },
            )
            .await
            .unwrap();
    }

    assert!(
        runtime
            .remove_source_identity(
                job.token,
                "198.51.100.44".parse().unwrap(),
                4662,
                Some([0x51; 16]),
            )
            .await
            .unwrap()
    );
    let sources = runtime
        .download_sources_after(job.token, 0, 256)
        .await
        .unwrap()
        .map(|page| {
            page.into_iter()
                .map(|entry| entry.source)
                .collect::<Vec<_>>()
        });
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].tcp_port, 4663);
    assert_eq!(
        sources[0].user_hash.as_deref(),
        Some(hex::encode([0x52; 16]).as_str())
    );
}

#[tokio::test]
async fn remembered_source_roundtrips_every_crypt_bit_combination() {
    let root = unique_test_dir("ed2k-transfer-source-connect-options");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x67; 16]);
    let job = admit_download_job(
        &runtime,
        file_hash,
        "source-connect-options.bin".to_string(),
        1024,
    );
    runtime.ensure_job(&job).await.unwrap();

    for connect_options in 0u8..=0x07 {
        runtime
            .remember_source(
                job.token,
                Ed2kSourceHint {
                    ip: format!("198.51.100.{}", 50 + connect_options),
                    tcp_port: 4662,
                    user_hash: Some(hex::encode([connect_options; 16])),
                    connect_options: Some(connect_options),
                    file_comment: String::new(),
                    file_rating: 0,
                },
            )
            .await
            .unwrap();
    }

    let sources = runtime
        .download_sources_after(job.token, 0, 256)
        .await
        .unwrap()
        .map(|page| {
            page.into_iter()
                .map(|entry| entry.source)
                .collect::<Vec<_>>()
        });
    assert_eq!(sources.len(), 8);
    for connect_options in 0u8..=0x07 {
        assert!(sources.iter().any(|source| {
            source.ip == format!("198.51.100.{}", 50 + connect_options)
                && source.connect_options == Some(connect_options)
        }));
    }
}

#[tokio::test]
async fn source_file_description_matches_identity_and_survives_rediscovery_and_reload() {
    let root = unique_test_dir("ed2k-transfer-source-file-description");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x68; 16]);
    let job = admit_download_job(
        &runtime,
        file_hash,
        "source-description.bin".to_string(),
        1024,
    );
    let user_hash = hex::encode([0x48; 16]);
    runtime.ensure_job(&job).await.unwrap();

    runtime
        .remember_source(
            job.token,
            Ed2kSourceHint {
                ip: "198.51.100.48".to_string(),
                tcp_port: 4662,
                user_hash: Some(user_hash.clone()),
                connect_options: Some(0x07),
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();
    // An inbound callback's socket uses an ephemeral port. Match the already
    // remembered public source by user hash instead of creating a second row.
    runtime
        .remember_source_file_description(
            job.token,
            Ed2kSourceHint {
                ip: "198.51.100.48".to_string(),
                tcp_port: 53001,
                user_hash: Some(user_hash.clone()),
                connect_options: Some(0x03),
                file_comment: "verified source comment".to_string(),
                file_rating: 5,
            },
        )
        .await
        .unwrap();
    runtime
        .remember_source(
            job.token,
            Ed2kSourceHint {
                ip: "198.51.100.48".to_string(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await
        .unwrap();

    let sources = runtime
        .download_sources_after(job.token, 0, 256)
        .await
        .unwrap()
        .map(|page| {
            page.into_iter()
                .map(|entry| entry.source)
                .collect::<Vec<_>>()
        });
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].tcp_port, 4662);
    assert_eq!(sources[0].file_comment, "verified source comment");
    assert_eq!(sources[0].file_rating, 5);
    drop(runtime);

    let reloaded = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let sources = reloaded
        .download_sources_after(job.token, 0, 256)
        .await
        .unwrap()
        .map(|page| {
            page.into_iter()
                .map(|entry| entry.source)
                .collect::<Vec<_>>()
        });
    assert_eq!(sources[0].file_comment, "verified source comment");
    assert_eq!(sources[0].file_rating, 5);
}

#[tokio::test]
async fn peer_names_remain_diagnostic_and_only_explicit_name_change_persists() {
    let root = unique_test_dir("ed2k-transfer-source-filename-majority");
    let metadata = MetadataStore::open(root.join("metadata.sqlite")).unwrap();
    let config = Ed2kRuntimeConfig {
        ..Ed2kRuntimeConfig::default()
    };
    let runtime =
        Ed2kTransferRuntime::load_or_create_with_metadata_and_config(&root, metadata, &config)
            .unwrap();
    let file_hash = Ed2kHash::from_bytes([0x69; 16]);
    let job = admit_download_job(&runtime, file_hash, "seed.bin".to_string(), 1024);
    runtime.ensure_job(&job).await.unwrap();

    for (last_octet, raw_name, software) in [
        (10, "Wrong.bin", "eMule v0.60d"),
        (11, "Caf%C3%A9.bin", "aMule 2.3.3"),
        (12, "Cafe\u{301}.bin", "eMule v0.50a"),
    ] {
        runtime
            .remember_source_file_name(
                job.token,
                Some(Ed2kSourceHint {
                    ip: format!("198.51.100.{last_octet}"),
                    tcp_port: 4662,
                    user_hash: Some(format!("{last_octet:02x}").repeat(16)),
                    connect_options: Some(0x07),
                    file_comment: String::new(),
                    file_rating: 0,
                }),
                raw_name,
                Some(software),
                "peer",
                Some("203.0.113.10:4661"),
            )
            .await
            .unwrap();
    }

    let manifest = runtime.manifest(job.token).await.unwrap();
    assert_eq!(manifest.display_name, "seed.bin");
    let observations = runtime
        .download_names_after(job.token, 0, 256)
        .await
        .unwrap();
    assert_eq!(observations.len(), 3);
    assert!(
        observations
            .iter()
            .any(|entry| entry.observation.raw_name == "Caf%C3%A9.bin"
                && entry.observation.normalized_name == "Café.bin"
                && entry.observation.client_software == "aMule 2.3.3")
    );

    runtime
        .rename_download_job(job.token, "Operator Choice.bin")
        .await
        .unwrap();
    runtime
        .remember_source_file_name(
            job.token,
            Some(Ed2kSourceHint {
                ip: "198.51.100.13".to_string(),
                tcp_port: 4662,
                user_hash: Some("13".repeat(16)),
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            }),
            "Another.bin",
            None,
            "peer",
            None,
        )
        .await
        .unwrap();
    drop(runtime);

    let reloaded = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let manifest = reloaded.manifest(job.token).await.unwrap();
    assert_eq!(manifest.display_name, "Operator Choice.bin");
    assert_eq!(
        reloaded
            .download_names_after(job.token, 0, 256)
            .await
            .unwrap()
            .len(),
        4
    );
}

#[tokio::test]
async fn repeated_peer_names_do_not_change_chosen_name() {
    let root = unique_test_dir("ed2k-transfer-source-filename-thresholds");
    let metadata = MetadataStore::open(root.join("metadata.sqlite")).unwrap();
    let config = Ed2kRuntimeConfig {
        ..Ed2kRuntimeConfig::default()
    };
    let runtime =
        Ed2kTransferRuntime::load_or_create_with_metadata_and_config(&root, metadata, &config)
            .unwrap();
    let file_hash = Ed2kHash::from_bytes([0x6A; 16]);
    let job = admit_download_job(&runtime, file_hash, "seed.bin".to_string(), 1024);
    runtime.ensure_job(&job).await.unwrap();

    for (last_octet, name) in [(20, "winner.bin"), (21, "winner.bin"), (22, "other.bin")] {
        runtime
            .remember_source_file_name(
                job.token,
                Some(Ed2kSourceHint {
                    ip: format!("198.51.100.{last_octet}"),
                    tcp_port: 4662,
                    user_hash: None,
                    connect_options: None,
                    file_comment: String::new(),
                    file_rating: 0,
                }),
                name,
                None,
                "peer",
                None,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        runtime.manifest(job.token).await.unwrap().display_name,
        "seed.bin"
    );

    runtime
        .remember_source_file_name(
            job.token,
            Some(Ed2kSourceHint {
                ip: "198.51.100.23".to_string(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            }),
            "winner.bin",
            None,
            "peer",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        runtime.manifest(job.token).await.unwrap().display_name,
        "seed.bin"
    );
}

#[tokio::test]
async fn peer_names_do_not_rename_completing_or_completed_jobs() {
    let root = unique_test_dir("ed2k-transfer-source-filename-completion-guard");
    let metadata = MetadataStore::open(root.join("metadata.sqlite")).unwrap();
    let config = Ed2kRuntimeConfig {
        ..Ed2kRuntimeConfig::default()
    };
    let runtime =
        Ed2kTransferRuntime::load_or_create_with_metadata_and_config(&root, metadata, &config)
            .unwrap();
    let payload = b"completion guard payload";
    let file_hash = Ed2kHash::from_bytes(Md4::digest(payload).into());
    let job = admit_download_job(
        &runtime,
        file_hash,
        "seed.bin".to_string(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data_unfinalized(job.token, 0, payload)
        .await
        .unwrap();
    let pending = runtime.manifest(job.token).await.unwrap();
    assert!(pending.final_rehash_pending);
    assert!(!pending.completed);

    for last_octet in [30, 31] {
        runtime
            .remember_source_file_name(
                job.token,
                Some(Ed2kSourceHint {
                    ip: format!("198.51.100.{last_octet}"),
                    tcp_port: 4662,
                    user_hash: None,
                    connect_options: None,
                    file_comment: String::new(),
                    file_rating: 0,
                }),
                "majority.bin",
                None,
                "peer",
                None,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        runtime.manifest(job.token).await.unwrap().display_name,
        "seed.bin"
    );

    assert!(runtime.finalize_pending_transfer(job.token).await.unwrap());
    runtime
        .remember_source_file_name(
            job.token,
            Some(Ed2kSourceHint {
                ip: "198.51.100.32".to_string(),
                tcp_port: 4662,
                user_hash: None,
                connect_options: None,
                file_comment: String::new(),
                file_rating: 0,
            }),
            "majority.bin",
            None,
            "peer",
            None,
        )
        .await
        .unwrap();
    let completed = runtime.manifest(job.token).await.unwrap();
    assert!(completed.completed);
    assert_eq!(completed.display_name, "seed.bin");
}
