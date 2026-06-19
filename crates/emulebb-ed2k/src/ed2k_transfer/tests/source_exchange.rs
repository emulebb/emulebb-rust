use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use crate::{
    ed2k_transfer::{Ed2kDownloadCoordinatorConfig, Ed2kTransferRuntime},
    paths::unique_test_dir,
};

#[tokio::test]
async fn source_exchange_reask_throttles_same_peer_and_file() {
    let root = unique_test_dir("ed2k-transfer-source-exchange-reask");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let now = Instant::now();
    let peer_addr = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 3), 4662));
    let user_hash = Some([0x51; 16]);

    assert!(
        runtime
            .should_request_source_exchange("aa", peer_addr, user_hash, 0, now)
            .await
    );
    assert!(
        !runtime
            .should_request_source_exchange(
                "aa",
                peer_addr,
                user_hash,
                0,
                now + Duration::from_secs(60),
            )
            .await
    );
    assert!(
        runtime
            .should_request_source_exchange(
                "aa",
                peer_addr,
                user_hash,
                0,
                now + Duration::from_secs(40 * 60 + 1),
            )
            .await
    );
    assert!(
        runtime
            .should_request_source_exchange(
                "bb",
                peer_addr,
                user_hash,
                0,
                now + Duration::from_secs(60),
            )
            .await
    );
}

#[tokio::test]
async fn source_exchange_common_files_use_common_reask_penalty() {
    let root = unique_test_dir("ed2k-transfer-source-exchange-common-reask");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let now = Instant::now();
    let peer_addr = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 5), 4662));
    let user_hash = Some([0x52; 16]);

    assert!(
        runtime
            .should_request_source_exchange("aa", peer_addr, user_hash, 51, now)
            .await
    );
    assert!(
        !runtime
            .should_request_source_exchange(
                "aa",
                peer_addr,
                user_hash,
                51,
                now + Duration::from_secs(40 * 60 + 1),
            )
            .await
    );
    assert!(
        runtime
            .should_request_source_exchange(
                "aa",
                peer_addr,
                user_hash,
                51,
                now + Duration::from_secs(160 * 60 + 1),
            )
            .await
    );
}

#[tokio::test]
async fn source_exchange_respects_soft_source_cap() {
    let root = unique_test_dir("ed2k-transfer-source-exchange-soft-cap");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.apply_download_coordinator_config(Ed2kDownloadCoordinatorConfig {
        max_sources_per_file: 10,
        ..Ed2kDownloadCoordinatorConfig::default()
    });
    let now = Instant::now();
    let peer_addr = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 4), 4662));

    assert!(
        runtime
            .should_request_source_exchange("aa", peer_addr, None, 8, now)
            .await
    );
    assert!(
        !runtime
            .should_request_source_exchange("bb", peer_addr, None, 9, now + Duration::from_secs(60))
            .await
    );
    assert!(
        runtime
            .should_request_source_exchange(
                "bb",
                peer_addr,
                None,
                8,
                now + Duration::from_secs(120),
            )
            .await,
        "a cap-denied request must not consume the peer throttle"
    );
}
