//! Runtime-level tests for the global (cross-transfer) download-rate throttle,
//! the download-side counterpart to the upload payload throttle.

use std::time::{Duration, Instant};

use crate::ed2k_transfer::Ed2kTransferRuntime;
use crate::paths::unique_test_dir;

#[tokio::test]
async fn download_throttle_is_unlimited_no_op_by_default() {
    // Default runtime has download_limit_bytes_per_sec == 0 (unlimited), so the
    // shared limiter never paces: every reservation is instant, preserving
    // today's behavior.
    let root = unique_test_dir("ed2k-transfer-download-throttle-unlimited");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(runtime.download_limit_bytes_per_sec().await, 0);
    let now = Instant::now();

    let first = runtime
        .reserve_download_payload_budget_at(184_320, now)
        .await;
    let second = runtime
        .reserve_download_payload_budget_at(184_320, now)
        .await;

    assert_eq!(first.delay, Duration::ZERO);
    assert_eq!(second.delay, Duration::ZERO);
}

#[tokio::test]
async fn download_throttle_paces_two_transfers_from_one_shared_bucket() {
    // The token bucket is shared across all transfers: two distinct transfers'
    // reservations draw from the same global budget, so the second is delayed by
    // the first's interval (1024 B at 1024 B/s -> 1s), mirroring the upload-side
    // shared throttle.
    let root = unique_test_dir("ed2k-transfer-download-throttle-shared");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.apply_download_limit(1024).await;
    assert_eq!(runtime.download_limit_bytes_per_sec().await, 1024);
    let now = Instant::now();

    // Reservations for two different transfers (file A then file B) consult the
    // one shared limiter; the byte count, not the file, paces the bucket.
    let transfer_a = runtime.reserve_download_payload_budget_at(1024, now).await;
    let transfer_b = runtime.reserve_download_payload_budget_at(1024, now).await;

    assert_eq!(transfer_a.delay, Duration::ZERO);
    assert_eq!(transfer_b.delay, Duration::from_secs(1));
}

#[tokio::test]
async fn download_throttle_zero_byte_reservation_is_instant() {
    let root = unique_test_dir("ed2k-transfer-download-throttle-zero");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.apply_download_limit(1024).await;
    let now = Instant::now();

    let reservation = runtime.reserve_download_payload_budget_at(0, now).await;

    assert_eq!(reservation.delay, Duration::ZERO);
}
