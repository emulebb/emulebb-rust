use super::*;

#[test]
fn download_read_timeout_uses_earliest_queue_deadline() {
    let now = tokio::time::Instant::now();
    let read_timeout = next_download_read_timeout(
        now,
        Duration::from_secs(300),
        None,
        Some(now + Duration::from_secs(20)),
        None,
    );
    assert_eq!(read_timeout, Duration::from_secs(20));
}

#[test]
fn download_read_timeout_uses_earliest_part_deadline() {
    let now = tokio::time::Instant::now();
    let read_timeout = next_download_read_timeout(
        now,
        Duration::from_secs(300),
        Some(Duration::from_secs(120)),
        Some(now + Duration::from_secs(25)),
        Some(now + Duration::from_secs(7)),
    );
    assert_eq!(read_timeout, Duration::from_secs(7));
}

#[test]
fn download_read_timeout_immediately_wakes_for_elapsed_deadline() {
    let now = tokio::time::Instant::now();
    let read_timeout = next_download_read_timeout(
        now,
        Duration::from_secs(300),
        None,
        Some(now - Duration::from_secs(1)),
        None,
    );
    assert_eq!(read_timeout, Duration::ZERO);
}

#[test]
fn download_window_starts_with_one_block_before_any_completed_payload() {
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x21; 16]),
        "window.iso".to_string(),
        ED2K_PART_SIZE * 5,
    );
    let manifest = Ed2kResumeManifest::new(&job);
    let limits = select_download_window_limits(&manifest, 0, 0, tokio::time::Instant::now());
    assert_eq!(
        limits,
        DownloadWindowLimits {
            max_pending_blocks: 1,
            min_pending_blocks: 1,
        }
    );
}

#[test]
fn download_window_grows_for_fast_large_transfer() {
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x31; 16]),
        "window.iso".to_string(),
        ED2K_PART_SIZE * 5,
    );
    let manifest = Ed2kResumeManifest::new(&job);
    let limits = select_download_window_limits(
        &manifest,
        3,
        1_024 * 1024,
        tokio::time::Instant::now() - Duration::from_secs(10),
    );
    assert_eq!(
        limits,
        DownloadWindowLimits {
            max_pending_blocks: 6,
            min_pending_blocks: 4,
        }
    );
}

#[test]
fn download_window_scales_to_master_rate_tiers() {
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x32; 16]),
        "window.iso".to_string(),
        ED2K_PART_SIZE * 32,
    );
    let manifest = Ed2kResumeManifest::new(&job);
    // Mirror master DownloadRequestSeams::SelectDownloadBlockRequestReserve:
    // 9 / 12 / 18 at >150K / >=512K / >=1M B/s. Each case keeps
    // completed_block_count >= 3 and a large remaining transfer.
    let cases = [
        (200 * 1024, 9usize, 6usize),
        (600 * 1024, 12usize, 8usize),
        (2 * 1024 * 1024, 18usize, 12usize),
    ];
    for (rate, expected_max, expected_min) in cases {
        let limits = select_download_window_limits(
            &manifest,
            3,
            rate,
            tokio::time::Instant::now() - Duration::from_secs(1),
        );
        assert_eq!(
            limits,
            DownloadWindowLimits {
                max_pending_blocks: expected_max,
                min_pending_blocks: expected_min,
            },
            "rate {rate} B/s should map to {expected_max}/{expected_min}"
        );
    }
}

#[test]
fn download_window_stays_small_for_slow_endgame_transfer() {
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x41; 16]),
        "window.iso".to_string(),
        ED2K_PART_SIZE * 2,
    );
    let manifest = Ed2kResumeManifest::new(&job);
    let limits = select_download_window_limits(
        &manifest,
        1,
        32 * 1024,
        tokio::time::Instant::now() - Duration::from_secs(20),
    );
    assert_eq!(
        limits,
        DownloadWindowLimits {
            max_pending_blocks: 1,
            min_pending_blocks: 1,
        }
    );
}
