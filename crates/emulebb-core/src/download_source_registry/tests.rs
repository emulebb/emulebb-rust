use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
use emulebb_kad_proto::Ed2kHash;

use super::{
    CANDIDATE_LIVENESS_TTL, DownloadSourceCandidate, DownloadSourceRegistry, NNP_REASK_HOLD,
};

#[test]
fn registry_derives_a4af_candidates_from_peer_fanout() {
    let source = source_with_hash([0x11; 16]);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();

    registry.add_candidate(
        now,
        candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1, source.clone()),
    );
    registry.add_candidate(
        now,
        candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2, 1, source.clone()),
    );

    assert_eq!(registry.candidate_count_for_peer(&source), 2);
    assert_eq!(registry.a4af_candidate_count(), 1);
}

#[test]
fn registry_leases_one_file_per_peer_and_prefers_best_candidate() {
    let source = source_with_hash([0x22; 16]);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    registry.add_candidate(
        now,
        candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 10, source.clone()),
    );
    registry.add_candidate(
        now,
        candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 5, 1, source.clone()),
    );

    let leased = registry
        .lease_best_for_file(
            now,
            Duration::ZERO,
            &source,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

    assert_eq!(leased.file_hash, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(
        registry
            .lease_best_for_file(
                now,
                Duration::ZERO,
                &source,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
            .is_none()
    );
    registry.release_peer(&source);
    assert!(
        registry
            .lease_best_for_file(
                now,
                Duration::ZERO,
                &source,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
            .is_some()
    );
}

#[test]
fn registry_refreshing_same_source_does_not_bypass_retry_cooldown() {
    let source = source_with_hash([0x23; 16]);
    let mut registry = DownloadSourceRegistry::default();
    let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let now = Instant::now();
    let retry_cooldown = Duration::from_secs(20 * 60);
    registry.add_candidate(now, candidate(file, 1, 10, source.clone()));

    assert!(
        registry
            .lease_best_for_file(now, retry_cooldown, &source, file)
            .is_some()
    );
    registry.release_peer(&source);

    // Fresh source discovery may re-add/refresh the same peer on the next
    // download attempt. That must not clear the last-attempt stamp; otherwise
    // a failing source can be redialed every short retry cycle.
    let refreshed_at = now + Duration::from_secs(30);
    registry.add_candidate(refreshed_at, candidate(file, 1, 10, source.clone()));

    assert!(
        registry
            .lease_best_for_file(refreshed_at, retry_cooldown, &source, file)
            .is_none()
    );
    assert_eq!(
        registry.endpoint_retry_delay(refreshed_at, retry_cooldown, &source, file),
        Some(retry_cooldown - Duration::from_secs(30))
    );
}

#[test]
fn registry_defers_when_peer_is_better_for_another_file() {
    let source = source_with_hash([0x33; 16]);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    registry.add_candidate(
        now,
        candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 10, source.clone()),
    );
    registry.add_candidate(
        now,
        candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 5, 1, source.clone()),
    );

    assert!(
        registry
            .lease_best_for_file(
                now,
                Duration::ZERO,
                &source,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .is_none()
    );
    assert!(
        registry
            .lease_best_for_file(
                now,
                Duration::ZERO,
                &source,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
            .is_some()
    );
}

#[test]
fn registry_swap_target_picks_best_other_wanted_file_and_skips_current() {
    let source = source_with_hash([0x55; 16]);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    // Peer serves three files: current (a), a low-priority other (b), and a
    // high-priority other (c). The NNP swap must pick c over b and never a.
    registry.add_candidate(
        now,
        candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, 9, source.clone()),
    );
    registry.add_candidate(
        now,
        candidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, 1, source.clone()),
    );
    registry.add_candidate(
        now,
        candidate("cccccccccccccccccccccccccccccccc", 5, 1, source.clone()),
    );

    let target = registry
        .swap_target_for_peer(&source, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
    assert_eq!(target.file_hash, "cccccccccccccccccccccccccccccccc");
}

#[test]
fn registry_swap_target_is_none_when_peer_serves_only_the_current_file() {
    let source = source_with_hash([0x66; 16]);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    registry.add_candidate(
        now,
        candidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 9, 9, source.clone()),
    );

    assert!(
        registry
            .swap_target_for_peer(&source, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
}

#[test]
fn stale_candidates_age_out_of_the_per_file_count_and_are_pruned() {
    // A long-lived file sees many distinct peers over time. Without a liveness
    // TTL the per-file count grew monotonically with every peer ever seen and
    // the file eventually stopped accepting new live sources. The TTL-filtered
    // count must reflect only currently-live candidates, and prune must keep
    // the map bounded.
    let mut registry = DownloadSourceRegistry::default();
    let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let t0 = Instant::now();

    // A dead source registered long ago.
    registry.add_candidate(t0, candidate(file, 5, 1, source_with_endpoint(0x01, 41100)));

    // A fresh source registered well past the TTL: only it is still live.
    let later = t0 + CANDIDATE_LIVENESS_TTL + Duration::from_secs(1);
    registry.add_candidate(
        later,
        candidate(file, 5, 1, source_with_endpoint(0x02, 41101)),
    );

    // The stale candidate is excluded from the live per-file count.
    assert_eq!(
        registry.candidate_count_for_file(later, file),
        1,
        "stale candidate must not count toward the per-file soft cap"
    );
    // Both rows still exist until a prune runs.
    assert_eq!(registry.candidate_count(), 2);

    // Pruning drops the stale candidate so the map stays bounded.
    registry.prune_stale_candidates(later);
    assert_eq!(registry.candidate_count(), 1);
    assert_eq!(registry.candidate_count_for_file(later, file), 1);

    // A still-fresh candidate keeps counting (a re-seen live source survives).
    let refreshed = later + Duration::from_secs(1);
    registry.add_candidate(
        refreshed,
        candidate(file, 5, 1, source_with_endpoint(0x02, 41101)),
    );
    assert_eq!(registry.candidate_count_for_file(refreshed, file), 1);
}

#[test]
fn release_file_clears_candidates_and_only_that_files_leases() {
    // A peer leased for the file being released loses its lease (returned for
    // the caller to drop the matching active endpoint); the file's candidates
    // are gone. A different peer leased for ANOTHER file keeps its lease and
    // candidate (an A4AF peer shared with a live transfer is not yanked out).
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    let target = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // Peer 1 serves only the target file and is leased on it.
    let peer_target = source_with_endpoint(0x01, 41200);
    registry.add_candidate(now, candidate(target, 5, 1, peer_target.clone()));
    assert!(
        registry
            .lease_best_for_file(now, Duration::ZERO, &peer_target, target)
            .is_some()
    );

    // Peer 2 serves a different file and is leased on it.
    let peer_other = source_with_endpoint(0x02, 41201);
    registry.add_candidate(now, candidate(other, 5, 1, peer_other.clone()));
    assert!(
        registry
            .lease_best_for_file(now, Duration::ZERO, &peer_other, other)
            .is_some()
    );

    // Peer 3 serves the target file but is NOT leased.
    let peer_unleased = source_with_endpoint(0x03, 41202);
    registry.add_candidate(now, candidate(target, 5, 1, peer_unleased.clone()));

    assert_eq!(registry.candidate_count_for_file(now, target), 2);
    assert_eq!(registry.leased_peer_count(), 2);

    let cleared = registry.release_file(target);

    // Only peer 1's endpoint is returned (it was leased for the target file).
    assert_eq!(cleared, vec![(peer_target.ip, peer_target.tcp_port)]);
    // The target file's candidates are gone; the other file's remain.
    assert_eq!(registry.candidate_count_for_file(now, target), 0);
    assert_eq!(registry.candidate_count_for_file(now, other), 1);
    // Peer 2's lease (for the other file) is untouched; peer 1's is gone.
    assert_eq!(registry.leased_peer_count(), 1);
    assert!(
        registry
            .lease_best_for_file(now, Duration::ZERO, &peer_other, other)
            .is_none(),
        "the other file's lease must still be held"
    );
}

#[test]
fn released_endpoint_stays_cooldown_deferred_until_retry_window_expires() {
    let source = source_with_endpoint(0x04, 41203);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cooldown = Duration::from_secs(20 * 60);
    registry.add_candidate(now, candidate(file, 5, 1, source.clone()));

    assert!(
        registry
            .lease_best_for_file(now, cooldown, &source, file)
            .is_some()
    );
    registry.release_peer(&source);
    assert!(
        registry
            .lease_best_for_file(now + Duration::from_secs(60), cooldown, &source, file)
            .is_none(),
        "a failed endpoint should not be re-dialed inside the MFC retry window"
    );
    assert!(
        registry
            .lease_best_for_file(
                now + cooldown + Duration::from_secs(1),
                cooldown,
                &source,
                file
            )
            .is_some()
    );
}

#[test]
fn endpoint_cooldown_is_per_file_so_a_multi_file_peer_serves_files_back_to_back() {
    // Regression (kad_swarm E2E stall): a peer that had just successfully
    // served file A was cooldown-blocked for file B for the whole 20-minute
    // window, so the deferred transfer's attempt slept past every test and
    // user-visible horizon. The cooldown is a per-(endpoint, file) anti-churn
    // floor, not a per-endpoint one.
    let source = source_with_endpoint(0x05, 41204);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    let file_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let file_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let cooldown = Duration::from_secs(20 * 60);
    registry.add_candidate(now, candidate(file_a, 5, 1, source.clone()));

    assert!(
        registry
            .lease_best_for_file(now, cooldown, &source, file_a)
            .is_some()
    );
    // File A completes: the peer's lease is released, file A's candidates are
    // gone, and the peer is now registered for file B (the next wanted file).
    registry.release_peer(&source);
    registry.release_file(file_a);
    let later = now + Duration::from_secs(5);
    registry.add_candidate(later, candidate(file_b, 5, 1, source.clone()));

    assert!(
        registry
            .lease_best_for_file(later, cooldown, &source, file_b)
            .is_some(),
        "a peer that just served file A must be immediately leasable for file B"
    );
    assert!(
        registry
            .endpoint_retry_delay(later, cooldown, &source, file_a)
            .is_some(),
        "file A keeps its own anti-churn window against the same endpoint"
    );
}

#[test]
fn nnp_hold_defers_the_lease_for_the_doubled_reask_interval() {
    // RUST-PAR-017 DL-3: a No-Needed-Parts source is HELD, not dropped —
    // it stays a candidate but is not re-dialed for FILEREASKTIME * 2
    // (58 min, oracle GetTimeUntilReask DownloadClient.cpp:2425-2431),
    // instead of being redialed on the 20-minute attempt cooldown.
    let source = source_with_endpoint(0x10, 41300);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cooldown = Duration::from_secs(20 * 60);
    registry.add_candidate(now, candidate(file, 5, 1, source.clone()));

    assert!(registry.mark_no_needed_parts(now, &source, file));
    assert_eq!(registry.nnp_source_count(now), 1);
    // The candidate is retained (held, not dropped).
    assert_eq!(registry.candidate_count_for_file(now, file), 1);

    // Past the 20-minute cooldown but inside the NNP hold: still deferred,
    // and the reported retry delay is the hold remainder (not the cooldown).
    let at_25_min = now + Duration::from_secs(25 * 60);
    assert!(
        registry
            .lease_best_for_file(at_25_min, cooldown, &source, file)
            .is_none(),
        "an NNP-held source must not be redialed at the 20-minute cooldown"
    );
    assert_eq!(
        registry.endpoint_retry_delay(at_25_min, cooldown, &source, file),
        Some(NNP_REASK_HOLD - Duration::from_secs(25 * 60)),
    );

    // After the doubled interval the hold expires and the re-ask leases.
    let after_hold = now + NNP_REASK_HOLD + Duration::from_secs(1);
    assert!(
        registry
            .lease_best_for_file(after_hold, cooldown, &source, file)
            .is_some(),
        "the NNP source is re-asked once the 58-minute hold elapses"
    );
    // The expired hold was pruned at lease time (oracle reset to
    // DS_ONQUEUE at reask time); the flag stays clear unless re-marked.
    assert_eq!(registry.nnp_source_count(after_hold), 0);
}

#[test]
fn peer_acquiring_needed_parts_clears_the_nnp_flag_and_resumes_normal_cadence() {
    // After the hold elapses the re-ask session runs; when the peer now HAS
    // needed parts the pair is simply not re-marked, so only the normal
    // attempt cooldown gates the next dial (not another 58-minute hold).
    let source = source_with_endpoint(0x11, 41301);
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cooldown = Duration::from_secs(20 * 60);
    registry.add_candidate(now, candidate(file, 5, 1, source.clone()));
    registry.mark_no_needed_parts(now, &source, file);

    // Hold elapsed -> re-ask leases (this is "the next reask/session").
    let reask_at = now + NNP_REASK_HOLD + Duration::from_secs(1);
    assert!(
        registry
            .lease_best_for_file(reask_at, cooldown, &source, file)
            .is_some()
    );
    registry.release_peer(&source);

    // The session found needed parts -> no re-mark. The next dial is gated
    // by the plain cooldown remainder only, not a fresh NNP hold.
    let later = reask_at + Duration::from_secs(60);
    assert_eq!(registry.nnp_source_count(later), 0);
    assert_eq!(
        registry.endpoint_retry_delay(later, cooldown, &source, file),
        Some(cooldown - Duration::from_secs(60)),
    );
    assert!(
        registry
            .lease_best_for_file(
                reask_at + cooldown + Duration::from_secs(1),
                cooldown,
                &source,
                file
            )
            .is_some(),
        "normal 20-minute cadence resumes once the NNP flag is gone"
    );
}

#[test]
fn nnp_hold_refreshes_liveness_and_is_cleaned_up_with_its_candidate() {
    let source = source_with_endpoint(0x12, 41302);
    let mut registry = DownloadSourceRegistry::default();
    let t0 = Instant::now();
    let file = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    registry.add_candidate(t0, candidate(file, 5, 1, source.clone()));

    // Marking NNP at t0+50min refreshes liveness: at t0+70min (past the TTL
    // from t0, inside it from the mark) the held candidate must survive the
    // prune — the oracle keeps NNP sources in the srclist across the hold.
    let marked_at = t0 + Duration::from_secs(50 * 60);
    registry.mark_no_needed_parts(marked_at, &source, file);
    let pruned_at = t0 + Duration::from_secs(70 * 60);
    registry.prune_stale_candidates(pruned_at);
    assert_eq!(
        registry.candidate_count_for_file(pruned_at, file),
        1,
        "an NNP-held candidate must not age out mid-hold"
    );

    // A genuine removal takes the hold with it.
    assert!(registry.remove_candidate(&source, file));
    assert_eq!(registry.nnp_source_count(marked_at), 0);
}

#[test]
fn nnp_purge_throttle_grants_once_per_40_second_window_per_file() {
    // Oracle PartFile.cpp:3056-3057: even under source-cap pressure at most
    // one NNP source is purged per 40-second window per file.
    let mut registry = DownloadSourceRegistry::default();
    let now = Instant::now();
    let file_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let file_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert!(registry.try_nnp_purge(now, file_a));
    assert!(!registry.try_nnp_purge(now + Duration::from_secs(39), file_a));
    // The window is per file: another file purges independently.
    assert!(registry.try_nnp_purge(now, file_b));
    assert!(registry.try_nnp_purge(now + Duration::from_secs(40), file_a));
}

fn source_with_endpoint(last_octet: u8, tcp_port: u16) -> Ed2kFoundSource {
    let mut source = source_with_hash([last_octet; 16]);
    source.ip = Ipv4Addr::new(198, 51, 100, last_octet);
    source.tcp_port = tcp_port;
    source.client_id = u32::from_be_bytes(source.ip.octets());
    source
}

fn candidate(
    file_hash: &str,
    file_priority: u32,
    rare_parts: u32,
    source: Ed2kFoundSource,
) -> DownloadSourceCandidate {
    DownloadSourceCandidate {
        file_hash: file_hash.to_string(),
        file_priority,
        needed_parts: 4,
        rare_parts,
        source,
        // Overwritten by add_candidate; placeholder only.
        last_seen: Instant::now(),
    }
}

fn source_with_hash(user_hash: [u8; 16]) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash: Ed2kHash::from_bytes([0x44; 16]),
        ip: Ipv4Addr::new(198, 51, 100, 40),
        tcp_port: 4662,
        client_id: 0xC633_6428,
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: Some(user_hash),
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    }
}
