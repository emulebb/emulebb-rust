use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use emulebb_ed2k::ed2k_server::{Ed2kServerSourceBatchTarget, Ed2kUdpSourceBatchTarget};
use emulebb_kad_proto::Ed2kHash;

use crate::{CoreState, Transfer};

pub(crate) const ED2K_SERVER_UDP_SOURCE_BATCH_COOLDOWN: Duration = Duration::from_secs(30 * 60);
pub(crate) const ED2K_CONNECTED_SERVER_SOURCE_COOLDOWN: Duration = Duration::from_secs(15 * 60);
pub(crate) const ED2K_CONNECTED_SERVER_SOURCE_FRAME_INTERVAL: Duration =
    Duration::from_secs(15 * (16 + 4));
pub(crate) const ED2K_CONNECTED_SERVER_SOURCE_FRAME_MAX_FILES: usize = 15;
pub(crate) const ED2K_KAD_SOURCE_REASK_BASE_COOLDOWN: Duration = Duration::from_secs(60 * 60);
const ED2K_KAD_SOURCE_REASK_MAX_MULTIPLIER: u8 = 7;

#[derive(Clone, Debug)]
pub(crate) struct ClaimedEd2kUdpSourceBatch {
    pub targets: Vec<Ed2kUdpSourceBatchTarget>,
    pub transfers: HashMap<Ed2kHash, Transfer>,
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimedConnectedServerSourceBatch {
    pub targets: Vec<Ed2kServerSourceBatchTarget>,
    pub transfers: HashMap<Ed2kHash, Transfer>,
}

pub(crate) fn claim_ed2k_udp_source_batch(
    state: &mut CoreState,
    current_transfer: &Transfer,
    current_file_hash: Ed2kHash,
    current_source_count: usize,
    udp_source_cap: usize,
    now: Instant,
) -> ClaimedEd2kUdpSourceBatch {
    state
        .ed2k_udp_source_batch_last_queried
        .retain(|_, last_queried| {
            now.saturating_duration_since(*last_queried) < ED2K_SERVER_UDP_SOURCE_BATCH_COOLDOWN
        });

    let mut targets = Vec::new();
    let mut transfers = HashMap::new();
    let mut candidates = Vec::new();
    candidates.push((
        current_file_hash,
        current_transfer.clone(),
        current_source_count,
    ));

    for transfer in state.transfers.values() {
        if transfer.hash == current_transfer.hash
            || !is_ed2k_udp_source_batch_transfer_candidate(transfer)
            || transfer.size_bytes == 0
        {
            continue;
        }
        let Ok(file_hash) = transfer.hash.parse::<Ed2kHash>() else {
            continue;
        };
        let source_count = state
            .download_source_registry
            .candidate_count_for_file(now, &transfer.hash);
        candidates.push((file_hash, transfer.clone(), source_count));
    }

    for (file_hash, transfer, source_count) in candidates {
        // Oracle GetMaxSourcePerFileUDP gate: only walk files still under
        // their UDP source cap (0 = uncapped).
        let under_cap = udp_source_cap == 0 || source_count < udp_source_cap;
        if !under_cap || was_recently_queried(state, &transfer.hash, now) {
            continue;
        }
        state
            .ed2k_udp_source_batch_last_queried
            .insert(transfer.hash.clone(), now);
        targets.push(Ed2kUdpSourceBatchTarget {
            file_hash,
            file_size: transfer.size_bytes,
        });
        transfers.insert(file_hash, transfer);
    }

    ClaimedEd2kUdpSourceBatch { targets, transfers }
}

pub(crate) fn claim_connected_server_source_batch(
    state: &mut CoreState,
    current_transfer: &Transfer,
    current_file_hash: Ed2kHash,
    now: Instant,
) -> ClaimedConnectedServerSourceBatch {
    state
        .ed2k_server_source_last_queried
        .retain(|_, last_queried| {
            now.saturating_duration_since(*last_queried) < ED2K_CONNECTED_SERVER_SOURCE_COOLDOWN
        });
    if state
        .ed2k_server_source_last_frame_at
        .is_some_and(|last_frame| {
            now.saturating_duration_since(last_frame) < ED2K_CONNECTED_SERVER_SOURCE_FRAME_INTERVAL
        })
    {
        return ClaimedConnectedServerSourceBatch {
            targets: Vec::new(),
            transfers: HashMap::new(),
        };
    }

    let mut candidates = Vec::new();
    candidates.push((current_file_hash, current_transfer.clone()));
    for transfer in state.transfers.values() {
        if transfer.hash == current_transfer.hash
            || !is_server_source_batch_transfer_candidate(transfer)
            || transfer.size_bytes == 0
        {
            continue;
        }
        let Ok(file_hash) = transfer.hash.parse::<Ed2kHash>() else {
            continue;
        };
        candidates.push((file_hash, transfer.clone()));
    }

    let mut targets = Vec::new();
    let mut transfers = HashMap::new();
    for (file_hash, transfer) in candidates {
        if was_recently_queried_on_connected_server(state, &transfer.hash, now) {
            continue;
        }
        state
            .ed2k_server_source_last_queried
            .insert(transfer.hash.clone(), now);
        targets.push(Ed2kServerSourceBatchTarget {
            file_hash,
            file_size: transfer.size_bytes,
        });
        transfers.insert(file_hash, transfer);
        if targets.len() >= ED2K_CONNECTED_SERVER_SOURCE_FRAME_MAX_FILES {
            break;
        }
    }
    if !targets.is_empty() {
        state.ed2k_server_source_last_frame_at = Some(now);
    }
    ClaimedConnectedServerSourceBatch { targets, transfers }
}

pub(crate) fn claim_kad_source_refresh(
    state: &mut CoreState,
    file_hash: &str,
    now: Instant,
) -> bool {
    if let Some((last_queried, searches)) = state.ed2k_kad_source_last_queried.get(file_hash) {
        let multiplier = (*searches).max(1) as u32;
        let cooldown = ED2K_KAD_SOURCE_REASK_BASE_COOLDOWN.saturating_mul(multiplier);
        if now.saturating_duration_since(*last_queried) < cooldown {
            return false;
        }
    }
    let searches = state
        .ed2k_kad_source_last_queried
        .get(file_hash)
        .map_or(1, |(_, searches)| {
            searches
                .saturating_add(1)
                .min(ED2K_KAD_SOURCE_REASK_MAX_MULTIPLIER)
        });
    state
        .ed2k_kad_source_last_queried
        .insert(file_hash.to_string(), (now, searches));
    true
}

fn was_recently_queried(state: &CoreState, file_hash: &str, now: Instant) -> bool {
    state
        .ed2k_udp_source_batch_last_queried
        .get(file_hash)
        .is_some_and(|last_queried| {
            now.saturating_duration_since(*last_queried) < ED2K_SERVER_UDP_SOURCE_BATCH_COOLDOWN
        })
}

fn was_recently_queried_on_connected_server(
    state: &CoreState,
    file_hash: &str,
    now: Instant,
) -> bool {
    state
        .ed2k_server_source_last_queried
        .get(file_hash)
        .is_some_and(|last_queried| {
            now.saturating_duration_since(*last_queried) < ED2K_CONNECTED_SERVER_SOURCE_COOLDOWN
        })
}

fn is_server_source_batch_transfer_candidate(transfer: &Transfer) -> bool {
    !matches!(
        transfer.state.as_str(),
        "completed" | "completing" | "paused" | "stopped" | "hashing"
    )
}

fn is_ed2k_udp_source_batch_transfer_candidate(transfer: &Transfer) -> bool {
    !matches!(
        transfer.state.as_str(),
        "completed" | "completing" | "paused" | "stopped" | "hashing"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use super::*;
    use crate::{
        CoreState, default_core_settings, download_source_registry::DownloadSourceRegistry,
    };

    #[test]
    fn claim_batches_current_and_other_active_scarce_transfers_once() {
        let now = Instant::now();
        let current_hash = Ed2kHash::from_bytes([0x11; 16]);
        let other_hash = Ed2kHash::from_bytes([0x22; 16]);
        let current = transfer(current_hash, "downloading", 1024);
        let other = transfer(other_hash, "queued", 2048);
        let mut state = core_state_with_transfers([current.clone(), other.clone()]);

        let claimed = claim_ed2k_udp_source_batch(&mut state, &current, current_hash, 1, 2, now);

        assert_eq!(claimed.targets.len(), 2);
        assert!(claimed.transfers.contains_key(&current_hash));
        assert!(claimed.transfers.contains_key(&other_hash));

        let repeated = claim_ed2k_udp_source_batch(&mut state, &current, current_hash, 1, 2, now);
        assert!(repeated.targets.is_empty());
    }

    #[test]
    fn claim_skips_terminal_or_rich_transfers() {
        let now = Instant::now();
        let current_hash = Ed2kHash::from_bytes([0x33; 16]);
        let completed_hash = Ed2kHash::from_bytes([0x44; 16]);
        let current = transfer(current_hash, "downloading", 1024);
        let completed = transfer(completed_hash, "completed", 2048);
        let mut state = core_state_with_transfers([current.clone(), completed]);

        let claimed = claim_ed2k_udp_source_batch(&mut state, &current, current_hash, 3, 2, now);

        assert!(claimed.targets.is_empty());
    }

    #[test]
    fn connected_server_source_batch_paces_frames_and_per_file_reasks() {
        let now = Instant::now();
        let current_hash = Ed2kHash::from_bytes([0x55; 16]);
        let other_hash = Ed2kHash::from_bytes([0x66; 16]);
        let current = transfer(current_hash, "downloading", 1024);
        let other = transfer(other_hash, "queued", 2048);
        let mut state = core_state_with_transfers([current.clone(), other.clone()]);

        let first = claim_connected_server_source_batch(&mut state, &current, current_hash, now);
        assert_eq!(first.targets.len(), 2);
        assert!(first.transfers.contains_key(&current_hash));
        assert!(first.transfers.contains_key(&other_hash));

        let frame_blocked = claim_connected_server_source_batch(
            &mut state,
            &current,
            current_hash,
            now + Duration::from_secs(5),
        );
        assert!(frame_blocked.targets.is_empty());

        let per_file_blocked = claim_connected_server_source_batch(
            &mut state,
            &current,
            current_hash,
            now + ED2K_CONNECTED_SERVER_SOURCE_FRAME_INTERVAL + Duration::from_secs(1),
        );
        assert!(per_file_blocked.targets.is_empty());

        let refreshed = claim_connected_server_source_batch(
            &mut state,
            &current,
            current_hash,
            now + ED2K_CONNECTED_SERVER_SOURCE_COOLDOWN + Duration::from_secs(1),
        );
        assert!(
            refreshed
                .targets
                .iter()
                .any(|target| target.file_hash == current_hash)
        );
    }

    #[test]
    fn connected_server_source_batch_limits_frame_to_mfc_size() {
        let now = Instant::now();
        let current_hash = Ed2kHash::from_bytes([0x91; 16]);
        let current = transfer(current_hash, "downloading", 1024);
        let mut transfers = vec![current.clone()];
        for byte in 0x92..0xB0 {
            transfers.push(transfer(Ed2kHash::from_bytes([byte; 16]), "queued", 1024));
        }
        let mut state = core_state_with_transfers(transfers);

        let claimed = claim_connected_server_source_batch(&mut state, &current, current_hash, now);

        assert_eq!(
            claimed.targets.len(),
            ED2K_CONNECTED_SERVER_SOURCE_FRAME_MAX_FILES
        );
    }

    #[test]
    fn kad_source_refresh_uses_mfc_backoff_per_file() {
        let now = Instant::now();
        let current_hash = Ed2kHash::from_bytes([0x77; 16]);
        let other_hash = Ed2kHash::from_bytes([0x88; 16]);
        let current = transfer(current_hash, "downloading", 1024);
        let mut state = core_state_with_transfers([current]);

        assert!(claim_kad_source_refresh(
            &mut state,
            &current_hash.to_string(),
            now
        ));
        assert!(!claim_kad_source_refresh(
            &mut state,
            &current_hash.to_string(),
            now + Duration::from_secs(5 * 60)
        ));
        assert!(claim_kad_source_refresh(
            &mut state,
            &other_hash.to_string(),
            now + Duration::from_secs(5 * 60)
        ));
        assert!(claim_kad_source_refresh(
            &mut state,
            &current_hash.to_string(),
            now + ED2K_KAD_SOURCE_REASK_BASE_COOLDOWN + Duration::from_secs(1)
        ));
        assert!(!claim_kad_source_refresh(
            &mut state,
            &current_hash.to_string(),
            now + ED2K_KAD_SOURCE_REASK_BASE_COOLDOWN + Duration::from_secs(10 * 60)
        ));
        assert!(claim_kad_source_refresh(
            &mut state,
            &current_hash.to_string(),
            now + ED2K_KAD_SOURCE_REASK_BASE_COOLDOWN.saturating_mul(3) + Duration::from_secs(2)
        ));
    }

    fn core_state_with_transfers(transfers: impl IntoIterator<Item = Transfer>) -> CoreState {
        let transfers = transfers
            .into_iter()
            .map(|transfer| (transfer.hash.clone(), transfer))
            .collect();
        CoreState {
            searches: HashMap::new(),
            next_search_id: 1,
            transfers,
            core_settings: default_core_settings(),
            categories: BTreeMap::new(),
            next_category_id: 1,
            friends: BTreeMap::new(),
            servers: HashMap::new(),
            server_overrides: HashMap::new(),
            disabled_servers: HashSet::new(),
            server_fail_counts: HashMap::new(),
            banned_source_clients: HashSet::new(),
            active_download_attempts: HashSet::new(),
            download_cancels: HashMap::new(),
            next_download_cancel_id: 0,
            active_download_peer_endpoints: HashSet::new(),
            download_source_registry: DownloadSourceRegistry::default(),
            ed2k_dead_sources: crate::ed2k_dead_source_list::DeadSourceList::default(),
            ed2k_server_source_last_queried: HashMap::new(),
            ed2k_server_source_last_frame_at: None,
            ed2k_udp_source_batch_last_queried: HashMap::new(),
            ed2k_kad_source_last_queried: HashMap::new(),
            ed2k_kad_callback_last_sent: HashMap::new(),
            ed2k_server_callback_last_sent: HashMap::new(),
            ed2k_direct_callback_last_sent: HashMap::new(),
            shared_directories: Vec::new(),
            unshared_hashes: HashSet::new(),
            monitor_shared_hashes: HashMap::new(),
            kad_running: false,
            last_source_count_emit_at: None,
        }
    }

    fn transfer(file_hash: Ed2kHash, state: &str, size_bytes: u64) -> Transfer {
        Transfer {
            hash: file_hash.to_string(),
            name: "Sample File.bin".to_string(),
            path: String::new(),
            delivered_path: None,
            size_bytes,
            completed_bytes: 0,
            state: state.to_string(),
            progress: 0.0,
            sources: 0,
            sources_transferring: 0,
            download_speed_ki_bps: 0.0,
            upload_speed_ki_bps: 0.0,
            stopped: false,
            ed2k_link: String::new(),
            priority: "normal".to_string(),
            category_id: 0,
            category_name: String::new(),
            eta: None,
            added_at: None,
            completed_at: None,
            parts_total: 1,
            parts_obtained: 0,
            parts_progress_text: "0".to_string(),
            parts_available: 0,
            auto_priority: false,
            in_incoming: false,
        }
    }
}
