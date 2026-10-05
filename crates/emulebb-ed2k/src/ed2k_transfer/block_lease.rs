//! Process-local download block reservations.
//!
//! The resume manifest records durable bytes only. Network ownership lives in
//! this registry so a crash, cancellation, or failed teardown cannot strand a
//! persisted `Requested` state. Multiple peers may reserve distinct eMule
//! blocks from the same part.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::Result;

use super::{Ed2kTransferRuntime, Ed2kTransferState};

type BlockKey = (u32, u64, u64);

#[derive(Debug, Clone)]
struct BlockLeaseOwner {
    lease_id: u64,
    peer_addr: SocketAddr,
    leased_at: Instant,
    transferred_bytes: u64,
    peer_rate_bytes_per_sec: u32,
}

const LATE_FILE_PERMILLE: u64 = 900;
const ENDGAME_FILE_PERMILLE: u64 = 999;
const ENDGAME_RATE_WINDOW: Duration = Duration::from_secs(30);
const ENDGAME_STEAL_WAIT: Duration = Duration::from_secs(15);
const ENDGAME_FASTER_MULTIPLIER: u64 = 5;
const ENDGAME_STEAL_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
struct LeaseRegistryState {
    files: HashMap<String, HashMap<BlockKey, BlockLeaseOwner>>,
    last_steal: HashMap<String, Instant>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct DownloadBlockLeaseRegistry(Arc<StdMutex<LeaseRegistryState>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EndgamePolicy {
    late: bool,
    endgame: bool,
}

#[derive(Debug, Clone, Copy)]
struct LeaseRequest {
    peer_addr: SocketAddr,
    peer_rate_bytes_per_sec: u32,
    policy: EndgamePolicy,
    allow_takeover: bool,
}

fn endgame_policy(file_size: u64, present_bytes: u64, aggregate_rate: u64) -> EndgamePolicy {
    if file_size == 0 {
        return EndgamePolicy {
            late: true,
            endgame: true,
        };
    }
    let present = present_bytes.min(file_size);
    let remaining = file_size - present;
    let permille = u128::from(present) * 1_000 / u128::from(file_size);
    let rate_window_bytes = aggregate_rate.saturating_mul(ENDGAME_RATE_WINDOW.as_secs());
    EndgamePolicy {
        late: permille >= u128::from(LATE_FILE_PERMILLE),
        endgame: permille >= u128::from(ENDGAME_FILE_PERMILLE)
            || (aggregate_rate > 0 && remaining <= rate_window_bytes),
    }
}

fn may_steal_lease(
    policy: EndgamePolicy,
    owner: &BlockLeaseOwner,
    requester: SocketAddr,
    requester_rate: u32,
    now: Instant,
    last_steal: Option<Instant>,
) -> bool {
    policy.late
        && policy.endgame
        && owner.peer_addr != requester
        && owner.transferred_bytes == 0
        && now.duration_since(owner.leased_at) >= ENDGAME_STEAL_WAIT
        && owner.peer_rate_bytes_per_sec > 0
        && u64::from(requester_rate)
            >= u64::from(owner.peer_rate_bytes_per_sec).saturating_mul(ENDGAME_FASTER_MULTIPLIER)
        && last_steal.is_none_or(|last| now.duration_since(last) >= ENDGAME_STEAL_COOLDOWN)
}

/// One live reservation for an absolute eMule block range.
///
/// Clones share one token. The reservation is removed when the final clone is
/// dropped, including when an async download task is cancelled.
#[derive(Debug, Clone)]
pub(crate) struct Ed2kDownloadBlockLease {
    token: Arc<BlockLeaseToken>,
}

#[derive(Debug)]
struct BlockLeaseToken {
    registry: DownloadBlockLeaseRegistry,
    file_hash: String,
    piece_index: u32,
    start: u64,
    end: u64,
    lease_id: u64,
}

impl Drop for BlockLeaseToken {
    fn drop(&mut self) {
        let mut registry = self.registry.0.lock().unwrap();
        let remove_file = if let Some(file) = registry.files.get_mut(&self.file_hash) {
            let key = (self.piece_index, self.start, self.end);
            if file
                .get(&key)
                .is_some_and(|owner| owner.lease_id == self.lease_id)
            {
                file.remove(&key);
            }
            file.is_empty()
        } else {
            false
        };
        if remove_file {
            registry.files.remove(&self.file_hash);
        }
    }
}

impl PartialEq for Ed2kDownloadBlockLease {
    fn eq(&self, other: &Self) -> bool {
        self.token.lease_id == other.token.lease_id
            && self.token.file_hash == other.token.file_hash
            && self.token.start == other.token.start
            && self.token.end == other.token.end
    }
}

impl Eq for Ed2kDownloadBlockLease {}

impl Ed2kDownloadBlockLease {
    #[must_use]
    pub(crate) fn piece_index(&self) -> u32 {
        self.token.piece_index
    }

    #[must_use]
    pub(crate) fn start(&self) -> u64 {
        self.token.start
    }

    #[must_use]
    pub(crate) fn end(&self) -> u64 {
        self.token.end
    }

    /// Mark useful payload against this lease. Endgame stealing is restricted
    /// to reservations which have not delivered a byte.
    pub(crate) fn note_payload(&self, bytes: u64) {
        let mut registry = self.token.registry.0.lock().unwrap();
        let key = (self.token.piece_index, self.token.start, self.token.end);
        let Some(owner) = registry
            .files
            .get_mut(&self.token.file_hash)
            .and_then(|file| file.get_mut(&key))
        else {
            return;
        };
        if owner.lease_id == self.token.lease_id {
            owner.transferred_bytes = owner.transferred_bytes.saturating_add(bytes);
        }
    }
}

impl Ed2kTransferRuntime {
    /// Reserve the next missing, currently-unleased eMule block for a peer.
    /// `preferred_piece` keeps a productive source in its current part when
    /// possible; the normal rarest/preview/completion picker chooses otherwise.
    pub(crate) async fn lease_next_download_block(
        &self,
        file_hash: &str,
        peer_addr: SocketAddr,
        peer_bitmap: Option<&[bool]>,
        preferred_piece: Option<u32>,
        peer_rate_bytes_per_sec: u32,
    ) -> Result<Option<Ed2kDownloadBlockLease>> {
        let _guard = self.lock_manifest(file_hash).await;
        let manifest = self.load_manifest_unlocked(file_hash).await?;
        let policy = endgame_policy(
            manifest.file_size,
            manifest.durable_present_bytes(),
            self.download_speed_bytes_per_sec(file_hash),
        );
        let part_total = manifest.pieces.len();
        let frequencies = self
            .available_sources_per_part(file_hash, u32::try_from(part_total).unwrap_or(u32::MAX));
        let mut eligible = peer_bitmap.map_or_else(
            || vec![true; part_total],
            |bitmap| {
                (0..part_total)
                    .map(|index| bitmap.get(index).copied().unwrap_or(false))
                    .collect()
            },
        );
        let takeover_eligible = eligible.clone();

        if let Some(piece_index) = preferred_piece
            && eligible
                .get(usize::try_from(piece_index).unwrap_or(usize::MAX))
                .copied()
                .unwrap_or(false)
            && let Some(lease) = self.try_lease_block_in_piece(
                &manifest,
                file_hash,
                piece_index,
                LeaseRequest {
                    peer_addr,
                    peer_rate_bytes_per_sec,
                    policy,
                    allow_takeover: false,
                },
            )
        {
            return Ok(Some(lease));
        }

        while let Some(piece_index) = super::download_pick::pick_next_missing_part(
            &manifest.pieces,
            manifest.file_size,
            manifest.piece_size,
            Some(&eligible),
            &frequencies,
        ) {
            if let Some(lease) = self.try_lease_block_in_piece(
                &manifest,
                file_hash,
                piece_index,
                LeaseRequest {
                    peer_addr,
                    peer_rate_bytes_per_sec,
                    policy,
                    allow_takeover: false,
                },
            ) {
                return Ok(Some(lease));
            }
            if let Some(slot) = eligible.get_mut(usize::try_from(piece_index).unwrap_or(usize::MAX))
            {
                *slot = false;
            } else {
                break;
            }
        }

        // Only duplicate an already-leased range after every ordinary gap the
        // peer can serve has been considered. This keeps endgame recovery from
        // wasting bandwidth while any unreserved work remains elsewhere.
        let mut eligible = takeover_eligible;
        while let Some(piece_index) = super::download_pick::pick_next_missing_part(
            &manifest.pieces,
            manifest.file_size,
            manifest.piece_size,
            Some(&eligible),
            &frequencies,
        ) {
            if let Some(lease) = self.try_lease_block_in_piece(
                &manifest,
                file_hash,
                piece_index,
                LeaseRequest {
                    peer_addr,
                    peer_rate_bytes_per_sec,
                    policy,
                    allow_takeover: true,
                },
            ) {
                return Ok(Some(lease));
            }
            if let Some(slot) = eligible.get_mut(usize::try_from(piece_index).unwrap_or(usize::MAX))
            {
                *slot = false;
            } else {
                return Ok(None);
            }
        }
        Ok(None)
    }

    fn try_lease_block_in_piece(
        &self,
        manifest: &super::Ed2kResumeManifest,
        file_hash: &str,
        piece_index: u32,
        request: LeaseRequest,
    ) -> Option<Ed2kDownloadBlockLease> {
        let piece = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == piece_index)?;
        if piece.state == Ed2kTransferState::Verified {
            return None;
        }
        let piece_start = u64::from(piece_index) * manifest.piece_size;
        let piece_end = (piece_start + manifest.piece_size).min(manifest.file_size);
        let part_len = piece_end.saturating_sub(piece_start);
        let bitmap = piece.resolve_block_bitmap(part_len);
        let mut registry = self.download_block_leases.0.lock().unwrap();
        let now = Instant::now();
        registry
            .last_steal
            .retain(|_, last| now.duration_since(*last) < ENDGAME_STEAL_COOLDOWN);
        let normalized_hash = file_hash.to_ascii_lowercase();
        let last_steal = registry.last_steal.get(&normalized_hash).copied();
        let file = registry.files.entry(normalized_hash.clone()).or_default();
        for block_index in 0..bitmap.block_count() {
            if bitmap.is_present(block_index) {
                continue;
            }
            let (relative_start, relative_end) = bitmap.block_range(block_index);
            // A checkpoint may retain a sub-block contiguous prefix even
            // though the persisted block bitmap only marks whole blocks.
            // Resume at that exact byte rather than re-requesting and
            // re-accounting the already durable prefix.
            let relative_start = relative_start.max(piece.bytes_written.min(relative_end));
            if relative_start >= relative_end {
                continue;
            }
            let start = piece_start + relative_start;
            let end = piece_start + relative_end;
            let key = (piece_index, start, end);
            if file.contains_key(&key) {
                continue;
            }
            let lease_id = self
                .next_download_block_lease_id
                .fetch_add(1, Ordering::Relaxed);
            file.insert(
                key,
                BlockLeaseOwner {
                    lease_id,
                    peer_addr: request.peer_addr,
                    leased_at: now,
                    transferred_bytes: 0,
                    peer_rate_bytes_per_sec: request.peer_rate_bytes_per_sec,
                },
            );
            return Some(Ed2kDownloadBlockLease {
                token: Arc::new(BlockLeaseToken {
                    registry: self.download_block_leases.clone(),
                    file_hash: file_hash.to_ascii_lowercase(),
                    piece_index,
                    start,
                    end,
                    lease_id,
                }),
            });
        }

        // MFC-style endgame takeover: once only leased gaps remain, a measured
        // peer at least five times faster may duplicate a request that has
        // produced no payload for 15 seconds. One takeover per file per minute
        // prevents fast-peer churn; an old token cannot release the new owner.
        if !request.allow_takeover {
            return None;
        }
        let candidate = file.iter().find_map(|(&key, owner)| {
            (key.0 == piece_index
                && may_steal_lease(
                    request.policy,
                    owner,
                    request.peer_addr,
                    request.peer_rate_bytes_per_sec,
                    now,
                    last_steal,
                ))
            .then_some((key, owner.clone()))
        });
        if let Some((key @ (piece_index, start, end), previous)) = candidate {
            let lease_id = self
                .next_download_block_lease_id
                .fetch_add(1, Ordering::Relaxed);
            file.insert(
                key,
                BlockLeaseOwner {
                    lease_id,
                    peer_addr: request.peer_addr,
                    leased_at: now,
                    transferred_bytes: 0,
                    peer_rate_bytes_per_sec: request.peer_rate_bytes_per_sec,
                },
            );
            registry.last_steal.insert(normalized_hash.clone(), now);
            tracing::debug!(
                file_hash = %normalized_hash,
                piece_index,
                start,
                end,
                old_peer = %previous.peer_addr,
                new_peer = %request.peer_addr,
                old_rate = previous.peer_rate_bytes_per_sec,
                new_rate = request.peer_rate_bytes_per_sec,
                "endgame block lease taken over by faster peer"
            );
            return Some(Ed2kDownloadBlockLease {
                token: Arc::new(BlockLeaseToken {
                    registry: self.download_block_leases.clone(),
                    file_hash: normalized_hash,
                    piece_index,
                    start,
                    end,
                    lease_id,
                }),
            });
        }
        None
    }

    /// Parts with at least one live block reservation, used by transfer details.
    #[must_use]
    pub fn requested_download_parts(&self, file_hash: &str) -> HashSet<u32> {
        self.download_block_leases
            .0
            .lock()
            .unwrap()
            .files
            .get(&file_hash.to_ascii_lowercase())
            .map(|file| file.keys().map(|(piece, _, _)| *piece).collect())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(super) fn active_download_block_lease_count(&self, file_hash: &str) -> usize {
        self.download_block_leases
            .0
            .lock()
            .unwrap()
            .files
            .get(&file_hash.to_ascii_lowercase())
            .map_or(0, HashMap::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(now: Instant, age: Duration, rate: u32, transferred_bytes: u64) -> BlockLeaseOwner {
        BlockLeaseOwner {
            lease_id: 1,
            peer_addr: "127.0.0.1:4662".parse().unwrap(),
            leased_at: now - age,
            transferred_bytes,
            peer_rate_bytes_per_sec: rate,
        }
    }

    #[test]
    fn endgame_uses_fixed_or_thirty_second_rate_threshold() {
        assert!(!endgame_policy(1_000_000, 899_999, 0).late);
        assert!(endgame_policy(1_000_000, 900_000, 0).late);
        assert!(!endgame_policy(1_000_000, 998_999, 0).endgame);
        assert!(endgame_policy(1_000_000, 999_000, 0).endgame);
        assert!(endgame_policy(1_000_000, 970_000, 1_000).endgame);
        assert!(!endgame_policy(1_000_000, 969_999, 1_000).endgame);
    }

    #[test]
    fn takeover_requires_endgame_wait_five_x_zero_progress_and_cooldown() {
        let now = Instant::now();
        let requester = "127.0.0.2:4662".parse().unwrap();
        let policy = EndgamePolicy {
            late: true,
            endgame: true,
        };
        let ready = owner(now, ENDGAME_STEAL_WAIT, 100, 0);
        assert!(may_steal_lease(policy, &ready, requester, 500, now, None));
        assert!(!may_steal_lease(
            policy,
            &owner(now, ENDGAME_STEAL_WAIT - Duration::from_millis(1), 100, 0),
            requester,
            500,
            now,
            None
        ));
        assert!(!may_steal_lease(
            policy,
            &owner(now, ENDGAME_STEAL_WAIT, 100, 1),
            requester,
            500,
            now,
            None
        ));
        assert!(!may_steal_lease(policy, &ready, requester, 499, now, None));
        assert!(!may_steal_lease(
            policy,
            &ready,
            requester,
            500,
            now,
            Some(now - ENDGAME_STEAL_COOLDOWN + Duration::from_millis(1))
        ));
    }
}
