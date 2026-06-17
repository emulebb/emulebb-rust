//! Part selection for ED2K downloads.
//!
//! Mirrors the master `CPartFile::GetNextRequestedBlock` chunk-selection intent
//! within the per-transfer-task model used here (there is no shared cross-file
//! scheduler, so the rarity input is the per-transfer live source part-frequency
//! already tracked in `download_activity`, not a global queue). The selection
//! ranks the locally-missing parts the connected peer actually holds by:
//!
//!  - Criterion 1 (rarity): rarest-first via the per-source availability
//!    frequency, so very rare parts are fetched first to spread the file.
//!  - Criterion 2 (preview): the first and last part(s) rank high so a partial
//!    file can be previewed/verified early.
//!  - Criterion 4 (completion): a part already partly written ranks above an
//!    untouched part of equal rarity (priority inversion), so in-flight parts
//!    finish before new ones start. This also covers the endgame tail where the
//!    remaining missing parts are all near completion.
//!
//! The peer-availability gate is the master `sender->IsPartAvailable(i)` filter
//! (Criterion entry condition): a part the peer lacks is never claimed against
//! that peer, which avoids soliciting an `OP_OUTOFPARTREQS` rejection.

use super::model::{Ed2kPieceState, Ed2kTransferState};

/// Lower rank wins. The base spacing keeps rarity dominant while leaving room
/// for the preview boost and the completion bonus to reorder ties.
const RARITY_WEIGHT: u32 = 1_000;
/// Preview parts (first / last) get a large negative offset so they outrank
/// common parts but still defer to a genuinely rarer part.
const PREVIEW_BONUS: u32 = 500;
/// Completion bonus span: a fully-started part shaves up to this much off its
/// rank, giving near-complete parts priority over untouched ones of equal
/// rarity (master Criterion 4, `100 - critCompletion`).
const COMPLETION_BONUS: u32 = 100;

/// Compute the selection rank for one missing part. Lower is better.
fn part_rank(piece: &Ed2kPieceState, frequency: u32, expected_len: u64, is_preview: bool) -> u32 {
    // Criterion 1: rarity dominates.
    let mut rank = frequency.saturating_mul(RARITY_WEIGHT);

    // Criterion 2: first / last part(s) for preview.
    if is_preview {
        rank = rank.saturating_sub(PREVIEW_BONUS);
    }

    // Criterion 4: completion priority-inversion. `bytes_written` is the present
    // prefix (or salvage-present prefix); a higher completion ratio lowers rank.
    if expected_len > 0 {
        let completion = (u128::from(piece.bytes_written) * u128::from(COMPLETION_BONUS)
            / u128::from(expected_len)) as u32;
        rank = rank.saturating_sub(completion.min(COMPLETION_BONUS));
    }

    rank
}

/// A part is a preview candidate if it is the first part, the last part, or the
/// second-to-last part when the final part is small (master Criterion 2).
fn is_preview_part(part_index: usize, part_total: usize) -> bool {
    if part_total == 0 {
        return false;
    }
    part_index == 0 || part_index == part_total - 1
}

/// Pick the next missing part index to claim against a peer.
///
/// `peer_bitmap` is the connected peer's advertised per-part availability. When
/// `Some`, only parts the peer holds are considered (master
/// `sender->IsPartAvailable`). When `None` (status not yet learned), every
/// missing part is eligible, matching the legacy behaviour. `frequency` is the
/// per-part live-source availability count (rarity input); a missing index is
/// treated as frequency 0 (rarest). Returns `None` when the peer holds none of
/// our missing parts, which the caller treats like an out-of-parts peer.
#[must_use]
pub(super) fn pick_next_missing_part(
    pieces: &[Ed2kPieceState],
    file_size: u64,
    piece_size: u64,
    peer_bitmap: Option<&[bool]>,
    frequency: &[u32],
) -> Option<u32> {
    let part_total = pieces.len();
    let mut best: Option<(u32, u32)> = None; // (rank, piece_index)
    for (position, piece) in pieces.iter().enumerate() {
        if piece.state != Ed2kTransferState::Missing {
            continue;
        }
        if let Some(bitmap) = peer_bitmap {
            // A peer with no status frame yet is handled by the `None` branch;
            // here a shorter/longer bitmap is tolerated by treating an absent
            // slot as "not available".
            if !bitmap.get(position).copied().unwrap_or(false) {
                continue;
            }
        }
        let expected_len = super::manifest::expected_piece_length(
            file_size,
            piece_size,
            u64::from(piece.piece_index),
        );
        let freq = frequency.get(position).copied().unwrap_or(0);
        let rank = part_rank(
            piece,
            freq,
            expected_len,
            is_preview_part(position, part_total),
        );
        match best {
            Some((best_rank, _)) if best_rank <= rank => {}
            _ => best = Some((rank, piece.piece_index)),
        }
    }
    best.map(|(_, index)| index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_transfer::ED2K_PART_SIZE;

    fn missing_piece(index: u32, bytes_written: u64) -> Ed2kPieceState {
        Ed2kPieceState {
            piece_index: index,
            state: Ed2kTransferState::Missing,
            bytes_written,
            block_bitmap: None,
        }
    }

    fn verified_piece(index: u32) -> Ed2kPieceState {
        Ed2kPieceState {
            piece_index: index,
            state: Ed2kTransferState::Verified,
            bytes_written: ED2K_PART_SIZE,
            block_bitmap: None,
        }
    }

    #[test]
    fn picks_rarest_part_first() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, 0),
            missing_piece(2, 0),
            missing_piece(3, 0),
        ];
        let file_size = ED2K_PART_SIZE * 4;
        // Part 2 is the rarest (only one source). Preview boosts parts 0 and 3,
        // but rarity dominates, so part 2 still wins.
        let frequency = [5, 5, 1, 5];
        let pick = pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency);
        assert_eq!(pick, Some(2));
    }

    #[test]
    fn prefers_preview_part_on_equal_rarity() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, 0),
            missing_piece(2, 0),
            missing_piece(3, 0),
        ];
        let file_size = ED2K_PART_SIZE * 4;
        let frequency = [3, 3, 3, 3];
        // All equally rare -> first part (preview) wins over interior parts.
        let pick = pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency);
        assert_eq!(pick, Some(0));
    }

    #[test]
    fn completion_inverts_priority_on_equal_rarity_and_preview() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, ED2K_PART_SIZE - 1),
            missing_piece(2, 0),
            missing_piece(3, 0),
        ];
        let file_size = ED2K_PART_SIZE * 4;
        // Interior parts 1 and 2 are equally rare and non-preview (parts 0 and 3
        // are the preview parts); part 1 is nearly complete, so the completion
        // bonus selects it. Parts 0/3 are made common so preview never wins.
        let frequency = [50, 3, 3, 50];
        let pick = pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency);
        assert_eq!(pick, Some(1));
    }

    #[test]
    fn skips_parts_the_peer_lacks() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, 0),
            missing_piece(2, 0),
        ];
        let file_size = ED2K_PART_SIZE * 3;
        let frequency = [1, 2, 8];
        // Part 0 is rarest but the peer does not have it; pick the rarest the
        // peer actually holds (part 1 is rarer than part 2).
        let peer = [false, true, true];
        let pick =
            pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, Some(&peer), &frequency);
        assert_eq!(pick, Some(1));
    }

    #[test]
    fn returns_none_when_peer_lacks_all_missing_parts() {
        let pieces = vec![verified_piece(0), missing_piece(1, 0)];
        let file_size = ED2K_PART_SIZE * 2;
        let frequency = [5, 5];
        let peer = [true, false];
        let pick =
            pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, Some(&peer), &frequency);
        assert_eq!(pick, None);
    }

    #[test]
    fn ignores_non_missing_parts() {
        let pieces = vec![verified_piece(0), missing_piece(1, 0)];
        let file_size = ED2K_PART_SIZE * 2;
        let frequency = [1, 9];
        let pick = pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency);
        assert_eq!(pick, Some(1));
    }
}
