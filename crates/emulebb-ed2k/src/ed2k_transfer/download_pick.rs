//! Select useful missing parts by observed scarcity, then finish started work.
//!
//! Frequencies come from the shared live-source tracker. Unknown frequency does
//! not establish rarity. A preferred in-flight part participates in the same
//! ordering rather than bypassing a rarer opportunity.

use super::model::{Ed2kPieceState, Ed2kTransferState};

type PartRank = (u32, bool, u64);

/// Lower rank wins: measured scarcity, started work, then bytes to finish it.
fn part_rank(
    piece: &Ed2kPieceState,
    frequency: u32,
    expected_len: u64,
    preferred: bool,
) -> PartRank {
    let measured = if frequency == 0 { u32::MAX } else { frequency };
    let started = piece.bytes_written > 0 || preferred;
    (
        measured,
        !started,
        if started {
            expected_len.saturating_sub(piece.bytes_written)
        } else {
            0
        },
    )
}

/// Pick only data the peer can serve. Without a status bitmap, missing parts
/// remain eligible but receive no inferred rarity. Verified and empty protocol
/// slices never become payload requests. Equal ranks retain stable part order.
#[must_use]
pub(super) fn pick_next_missing_part(
    pieces: &[Ed2kPieceState],
    file_size: u64,
    piece_size: u64,
    peer_bitmap: Option<&[bool]>,
    frequency: &[u32],
    preferred_piece: Option<u32>,
) -> Option<u32> {
    let mut best: Option<(PartRank, u32)> = None;
    for (position, piece) in pieces.iter().enumerate() {
        if piece.state == Ed2kTransferState::Verified {
            continue;
        }
        if peer_bitmap.is_some_and(|bitmap| !bitmap.get(position).copied().unwrap_or(false)) {
            continue;
        }
        let expected_len = super::manifest::expected_piece_length(
            file_size,
            piece_size,
            u64::from(piece.piece_index),
        );
        if expected_len == 0 {
            continue;
        }
        let rank = part_rank(
            piece,
            frequency.get(position).copied().unwrap_or(0),
            expected_len,
            preferred_piece == Some(piece.piece_index),
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
            ich_corrupted: false,
        }
    }

    fn verified_piece(index: u32) -> Ed2kPieceState {
        Ed2kPieceState {
            piece_index: index,
            state: Ed2kTransferState::Verified,
            bytes_written: ED2K_PART_SIZE,
            block_bitmap: None,
            ich_corrupted: false,
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
        // Part 2 is the only part with one observed source.
        let frequency = [5, 5, 1, 5];
        let pick =
            pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency, None);
        assert_eq!(pick, Some(2));
    }

    #[test]
    fn measured_availability_precedes_unknown_frequency() {
        let pieces = vec![missing_piece(0, ED2K_PART_SIZE - 1), missing_piece(1, 0)];
        for frequency in [&[0, 3][..], &[0, 1][..]] {
            assert_eq!(
                pick_next_missing_part(
                    &pieces,
                    ED2K_PART_SIZE * 2,
                    ED2K_PART_SIZE,
                    None,
                    frequency,
                    Some(0)
                ),
                Some(1)
            );
        }
    }

    #[test]
    fn preferred_part_only_wins_among_equally_scarce_work() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, 0),
            missing_piece(2, 0),
        ];
        assert_eq!(
            pick_next_missing_part(
                &pieces,
                ED2K_PART_SIZE * 3,
                ED2K_PART_SIZE,
                None,
                &[3, 1, 3],
                Some(2)
            ),
            Some(1)
        );
        assert_eq!(
            pick_next_missing_part(
                &pieces,
                ED2K_PART_SIZE * 3,
                ED2K_PART_SIZE,
                None,
                &[3; 3],
                Some(2)
            ),
            Some(2)
        );
    }

    #[test]
    fn rare_unstarted_part_precedes_common_nearly_complete_work() {
        let pieces = vec![missing_piece(0, ED2K_PART_SIZE - 1), missing_piece(1, 0)];
        assert_eq!(
            pick_next_missing_part(
                &pieces,
                ED2K_PART_SIZE * 2,
                ED2K_PART_SIZE,
                None,
                &[2, 1],
                Some(0)
            ),
            Some(1)
        );
    }

    #[test]
    fn empty_protocol_slice_is_never_payload_work() {
        let pieces = vec![missing_piece(0, 0), missing_piece(1, 0)];
        assert_eq!(
            pick_next_missing_part(&pieces, ED2K_PART_SIZE, ED2K_PART_SIZE, None, &[], Some(1)),
            Some(0)
        );
    }

    #[test]
    fn untouched_short_tail_does_not_reorder_equally_scarce_parts() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, 0),
            missing_piece(2, 0),
        ];
        assert_eq!(
            pick_next_missing_part(
                &pieces,
                ED2K_PART_SIZE * 2 + 16,
                ED2K_PART_SIZE,
                None,
                &[1; 3],
                None
            ),
            Some(0)
        );
    }

    #[test]
    fn equal_rank_uses_stable_part_order() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, 0),
            missing_piece(2, 0),
            missing_piece(3, 0),
        ];
        let file_size = ED2K_PART_SIZE * 4;
        let frequency = [3, 3, 3, 3];
        // Equal work retains stable order.
        let pick =
            pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency, None);
        assert_eq!(pick, Some(0));
    }

    #[test]
    fn finishes_started_interior_part_before_equally_scarce_untouched_parts() {
        let pieces = vec![
            missing_piece(0, 0),
            missing_piece(1, ED2K_PART_SIZE - 1),
            missing_piece(2, 0),
            missing_piece(3, 0),
        ];
        let file_size = ED2K_PART_SIZE * 4;
        let frequency = [3, 3, 3, 3];
        let pick =
            pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency, None);
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
        let pick = pick_next_missing_part(
            &pieces,
            file_size,
            ED2K_PART_SIZE,
            Some(&peer),
            &frequency,
            None,
        );
        assert_eq!(pick, Some(1));
    }

    #[test]
    fn returns_none_when_peer_lacks_all_missing_parts() {
        let pieces = vec![verified_piece(0), missing_piece(1, 0)];
        let file_size = ED2K_PART_SIZE * 2;
        let frequency = [5, 5];
        let peer = [true, false];
        let pick = pick_next_missing_part(
            &pieces,
            file_size,
            ED2K_PART_SIZE,
            Some(&peer),
            &frequency,
            None,
        );
        assert_eq!(pick, None);
    }

    #[test]
    fn ignores_non_missing_parts() {
        let pieces = vec![verified_piece(0), missing_piece(1, 0)];
        let file_size = ED2K_PART_SIZE * 2;
        let frequency = [1, 9];
        let pick =
            pick_next_missing_part(&pieces, file_size, ED2K_PART_SIZE, None, &frequency, None);
        assert_eq!(pick, Some(1));
    }
}
