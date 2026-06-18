//! Parity tests for the OP_FILESTATUS / ext-info part count, which carries
//! eMule's `m_iED2KPartCount` (`size / PARTSIZE + 1`, KnownFile.cpp:769) and is
//! one MORE than the data-part count at exact PARTSIZE multiples. The trailing
//! extra part is the zero-length EOF slice eMule always treats complete
//! (`CPartFile::IsCompleteBD` clamps `end` to `file_size - 1`, so `start > end`
//! -> the gap scan returns `true`).

use crate::ed2k_transfer::{
    ED2K_PART_SIZE, Ed2kPieceState, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSharedRange,
    Ed2kTransferState, ed2k_part_count,
};

/// Decode an OP_FILESTATUS body (u16 ED2K part count + LSB-first bits) back into
/// a per-part complete bitmap, mirroring the on-wire decode in
/// `ed2k_tcp::codec::file_status`.
fn decode_status_body(body: &[u8]) -> (u16, Vec<bool>) {
    let part_count = u16::from_le_bytes([body[0], body[1]]);
    let bitfield = &body[2..];
    let bitmap = (0..usize::from(part_count))
        .map(|index| (bitfield[index / 8] >> (index % 8)) & 1 == 1)
        .collect();
    (part_count, bitmap)
}

fn manifest(file_size: u64, completed: bool, ranges: Vec<Ed2kSharedRange>) -> Ed2kResumeManifest {
    // One data piece per data part, verified exactly where the verified ranges
    // cover it, so `from_manifest` derives `complete_parts` via the production
    // path. The trailing ED2K extra part has no piece (handled as EOF slice).
    let data_parts = file_size.div_ceil(ED2K_PART_SIZE);
    let pieces = (0..data_parts)
        .map(|part| {
            let start = part * ED2K_PART_SIZE;
            let end = (start + ED2K_PART_SIZE).min(file_size);
            let verified = ranges.iter().any(|r| r.start <= start && end <= r.end);
            Ed2kPieceState {
                piece_index: u32::try_from(part).unwrap(),
                state: if verified {
                    Ed2kTransferState::Verified
                } else {
                    Ed2kTransferState::Missing
                },
                bytes_written: if verified { end - start } else { 0 },
                block_bitmap: None,
            }
        })
        .collect();
    Ed2kResumeManifest {
        file_hash: "0".repeat(32),
        canonical_name: "f".to_string(),
        file_size,
        piece_size: ED2K_PART_SIZE,
        completed,
        md4_hashset_acquired: false,
        md4_hashset: Vec::new(),
        aich_hashset_acquired: false,
        aich_root: None,
        aich_hashset: Vec::new(),
        verified_ranges: ranges,
        pieces,
        sources: Vec::new(),
        upload_priority: "auto".to_string(),
        auto_upload_priority: true,
        comment: String::new(),
        rating: 0,
        category_id: 0,
        control_state: None,
        transfer_row_removed: false,
    }
}

fn entry_with_ranges(file_size: u64, ranges: Vec<Ed2kSharedRange>) -> Ed2kSharedEntry {
    Ed2kSharedEntry::from_manifest(&manifest(file_size, false, ranges))
}

#[test]
fn ed2k_part_count_matches_known_file_table() {
    // KnownFile.cpp:749-755 documented table (ED2K parts column).
    assert_eq!(ed2k_part_count(0), 0);
    assert_eq!(ed2k_part_count(1), 1);
    assert_eq!(ed2k_part_count(ED2K_PART_SIZE - 1), 1);
    assert_eq!(ed2k_part_count(ED2K_PART_SIZE), 2); // PARTSIZE -> 2 (!)
    assert_eq!(ed2k_part_count(ED2K_PART_SIZE + 1), 2);
    assert_eq!(ed2k_part_count(ED2K_PART_SIZE * 2), 3); // PARTSIZE*2 -> 3 (!)
    assert_eq!(ed2k_part_count(ED2K_PART_SIZE * 2 + 1), 3);
}

#[test]
fn exact_multiple_partfile_emits_ed2k_part_count_with_complete_trailing_part() {
    let file_size = ED2K_PART_SIZE * 2; // exact multiple
    assert_eq!(ed2k_part_count(file_size), 3, "ED2K parts = data parts + 1");

    // Both data parts verified, plus the trailing EOF extra part.
    let entry = entry_with_ranges(
        file_size,
        vec![Ed2kSharedRange {
            start: 0,
            end: file_size,
        }],
    );
    assert_eq!(
        entry.complete_parts.len(),
        3,
        "catalog vector must size to the ED2K part count, not the data-part count"
    );
    assert!(entry.complete_parts.iter().all(|c| *c));

    let body = entry.encode_part_status_body();
    let (decoded_count, decoded_bits) = decode_status_body(&body);
    assert_eq!(decoded_count, 3);
    assert_eq!(decoded_bits, vec![true, true, true]);
}

#[test]
fn exact_multiple_partfile_trailing_part_complete_even_with_one_data_part_missing() {
    let file_size = ED2K_PART_SIZE * 2;
    // Only the first data part verified; the second data part is missing but the
    // trailing EOF extra part is still complete (zero-length slice).
    let entry = entry_with_ranges(
        file_size,
        vec![Ed2kSharedRange {
            start: 0,
            end: ED2K_PART_SIZE,
        }],
    );
    let (count, bits) = decode_status_body(&entry.encode_part_status_body());
    assert_eq!(count, 3);
    assert_eq!(bits, vec![true, false, true]);
}

#[test]
fn non_multiple_partfile_counts_coincide() {
    // 2*PARTSIZE+1: data parts = 3, ED2K parts = 3 (counts coincide).
    let file_size = ED2K_PART_SIZE * 2 + 1;
    assert_eq!(ed2k_part_count(file_size), 3);
    let entry = entry_with_ranges(
        file_size,
        vec![Ed2kSharedRange {
            start: 0,
            end: file_size,
        }],
    );
    assert_eq!(entry.complete_parts.len(), 3);
    let (count, bits) = decode_status_body(&entry.encode_part_status_body());
    assert_eq!(count, 3);
    assert_eq!(bits, vec![true, true, true]);
}

#[test]
fn complete_file_collapses_to_sentinel() {
    let file_size = ED2K_PART_SIZE * 2;
    let entry = Ed2kSharedEntry::from_manifest(&manifest(
        file_size,
        true,
        vec![Ed2kSharedRange {
            start: 0,
            end: file_size,
        }],
    ));
    assert!(entry.complete_parts.is_empty());
    // Complete file -> WriteUInt16(0) sentinel, no per-part bits.
    assert_eq!(entry.encode_part_status_body(), 0u16.to_le_bytes().to_vec());
}
