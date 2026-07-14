use std::str::FromStr;

use emulebb_kad_proto::Ed2kHash;

use super::*;
use crate::{HashType, PopularHash};

#[test]
fn shared_entry_from_popular_hash_requires_valid_ed2k_hash() {
    let popular = PopularHash {
        hash: HashType::Ed2k("not-a-real-hash".to_string()),
        display_name: "bad.bin".to_string(),
        size: 1,
        source_count: 1,
    };
    assert!(crate::ed2k_transfer::Ed2kSharedEntry::from_popular_hash(&popular).is_none());
}

#[test]
fn manifest_new_initializes_missing_piece_state() {
    let file_hash = Ed2kHash::from_str("fedcba9876543210fedcba9876543210").unwrap();
    let job = new_transfer_job(file_hash, "ubuntu.iso".to_string(), ED2K_PART_SIZE * 2);
    let manifest = Ed2kResumeManifest::new(&job);
    assert_eq!(manifest.pieces.len(), 2);
    assert!(
        manifest
            .pieces
            .iter()
            .all(|piece| piece.state == Ed2kTransferState::Missing)
    );
    assert!(manifest.sources.is_empty());
}
