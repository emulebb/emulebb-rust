use anyhow::Result;
use emulebb_metadata::{
    MetadataStore, MetadataTransferCatalogEntry, MetadataTransferManifest, MetadataTransferPiece,
    MetadataTransferRange, MetadataTransferSource,
};

use super::{
    Ed2kPieceState, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSharedRange, Ed2kSourceHint,
    Ed2kTransferState, catalog::Ed2kSharedPublishStats,
};

pub(super) fn manifest_to_metadata(manifest: &Ed2kResumeManifest) -> MetadataTransferManifest {
    MetadataTransferManifest {
        file_hash: manifest.file_hash.clone(),
        canonical_name: manifest.canonical_name.clone(),
        file_size: manifest.file_size,
        piece_size: manifest.piece_size,
        completed: manifest.completed,
        md4_hashset_acquired: manifest.md4_hashset_acquired,
        md4_hashset: manifest.md4_hashset.clone(),
        aich_hashset_acquired: manifest.aich_hashset_acquired,
        aich_root: manifest.aich_root.clone(),
        aich_hashset: manifest.aich_hashset.clone(),
        verified_ranges: manifest
            .verified_ranges
            .iter()
            .map(|range| MetadataTransferRange {
                start: range.start,
                end: range.end,
            })
            .collect(),
        pieces: manifest
            .pieces
            .iter()
            .map(|piece| MetadataTransferPiece {
                piece_index: piece.piece_index,
                state: transfer_state_to_sql(piece.state).to_string(),
                bytes_written: piece.bytes_written,
                block_bitmap: piece.block_bitmap.clone(),
                ich_corrupted: piece.ich_corrupted,
            })
            .collect(),
        sources: manifest
            .sources
            .iter()
            .map(|source| MetadataTransferSource {
                ip: source.ip.clone(),
                tcp_port: source.tcp_port,
                user_hash: source.user_hash.clone(),
            })
            .collect(),
        upload_priority: manifest.upload_priority.clone(),
        auto_upload_priority: manifest.auto_upload_priority,
        comment: manifest.comment.clone(),
        rating: manifest.rating,
        category_id: manifest.category_id,
        control_state: manifest.control_state.clone(),
        transfer_row_removed: manifest.transfer_row_removed,
        delivered_path: manifest.delivered_path.clone(),
        source_path: manifest.source_path.clone(),
        source_mtime_ms: manifest.source_mtime_ms,
    }
}

pub(super) fn manifest_from_metadata(
    manifest: MetadataTransferManifest,
) -> Result<Ed2kResumeManifest> {
    // `piece_size` is read straight from the persisted manifest row. A corrupt
    // or hand-edited DB row with piece_size==0 while file_size>0 would later
    // panic with a divide-by-zero in piece_count (file_size.div_ceil(0)).
    // Reject such a row on load so it never reaches the coordinator.
    if manifest.piece_size == 0 && manifest.file_size > 0 {
        anyhow::bail!(
            "invalid persisted manifest for {}: piece_size=0 with file_size={}",
            manifest.file_hash,
            manifest.file_size
        );
    }
    Ok(Ed2kResumeManifest {
        file_hash: manifest.file_hash,
        canonical_name: manifest.canonical_name,
        file_size: manifest.file_size,
        piece_size: manifest.piece_size,
        completed: manifest.completed,
        md4_hashset_acquired: manifest.md4_hashset_acquired,
        md4_hashset: manifest.md4_hashset,
        aich_hashset_acquired: manifest.aich_hashset_acquired,
        aich_root: manifest.aich_root,
        aich_hashset: manifest.aich_hashset,
        verified_ranges: manifest
            .verified_ranges
            .into_iter()
            .map(|range| Ed2kSharedRange {
                start: range.start,
                end: range.end,
            })
            .collect(),
        pieces: manifest
            .pieces
            .into_iter()
            .map(|piece| {
                Ok(Ed2kPieceState {
                    piece_index: piece.piece_index,
                    state: transfer_state_from_sql(&piece.state)?,
                    bytes_written: piece.bytes_written,
                    block_bitmap: piece.block_bitmap,
                    ich_corrupted: piece.ich_corrupted,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        sources: manifest
            .sources
            .into_iter()
            .map(|source| Ed2kSourceHint {
                ip: source.ip,
                tcp_port: source.tcp_port,
                user_hash: source.user_hash,
            })
            .collect(),
        upload_priority: manifest.upload_priority,
        auto_upload_priority: manifest.auto_upload_priority,
        comment: manifest.comment,
        rating: manifest.rating,
        category_id: manifest.category_id,
        control_state: manifest.control_state,
        transfer_row_removed: manifest.transfer_row_removed,
        delivered_path: manifest.delivered_path,
        source_path: manifest.source_path,
        source_mtime_ms: manifest.source_mtime_ms,
    })
}

pub(super) fn completed_catalog_from_metadata_store(
    metadata: &MetadataStore,
) -> Result<Vec<Ed2kSharedEntry>> {
    metadata
        .completed_transfer_catalog_entries()?
        .into_iter()
        .map(shared_entry_from_catalog_entry)
        .collect()
}

fn shared_entry_from_catalog_entry(entry: MetadataTransferCatalogEntry) -> Result<Ed2kSharedEntry> {
    Ok(Ed2kSharedEntry {
        file_hash: entry.file_hash,
        canonical_name: entry.canonical_name,
        file_size: entry.file_size,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: entry.aich_root,
        upload_priority: entry.upload_priority,
        auto_upload_priority: entry.auto_upload_priority,
        comment: entry.comment,
        rating: entry.rating,
        all_time_uploaded_bytes: entry.all_time_uploaded_bytes,
        complete_parts: Vec::new(),
        publish: Ed2kSharedPublishStats {
            all_time_request_count: entry.all_time_upload_requests,
            all_time_accept_count: entry.all_time_upload_accepts,
            last_request_unix_ms: entry.last_upload_request_ms,
            ..Default::default()
        },
    })
}

fn transfer_state_to_sql(state: Ed2kTransferState) -> &'static str {
    match state {
        Ed2kTransferState::Missing => "Missing",
        Ed2kTransferState::Requested => "Requested",
        Ed2kTransferState::Written => "Written",
        Ed2kTransferState::Verified => "Verified",
    }
}

fn transfer_state_from_sql(value: &str) -> Result<Ed2kTransferState> {
    match value {
        "Missing" => Ok(Ed2kTransferState::Missing),
        "Requested" => Ok(Ed2kTransferState::Requested),
        "Written" => Ok(Ed2kTransferState::Written),
        "Verified" => Ok(Ed2kTransferState::Verified),
        _ => anyhow::bail!("unknown ED2K transfer piece state {value:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_row(file_size: u64, piece_size: u64) -> MetadataTransferManifest {
        MetadataTransferManifest {
            file_hash: "00000000000000000000000000000000".to_string(),
            canonical_name: "f.bin".to_string(),
            file_size,
            piece_size,
            completed: false,
            md4_hashset_acquired: false,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: false,
            aich_root: None,
            aich_hashset: Vec::new(),
            verified_ranges: Vec::new(),
            pieces: Vec::new(),
            sources: Vec::new(),
            upload_priority: String::new(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id: 0,
            control_state: None,
            transfer_row_removed: false,
            delivered_path: None,
            source_path: None,
            source_mtime_ms: None,
        }
    }

    #[test]
    fn rejects_zero_piece_size_with_nonzero_file_size() {
        // Corrupt/hand-edited row: piece_size=0, file_size>0. Must be rejected on
        // load so the divide-by-zero in piece_count is never reached.
        let err = manifest_from_metadata(manifest_row(1024, 0)).unwrap_err();
        assert!(
            err.to_string().contains("piece_size=0"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn accepts_zero_piece_size_for_empty_file() {
        // A zero-length file legitimately has no pieces; piece_size==0 there is
        // harmless and must not be rejected.
        let manifest = manifest_from_metadata(manifest_row(0, 0)).expect("empty file loads");
        assert_eq!(manifest.file_size, 0);
    }
}
