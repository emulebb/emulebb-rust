use anyhow::Result;
use emulebb_metadata::{
    MetadataTransferManifest, MetadataTransferPiece, MetadataTransferRange, MetadataTransferSource,
};

use super::{
    Ed2kPieceState, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSharedRange, Ed2kSourceHint,
    Ed2kTransferState,
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
        control_state: manifest.control_state.clone(),
        transfer_row_removed: manifest.transfer_row_removed,
    }
}

pub(super) fn manifest_from_metadata(
    manifest: MetadataTransferManifest,
) -> Result<Ed2kResumeManifest> {
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
        control_state: manifest.control_state,
        transfer_row_removed: manifest.transfer_row_removed,
    })
}

pub(super) fn completed_catalog_from_metadata(
    manifests: Vec<MetadataTransferManifest>,
) -> Result<Vec<Ed2kSharedEntry>> {
    manifests
        .into_iter()
        .filter(|manifest| manifest.completed)
        .map(manifest_from_metadata)
        .map(|manifest| manifest.map(|manifest| Ed2kSharedEntry::from_manifest(&manifest)))
        .collect()
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
