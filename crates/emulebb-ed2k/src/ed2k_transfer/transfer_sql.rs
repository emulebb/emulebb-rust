use anyhow::Result;
use emulebb_metadata::{
    MetadataStore, MetadataTransferCatalogEntry, MetadataTransferManifest,
    MetadataTransferMediaMetadata, MetadataTransferPiece, MetadataTransferRange,
    MetadataTransferSource,
};

use super::{
    Ed2kPieceState, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSharedRange, Ed2kSourceHint,
    Ed2kTransferState, catalog::Ed2kSharedPublishStats,
};

pub(super) const MEDIA_METADATA_EXTRACTOR_VERSION: u32 = 1;

pub(super) fn manifest_to_metadata(manifest: &Ed2kResumeManifest) -> MetadataTransferManifest {
    MetadataTransferManifest {
        file_hash: manifest.file_hash.clone(),
        display_name: manifest.display_name.clone(),
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
        pieces: manifest.pieces.iter().map(piece_to_metadata).collect(),
        sources: manifest
            .sources
            .iter()
            .map(|source| MetadataTransferSource {
                ip: source.ip.clone(),
                tcp_port: source.tcp_port,
                user_hash: source.user_hash.clone(),
                connect_options: source.connect_options,
                file_comment: source.file_comment.clone(),
                file_rating: source.file_rating,
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

/// SQL form of one runtime piece state, shared by the full manifest upsert and
/// the per-block single-piece progress checkpoint.
pub(super) fn piece_to_metadata(piece: &Ed2kPieceState) -> MetadataTransferPiece {
    MetadataTransferPiece {
        piece_index: piece.piece_index,
        state: transfer_state_to_sql(piece.state).to_string(),
        bytes_written: piece.bytes_written,
        block_bitmap: piece.block_bitmap.clone(),
        ich_corrupted: piece.ich_corrupted,
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
        display_name: manifest.display_name,
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
                connect_options: source.connect_options,
                file_comment: source.file_comment,
                file_rating: source.file_rating,
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
    root_dir: &std::path::Path,
) -> Result<Vec<Ed2kSharedEntry>> {
    metadata
        .completed_transfer_catalog_entries()?
        .into_iter()
        .map(|entry| shared_entry_from_catalog_entry(metadata, entry, root_dir))
        .collect()
}

fn shared_entry_from_catalog_entry(
    metadata: &MetadataStore,
    entry: MetadataTransferCatalogEntry,
    root_dir: &std::path::Path,
) -> Result<Ed2kSharedEntry> {
    let media = if entry.media.extractor_version == MEDIA_METADATA_EXTRACTOR_VERSION {
        media_from_metadata(entry.media.clone())
    } else {
        let media_path = entry
            .media_path
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                root_dir
                    .join(&entry.file_hash)
                    .join(super::PAYLOAD_FILE_NAME)
            });
        let media = super::media_metadata::extract_media_metadata(&media_path, &entry.display_name);
        let persisted = media_to_metadata(&media, MEDIA_METADATA_EXTRACTOR_VERSION);
        if let Err(error) = metadata.update_transfer_media_metadata(&entry.file_hash, &persisted) {
            tracing::warn!(
                file_hash = %entry.file_hash,
                "failed to persist refreshed shared media metadata: {error:#}"
            );
        }
        media
    };
    Ok(Ed2kSharedEntry {
        file_hash: entry.file_hash,
        display_name: entry.display_name,
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
        media,
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

pub(super) fn media_from_metadata(
    media: MetadataTransferMediaMetadata,
) -> super::Ed2kMediaMetadata {
    super::Ed2kMediaMetadata {
        artist: media.artist,
        album: media.album,
        title: media.title,
        length_seconds: media.length_seconds,
        bitrate_kbps: media.bitrate_kbps,
        codec: media.codec,
    }
}

pub(super) fn media_to_metadata(
    media: &super::Ed2kMediaMetadata,
    extractor_version: u32,
) -> MetadataTransferMediaMetadata {
    MetadataTransferMediaMetadata {
        artist: media.artist.clone(),
        album: media.album.clone(),
        title: media.title.clone(),
        length_seconds: media.length_seconds,
        bitrate_kbps: media.bitrate_kbps,
        codec: media.codec.clone(),
        extractor_version,
    }
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
            display_name: "f.bin".to_string(),
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
