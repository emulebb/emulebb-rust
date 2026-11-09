use std::collections::BTreeMap;

use anyhow::Result;
use emulebb_metadata::{
    MetadataStore, MetadataTransferCatalogEntry, MetadataTransferDeliveryOwnership,
    MetadataTransferDeliveryState, MetadataTransferFileNameObservation, MetadataTransferManifest,
    MetadataTransferMediaMetadata, MetadataTransferPiece, MetadataTransferRange,
    MetadataTransferSource,
};

use super::{
    Ed2kDeliveryOwnership, Ed2kDeliveryState, Ed2kFileNameObservation, Ed2kPieceState,
    Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSharedRange, Ed2kSourceHint, Ed2kTransferState,
    block_bitmap::PartBlockBitmap, catalog::Ed2kSharedPublishStats, expected_piece_length,
};

pub(super) const MEDIA_METADATA_EXTRACTOR_VERSION: u32 = 1;

pub(super) fn manifest_to_metadata(
    manifest: &Ed2kResumeManifest,
) -> Result<MetadataTransferManifest> {
    Ok(MetadataTransferManifest {
        file_hash: manifest.file_hash.clone(),
        display_name: manifest.display_name.clone(),
        display_name_pinned: manifest.display_name_pinned,
        follow_majority_filename: manifest.follow_majority_filename,
        file_name_observations: manifest
            .file_name_observations
            .iter()
            .map(|observation| MetadataTransferFileNameObservation {
                source_ip: observation.source_ip.clone(),
                source_tcp_port: observation.source_tcp_port,
                user_hash: observation.user_hash.clone(),
                client_software: observation.client_software.clone(),
                origin: observation.origin.clone(),
                server_endpoint: observation.server_endpoint.clone(),
                raw_name: observation.raw_name.clone(),
                normalized_name: observation.normalized_name.clone(),
                observed_at_ms: observation.observed_at_ms,
            })
            .collect(),
        file_size: manifest.file_size,
        piece_size: manifest.piece_size,
        completed: manifest.completed,
        final_rehash_pending: manifest.final_rehash_pending,
        md4_hashset_acquired: manifest.md4_hashset_acquired,
        md4_hashset: manifest.md4_hashset.clone(),
        aich_hashset_acquired: manifest.aich_hashset_acquired,
        aich_root: manifest.aich_root.clone(),
        aich_root_origin: manifest
            .aich_root_origin
            .map(|origin| origin.as_str().to_owned()),
        aich_trust_generation: manifest.aich_trust_generation,
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
        delivery_state: match manifest.delivery_state {
            Ed2kDeliveryState::Pending => MetadataTransferDeliveryState::Pending,
            Ed2kDeliveryState::Delivered => MetadataTransferDeliveryState::Delivered,
        },
        delivery_ownership: match manifest.delivery_ownership {
            Ed2kDeliveryOwnership::None => MetadataTransferDeliveryOwnership::None,
            Ed2kDeliveryOwnership::Owned => MetadataTransferDeliveryOwnership::Owned,
            Ed2kDeliveryOwnership::Unowned => MetadataTransferDeliveryOwnership::Unowned,
        },
        delivered_path: manifest.delivered_path.clone(),
        source_fingerprint: manifest.source_fingerprint.clone(),
        payload_fingerprint: manifest.payload_fingerprint.clone(),
    })
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
    let file_size = manifest.file_size;
    let piece_size = manifest.piece_size;
    let manifest_hash = manifest.file_hash.clone();
    Ok(Ed2kResumeManifest {
        file_hash: manifest.file_hash,
        display_name: manifest.display_name,
        display_name_pinned: manifest.display_name_pinned,
        follow_majority_filename: manifest.follow_majority_filename,
        file_name_observations: manifest
            .file_name_observations
            .into_iter()
            .map(|observation| Ed2kFileNameObservation {
                source_ip: observation.source_ip,
                source_tcp_port: observation.source_tcp_port,
                user_hash: observation.user_hash,
                client_software: observation.client_software,
                origin: observation.origin,
                server_endpoint: observation.server_endpoint,
                raw_name: observation.raw_name,
                normalized_name: observation.normalized_name,
                observed_at_ms: observation.observed_at_ms,
            })
            .collect(),
        file_size: manifest.file_size,
        piece_size: manifest.piece_size,
        completed: manifest.completed,
        final_rehash_pending: manifest.final_rehash_pending,
        md4_hashset_acquired: manifest.md4_hashset_acquired,
        md4_hashset: manifest.md4_hashset,
        aich_hashset_acquired: manifest.aich_hashset_acquired,
        aich_root: manifest.aich_root,
        aich_root_origin: manifest
            .aich_root_origin
            .as_deref()
            .map(super::Ed2kAichRootOrigin::parse)
            .transpose()?,
        aich_trust_generation: manifest.aich_trust_generation,
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
                if let Some(bitmap) = piece.block_bitmap.as_deref() {
                    let part_len =
                        expected_piece_length(file_size, piece_size, u64::from(piece.piece_index));
                    anyhow::ensure!(
                        part_len > 0 && PartBlockBitmap::from_hex(part_len, bitmap).is_some(),
                        "invalid persisted block bitmap for {} piece {}",
                        manifest_hash,
                        piece.piece_index
                    );
                }
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
        delivery_state: match manifest.delivery_state {
            MetadataTransferDeliveryState::Pending => Ed2kDeliveryState::Pending,
            MetadataTransferDeliveryState::Delivered => Ed2kDeliveryState::Delivered,
        },
        delivery_ownership: match manifest.delivery_ownership {
            MetadataTransferDeliveryOwnership::None => Ed2kDeliveryOwnership::None,
            MetadataTransferDeliveryOwnership::Owned => Ed2kDeliveryOwnership::Owned,
            MetadataTransferDeliveryOwnership::Unowned => Ed2kDeliveryOwnership::Unowned,
        },
        delivered_path: manifest.delivered_path,
        source_fingerprint: manifest.source_fingerprint,
        payload_fingerprint: manifest.payload_fingerprint,
    })
}

pub(super) fn completed_catalog_from_metadata_store(
    metadata: &MetadataStore,
) -> Result<Vec<Ed2kSharedEntry>> {
    Ok(completed_catalog_page_from_metadata_store(metadata, None, usize::MAX)?.entries)
}

/// A keyset page whose cursor also advances across rejected stale candidates.
pub(super) struct CompletedCatalogPage {
    pub entries: Vec<Ed2kSharedEntry>,
    pub cursor: Option<String>,
    pub has_more: bool,
}

pub(super) fn completed_catalog_page_from_metadata_store(
    metadata: &MetadataStore,
    after_hash: Option<&str>,
    limit: usize,
) -> Result<CompletedCatalogPage> {
    let mut by_hash = BTreeMap::new();
    // A completed download awaiting delivery can still serve its verified
    // payload. A complete local file is authorized by a root membership.
    for entry in metadata.completed_transfer_catalog_entries_after(after_hash, limit)? {
        by_hash.insert(
            entry.file_hash.clone(),
            (shared_entry_from_catalog_entry(entry)?, false, None),
        );
    }
    for entry in metadata.active_local_catalog_page(after_hash, limit)? {
        let download_fallback = by_hash
            .remove(&entry.file_hash)
            .map(|(download, _, _)| download);
        by_hash.insert(
            entry.file_hash.clone(),
            (
                shared_entry_from_catalog_entry(entry)?,
                true,
                download_fallback,
            ),
        );
    }
    let candidates = by_hash.into_values().take(limit).collect::<Vec<_>>();
    let cursor = candidates
        .last()
        .map(|(entry, _, _)| entry.file_hash.clone());
    let has_more = candidates.len() == limit;
    let mut entries = Vec::with_capacity(candidates.len());
    for (mut entry, local, download_fallback) in candidates {
        if local {
            // WHY: a persisted root membership is only a candidate after
            // restart. Check current identity before any protocol publication.
            let Some(source) = super::duplicate::first_present_source(
                metadata.current_shared_files_by_hash(&entry.file_hash)?,
            ) else {
                if let Some(download) = download_fallback {
                    entries.push(download);
                }
                continue;
            };
            if !metadata
                .mark_session_verified_local_path(&source.metadata_path, &source.fingerprint)?
            {
                if let Some(download) = download_fallback {
                    entries.push(download);
                }
                continue;
            }
            if let Some(name) =
                emulebb_metadata::NativePath::from(source.path.as_path()).display_file_name()
            {
                entry.display_name = name;
            }
        }
        entries.push(entry);
    }
    Ok(CompletedCatalogPage {
        entries,
        cursor,
        has_more,
    })
}

pub(super) fn shared_entry_from_catalog_entry(
    entry: MetadataTransferCatalogEntry,
) -> Result<Ed2kSharedEntry> {
    let media = if entry.media.extractor_version == MEDIA_METADATA_EXTRACTOR_VERSION {
        media_from_metadata(entry.media.clone())
    } else {
        Default::default()
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
        Ed2kTransferState::Verified => "Verified",
    }
}

fn transfer_state_from_sql(value: &str) -> Result<Ed2kTransferState> {
    match value {
        "Missing" => Ok(Ed2kTransferState::Missing),
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
            display_name_pinned: false,
            follow_majority_filename: false,
            file_name_observations: Vec::new(),
            file_size,
            piece_size,
            completed: false,
            final_rehash_pending: false,
            md4_hashset_acquired: false,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: false,
            aich_root: None,
            aich_root_origin: None,
            aich_trust_generation: 0,
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
            delivery_state: MetadataTransferDeliveryState::Pending,
            delivery_ownership: MetadataTransferDeliveryOwnership::None,
            delivered_path: None,
            source_fingerprint: None,
            payload_fingerprint: None,
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

    #[test]
    fn rejects_malformed_persisted_block_bitmap() {
        let mut row = manifest_row(1024, 1024);
        row.pieces = vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            bytes_written: 0,
            block_bitmap: Some("01".to_string()),
            ich_corrupted: false,
        }];
        assert!(manifest_from_metadata(row.clone()).is_ok());
        for invalid in ["", "zz", "0000", "0A", "02"] {
            row.pieces[0].block_bitmap = Some(invalid.to_string());
            let error = manifest_from_metadata(row.clone()).unwrap_err();
            assert!(error.to_string().contains("invalid persisted block bitmap"));
        }
    }
}
