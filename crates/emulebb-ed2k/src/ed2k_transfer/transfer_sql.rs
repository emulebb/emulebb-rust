use std::collections::BTreeMap;

use anyhow::Result;
use emulebb_metadata::{
    MetadataStore, MetadataTransferCatalogEntry, MetadataTransferDeliveryOwnership,
    MetadataTransferDeliveryState, MetadataTransferManifest, MetadataTransferMediaMetadata,
    MetadataTransferPiece, MetadataTransferRange,
};

use super::{
    Ed2kDeliveryOwnership, Ed2kDeliveryState, Ed2kPieceState, Ed2kResumeManifest, Ed2kSharedEntry,
    Ed2kSharedRange, Ed2kTransferState, block_bitmap::PartBlockBitmap,
    catalog::Ed2kSharedPublishStats, expected_piece_length,
};

pub(super) const MEDIA_METADATA_EXTRACTOR_VERSION: u32 = 1;

pub(super) fn manifest_to_metadata(
    manifest: &Ed2kResumeManifest,
) -> Result<MetadataTransferManifest> {
    Ok(MetadataTransferManifest {
        token: manifest.token,
        file_hash: manifest.file_hash.clone(),
        display_name: manifest.display_name.clone(),
        expected_size_bytes: Some(manifest.file_size),
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
        pieces: manifest
            .pieces
            .iter()
            .map(|piece| {
                piece_to_metadata(
                    piece,
                    expected_piece_length(
                        manifest.file_size,
                        manifest.piece_size,
                        u64::from(piece.piece_index),
                    ),
                )
            })
            .collect(),
        upload_priority: manifest.upload_priority.clone(),
        auto_upload_priority: manifest.auto_upload_priority,
        comment: manifest.comment.clone(),
        rating: manifest.rating,
        category_id: manifest.category_id,
        intent: manifest.intent,
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
pub(super) fn piece_to_metadata(piece: &Ed2kPieceState, extent: u64) -> MetadataTransferPiece {
    MetadataTransferPiece {
        piece_index: piece.piece_index,
        state: transfer_state_to_sql(piece.state).to_string(),
        prefix_bytes: piece.bytes_written,
        present_bytes: if piece.block_bitmap.is_some() {
            piece.resolve_block_bitmap(extent).present_bytes()
        } else {
            piece.bytes_written
        },
        block_bitmap: piece.block_bitmap.clone(),
        ich_corrupted: piece.ich_corrupted,
    }
}

pub(super) fn manifest_from_metadata(
    manifest: MetadataTransferManifest,
) -> Result<Ed2kResumeManifest> {
    let file_size = manifest.expected_size_bytes.ok_or_else(|| {
        anyhow::anyhow!(
            "job {} has unknown expected size and cannot execute",
            manifest.token.job_id
        )
    })?;
    anyhow::ensure!(
        manifest.piece_size > 0 && file_size > 0,
        "invalid executable download geometry"
    );
    let piece_size = manifest.piece_size;
    let manifest_hash = manifest.file_hash.clone();
    Ok(Ed2kResumeManifest {
        token: manifest.token,
        file_hash: manifest.file_hash,
        display_name: manifest.display_name,
        file_size,
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
                    bytes_written: piece.prefix_bytes,
                    block_bitmap: piece.block_bitmap,
                    ich_corrupted: piece.ich_corrupted,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        upload_priority: manifest.upload_priority,
        auto_upload_priority: manifest.auto_upload_priority,
        comment: manifest.comment,
        rating: manifest.rating,
        category_id: manifest.category_id,
        intent: manifest.intent,
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

/// Build only selected execution geometry; each SQL row is moved directly into
/// its final vector. Durable source/name history is read through separate pages.
pub(super) fn stream_execution_from_metadata(
    metadata: &MetadataStore,
    token: emulebb_metadata::JobToken,
) -> Result<Option<Ed2kResumeManifest>> {
    use emulebb_metadata::MetadataDownloadExecutionRow as Row;
    let mut result: Option<Ed2kResumeManifest> = None;
    let found = metadata.stream_download_execution(token, |row| {
        match row {
            Row::Header(header, counts) => {
                result = Some(Ed2kResumeManifest {
                    token: header.token,
                    file_hash: header.file_hash,
                    display_name: header.display_name,
                    file_size: header.file_size,
                    piece_size: header.piece_size,
                    completed: header.completed,
                    final_rehash_pending: header.final_rehash_pending,
                    md4_hashset_acquired: header.md4_hashset_acquired,
                    md4_hashset: Vec::with_capacity(counts.md4_hashes),
                    aich_hashset_acquired: header.aich_hashset_acquired,
                    aich_root: header.aich_root,
                    aich_root_origin: header
                        .aich_root_origin
                        .as_deref()
                        .map(super::Ed2kAichRootOrigin::parse)
                        .transpose()?,
                    aich_trust_generation: header.aich_trust_generation,
                    aich_hashset: Vec::with_capacity(counts.aich_hashes),
                    verified_ranges: Vec::with_capacity(counts.ranges),
                    pieces: Vec::with_capacity(counts.pieces),
                    upload_priority: header.upload_priority,
                    auto_upload_priority: header.auto_upload_priority,
                    comment: header.comment,
                    rating: header.rating,
                    category_id: header.category_id,
                    intent: header.intent,
                    transfer_row_removed: false,
                    delivery_state: match header.delivery_state {
                        MetadataTransferDeliveryState::Pending => super::Ed2kDeliveryState::Pending,
                        MetadataTransferDeliveryState::Delivered => {
                            super::Ed2kDeliveryState::Delivered
                        }
                    },
                    delivery_ownership: match header.delivery_ownership {
                        MetadataTransferDeliveryOwnership::None => {
                            super::Ed2kDeliveryOwnership::None
                        }
                        MetadataTransferDeliveryOwnership::Owned => {
                            super::Ed2kDeliveryOwnership::Owned
                        }
                        MetadataTransferDeliveryOwnership::Unowned => {
                            super::Ed2kDeliveryOwnership::Unowned
                        }
                    },
                    delivered_path: header.delivered_path,
                    source_fingerprint: header.source_fingerprint,
                    payload_fingerprint: header.payload_fingerprint,
                });
            }
            Row::Piece(piece) => {
                let manifest = result.as_mut().expect("execution header precedes rows");
                if let Some(bitmap) = piece.block_bitmap.as_deref() {
                    let size = expected_piece_length(
                        manifest.file_size,
                        manifest.piece_size,
                        u64::from(piece.piece_index),
                    );
                    anyhow::ensure!(
                        PartBlockBitmap::from_hex(size, bitmap).is_some(),
                        "invalid execution bitmap"
                    );
                }
                manifest.pieces.push(Ed2kPieceState {
                    piece_index: piece.piece_index,
                    state: transfer_state_from_sql(&piece.state)?,
                    bytes_written: piece.prefix_bytes,
                    block_bitmap: piece.block_bitmap,
                    ich_corrupted: piece.ich_corrupted,
                });
            }
            Row::Md4(hash) => result
                .as_mut()
                .expect("execution header precedes rows")
                .md4_hashset
                .push(hex::encode(hash)),
            Row::Aich(hash) => result
                .as_mut()
                .expect("execution header precedes rows")
                .aich_hashset
                .push(hex::encode(hash)),
            Row::Range(range) => result
                .as_mut()
                .expect("execution header precedes rows")
                .verified_ranges
                .push(Ed2kSharedRange {
                    start: range.start,
                    end: range.end,
                }),
        }
        Ok(())
    })?;
    if !found {
        return Ok(None);
    }
    Ok(result)
}

/// Build directly into the one owned catalog; bounded read pages are dropped
/// before advancing, rather than collecting a second library-sized entry list.
pub(super) fn completed_catalog_from_metadata_store(
    metadata: &MetadataStore,
) -> Result<super::IndexedSharedCatalog> {
    let mut catalog = super::IndexedSharedCatalog::default();
    let mut after = None;
    loop {
        let page = completed_catalog_page_from_metadata_store(
            metadata,
            after.as_deref(),
            super::STARTUP_SHARED_CATALOG_BATCH,
        )?;
        for entry in page.entries {
            catalog.push(entry);
        }
        if !page.has_more {
            break;
        }
        anyhow::ensure!(page.cursor > after, "catalog page did not advance");
        after = page.cursor;
    }
    Ok(catalog)
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
    anyhow::ensure!((1..=256).contains(&limit), "invalid catalog page size");
    let complete = metadata.completed_transfer_catalog_entries_after(after_hash, limit)?;
    let local = metadata.active_local_catalog_page(after_hash, limit)?;
    // WHY: a provider may stop at its byte allowance before reaching the row
    // limit. Advancing past either returned frontier could skip its next rows.
    // Only empty input establishes exhaustion; rejected stale candidates still
    // advance the cursor and a final empty page terminates traversal.
    let frontier = complete
        .last()
        .into_iter()
        .chain(local.last())
        .map(|entry| entry.file_hash.clone())
        .min();
    let mut by_hash = BTreeMap::new();
    // Both providers describe local instances, not internal download payloads.
    // A duplicate row is never independent fallback authority for a stale copy.
    for entry in complete
        .into_iter()
        .chain(local)
        .filter(|entry| Some(&entry.file_hash) <= frontier.as_ref())
    {
        by_hash.insert(
            entry.file_hash.clone(),
            shared_entry_from_catalog_entry(entry)?,
        );
    }
    let candidates = by_hash.into_values().take(limit).collect::<Vec<_>>();
    let cursor = candidates.last().map(|entry| entry.file_hash.clone());
    let has_more = cursor.is_some();
    let mut entries = Vec::with_capacity(candidates.len());
    for mut entry in candidates {
        let Some(source) = super::duplicate::first_present_source(
            metadata.current_shared_files_by_hash(&entry.file_hash)?,
        ) else {
            continue;
        };
        if !metadata.mark_session_verified_local_path(&source.metadata_path, &source.fingerprint)? {
            continue;
        }
        if let Some(name) =
            emulebb_metadata::NativePath::from(source.path.as_path()).display_file_name()
        {
            entry.display_name = name;
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

    #[test]
    fn streamed_maximum_execution_capacity_fits_six_mebibytes_without_second_dto() {
        let size = 0x4000000000u64;
        let part_size = super::super::ED2K_PART_SIZE;
        let count = usize::try_from(size.div_ceil(part_size)).unwrap();
        assert_eq!(
            count,
            super::super::manifest::piece_count(size, part_size) as usize
        );
        assert_eq!(count, 28_257);
        let mut pieces = Vec::with_capacity(count);
        let md4_count = usize::from(super::super::hashset::expected_md4_hash_count(size));
        let mut md4 = Vec::with_capacity(md4_count);
        let mut aich = Vec::with_capacity(count);
        let mut ranges = Vec::with_capacity(count.div_ceil(2));
        let mut fragmented_blocks = 0usize;
        for index in 0..count {
            let start = index as u64 * part_size;
            let length = part_size.min(size - start);
            let mut bitmap = PartBlockBitmap::empty(length);
            for block in (0..bitmap.block_count()).step_by(2) {
                bitmap.set_present(block);
                fragmented_blocks += 1;
            }
            // The maximal alternating part coverage is independent of the
            // per-part bitmap backing bound. Keep both allocations charged.
            pieces.push(Ed2kPieceState {
                piece_index: index as u32,
                state: if index % 2 == 0 {
                    Ed2kTransferState::Verified
                } else {
                    Ed2kTransferState::Missing
                },
                bytes_written: if index % 2 == 0 {
                    length
                } else {
                    bitmap.contiguous_prefix_bytes()
                },
                block_bitmap: Some(bitmap.to_hex()),
                ich_corrupted: false,
            });
            md4.push(hex::encode([0u8; 16]));
            aich.push(hex::encode([0u8; 20]));
            if index % 2 == 0 {
                ranges.push(Ed2kSharedRange {
                    start,
                    end: start + length,
                });
            }
        }
        if md4_count > count {
            md4.push(hex::encode([0u8; 16]));
        }
        assert_eq!(md4.len(), md4_count);
        assert!(fragmented_blocks > 700_000);
        assert_eq!(ranges.len(), count.div_ceil(2));
        let vectors = pieces.capacity() * std::mem::size_of::<Ed2kPieceState>()
            + md4.capacity() * std::mem::size_of::<String>()
            + aich.capacity() * std::mem::size_of::<String>()
            + ranges.capacity() * std::mem::size_of::<Ed2kSharedRange>();
        let backing = pieces
            .iter()
            .map(|piece| piece.block_bitmap.as_ref().unwrap().capacity())
            .sum::<usize>()
            + md4.iter().map(String::capacity).sum::<usize>()
            + aich.iter().map(String::capacity).sum::<usize>();
        // Three bounded 64-KiB texts plus native path conversion and constant
        // row/bitmap decoder scratch fit the separately counted 512-KiB header.
        assert!(vectors + backing + 512 * 1024 <= 6 * 1024 * 1024);
    }

    fn manifest_row(file_size: u64, piece_size: u64) -> MetadataTransferManifest {
        let (_profile, token) = crate::ed2k_transfer::test_support::admit_protocol_job(
            emulebb_kad_proto::Ed2kHash::from_bytes([0; 16]),
        );
        MetadataTransferManifest {
            token,
            file_hash: "00000000000000000000000000000000".to_string(),
            display_name: "f.bin".to_string(),
            expected_size_bytes: Some(file_size),
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
            upload_priority: String::new(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
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
            err.to_string()
                .contains("invalid executable download geometry"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn zero_length_content_is_not_executable_download_geometry() {
        let error = manifest_from_metadata(manifest_row(0, 0)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid executable download geometry")
        );
    }

    #[test]
    fn rejects_malformed_persisted_block_bitmap() {
        let mut row = manifest_row(1024, 1024);
        row.pieces = vec![MetadataTransferPiece {
            piece_index: 0,
            state: "Missing".to_string(),
            prefix_bytes: 0,
            present_bytes: 0,
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
