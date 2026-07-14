use std::path::Path;

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use flate2::{Compress, Compression, FlushCompress, FlushDecompress, Status};

use super::super::{
    ED2K_UPLOAD_PACKET_FRAGMENT_LEN, ED2K_UPLOAD_PACKET_SPLIT_THRESHOLD, EncodedUploadPartPacket,
    OP_COMPRESSEDPART, OP_COMPRESSEDPART_I64, OP_EDONKEYPROT, OP_EMULEPROT, OP_REQUESTPARTS,
    OP_REQUESTPARTS_I64, OP_SENDINGPART, OP_SENDINGPART_I64, PendingCompressedPart,
};
use super::encode_packet;

pub(in crate::ed2k_tcp) fn decode_request_parts_payload(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, Vec<(u64, u64)>)> {
    if payload.len() < 16 {
        anyhow::bail!("short OP_REQUESTPARTS payload");
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let width = if use_i64 { 8 } else { 4 };
    let expected = 16 + (width * 3) + (width * 3);
    if payload.len() < expected {
        anyhow::bail!(
            "short OP_REQUESTPARTS payload {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let starts = &payload[16..16 + (width * 3)];
    let ends = &payload[16 + (width * 3)..expected];
    let mut ranges = Vec::new();
    for index in 0..3usize {
        let start = if use_i64 {
            u64::from_le_bytes(
                starts[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("i64 width"),
            )
        } else {
            u64::from(u32::from_le_bytes(
                starts[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("u32 width"),
            ))
        };
        let end = if use_i64 {
            u64::from_le_bytes(
                ends[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("i64 width"),
            )
        } else {
            u64::from(u32::from_le_bytes(
                ends[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("u32 width"),
            ))
        };
        if end > start {
            ranges.push((start, end));
        }
    }
    Ok((Ed2kHash::from_bytes(hash), ranges))
}

/// Encode one ED2K `OP_REQUESTPARTS` packet with up to three ranges.
///
/// The successful public oracle capture used rolling multi-range requests
/// instead of emitting one separate request packet per range, so the native
/// downloader batches adjacent work into one packet to stay closer to that
/// accepted wire shape.
pub(in crate::ed2k_tcp) fn encode_request_parts_batch(
    file_hash: &Ed2kHash,
    ranges: &[(u64, u64)],
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !ranges.is_empty() && ranges.len() <= 3,
        "OP_REQUESTPARTS expects between one and three ranges"
    );
    let use_i64 = ranges.iter().any(|(_, end)| *end > u64::from(u32::MAX));
    let mut payload = Vec::with_capacity(16 + if use_i64 { 48 } else { 24 });
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        for index in 0..3usize {
            let start = ranges.get(index).map_or(0, |(start, _)| *start);
            payload.extend_from_slice(&start.to_le_bytes());
        }
        for index in 0..3usize {
            let end = ranges.get(index).map_or(0, |(_, end)| *end);
            payload.extend_from_slice(&end.to_le_bytes());
        }
        return Ok(encode_packet(OP_EMULEPROT, OP_REQUESTPARTS_I64, &payload));
    }
    for index in 0..3usize {
        let start = ranges.get(index).map_or(0, |(start, _)| *start);
        let start = u32::try_from(start).context("start offset exceeds OP_REQUESTPARTS limit")?;
        payload.extend_from_slice(&start.to_le_bytes());
    }
    for index in 0..3usize {
        let end = ranges.get(index).map_or(0, |(_, end)| *end);
        let end = u32::try_from(end).context("end offset exceeds OP_REQUESTPARTS limit")?;
        payload.extend_from_slice(&end.to_le_bytes());
    }
    Ok(encode_packet(OP_EDONKEYPROT, OP_REQUESTPARTS, &payload))
}

pub(in crate::ed2k_tcp) fn decode_sending_part_payload(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, u64, u64, &[u8])> {
    let header_len = 16 + if use_i64 { 16 } else { 8 };
    if payload.len() < header_len {
        anyhow::bail!("short OP_SENDINGPART payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let (start, end) = if use_i64 {
        let start = u64::from_le_bytes(payload[16..24].try_into().expect("u64 width"));
        let end = u64::from_le_bytes(payload[24..32].try_into().expect("u64 width"));
        (start, end)
    } else {
        let start = u64::from(u32::from_le_bytes(
            payload[16..20].try_into().expect("u32 width"),
        ));
        let end = u64::from(u32::from_le_bytes(
            payload[20..24].try_into().expect("u32 width"),
        ));
        (start, end)
    };
    if end < start {
        anyhow::bail!("invalid OP_SENDINGPART range {start}..{end}");
    }
    // Borrow the body out of the packet payload: the receive path buffers it
    // into the pending request itself, so an owned copy here was pure churn.
    let bytes = &payload[header_len..];
    if usize::try_from(end - start).unwrap_or(usize::MAX) != bytes.len() {
        anyhow::bail!(
            "OP_SENDINGPART body length {} does not match range {}..{}",
            bytes.len(),
            start,
            end
        );
    }
    Ok((Ed2kHash::from_bytes(hash), start, end, bytes))
}

pub(in crate::ed2k_tcp) fn decode_compressed_part_fragment(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, u64, usize, &[u8])> {
    let header_len = 16 + if use_i64 { 12 } else { 8 };
    if payload.len() < header_len {
        anyhow::bail!("short OP_COMPRESSEDPART payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let (start, advertised_compressed_len) = if use_i64 {
        let start = u64::from_le_bytes(payload[16..24].try_into().expect("u64 width"));
        let advertised_compressed_len = usize::try_from(u32::from_le_bytes(
            payload[24..28].try_into().expect("u32 width"),
        ))
        .unwrap_or(usize::MAX);
        (start, advertised_compressed_len)
    } else {
        let start = u64::from(u32::from_le_bytes(
            payload[16..20].try_into().expect("u32 width"),
        ));
        let advertised_compressed_len = usize::try_from(u32::from_le_bytes(
            payload[20..24].try_into().expect("u32 width"),
        ))
        .unwrap_or(usize::MAX);
        (start, advertised_compressed_len)
    };
    Ok((
        Ed2kHash::from_bytes(hash),
        start,
        advertised_compressed_len,
        &payload[header_len..],
    ))
}

pub(in crate::ed2k_tcp) fn inflate_compressed_part_fragment(
    pending: &mut PendingCompressedPart,
    compressed_fragment: &[u8],
) -> Result<(Vec<u8>, bool)> {
    let mut remaining = compressed_fragment;
    let mut bytes = Vec::new();
    let mut finished = false;

    // Decompression-bomb guard. The fully inflated stream for this part can never
    // legitimately exceed the requested piece span (`end - start`, itself bounded
    // by ED2K_PART_SIZE). A single crafted fragment (compressed input <=
    // MAX_ED2K_PACKET_LEN) could otherwise inflate to ~2 GB transiently before
    // the post-fragment `uncompressed_written > piece_len` check fires. We cap
    // the accumulated output incrementally (mirroring the OP_PACKEDPROT path) so
    // the oversized allocation never happens.
    let max_uncompressed_output = pending.end.saturating_sub(pending.start);

    while !remaining.is_empty() {
        let mut output = [0u8; 16 * 1024];
        let total_in_before = pending.inflater.total_in();
        let total_out_before = pending.inflater.total_out();
        let status = pending
            .inflater
            .decompress(remaining, &mut output, FlushDecompress::Sync)
            .context("failed to inflate OP_COMPRESSEDPART fragment")?;
        let consumed = usize::try_from(pending.inflater.total_in() - total_in_before).unwrap_or(0);
        let produced =
            usize::try_from(pending.inflater.total_out() - total_out_before).unwrap_or(0);
        if produced != 0 {
            let accumulated = pending
                .uncompressed_written
                .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .saturating_add(u64::try_from(produced).unwrap_or(u64::MAX));
            if accumulated > max_uncompressed_output {
                anyhow::bail!(
                    "OP_COMPRESSEDPART inflate exceeded expected piece length {} bytes",
                    max_uncompressed_output
                );
            }
            bytes.extend_from_slice(&output[..produced]);
        }
        remaining = &remaining[consumed..];
        match status {
            Status::StreamEnd => {
                finished = true;
                break;
            }
            Status::Ok => {
                if consumed == 0 && produced == 0 {
                    anyhow::bail!("OP_COMPRESSEDPART inflate made no progress");
                }
            }
            Status::BufError => {
                if consumed == 0 && produced == 0 {
                    break;
                }
            }
        }
    }

    pending.compressed_received += compressed_fragment.len();
    if pending.compressed_received > pending.advertised_compressed_len {
        anyhow::bail!(
            "OP_COMPRESSEDPART received {} compressed bytes, above advertised {}",
            pending.compressed_received,
            pending.advertised_compressed_len
        );
    }
    if pending.compressed_received == pending.advertised_compressed_len && !finished {
        loop {
            let mut output = [0u8; 16 * 1024];
            let total_out_before = pending.inflater.total_out();
            let status = pending
                .inflater
                .decompress(&[], &mut output, FlushDecompress::Finish)
                .context("failed to finish OP_COMPRESSEDPART inflate stream")?;
            let produced =
                usize::try_from(pending.inflater.total_out() - total_out_before).unwrap_or(0);
            if produced != 0 {
                let accumulated = pending
                    .uncompressed_written
                    .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(produced).unwrap_or(u64::MAX));
                if accumulated > max_uncompressed_output {
                    anyhow::bail!(
                        "OP_COMPRESSEDPART inflate exceeded expected piece length {} bytes",
                        max_uncompressed_output
                    );
                }
                bytes.extend_from_slice(&output[..produced]);
            }
            match status {
                Status::StreamEnd => {
                    finished = true;
                    break;
                }
                Status::Ok | Status::BufError if produced == 0 => {
                    finished = true;
                    break;
                }
                Status::Ok | Status::BufError => {}
            }
        }
    }
    pending.uncompressed_written += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    Ok((bytes, finished))
}

fn upload_packet_fragment_len(remaining: usize) -> usize {
    if remaining < ED2K_UPLOAD_PACKET_SPLIT_THRESHOLD {
        remaining
    } else {
        ED2K_UPLOAD_PACKET_FRAGMENT_LEN
    }
}

fn should_attempt_upload_compression(display_name: &str) -> bool {
    let Some(extension) = Path::new(display_name)
        .extension()
        .and_then(|value| value.to_str())
    else {
        return true;
    };
    let extension = extension.to_ascii_lowercase();
    // Already-compressed / incompressible container formats: deflating them only
    // burns CPU for ~no gain (and can grow the payload). Mirrors the master
    // CUploadDiskIOThread::ShouldCompressBasedOnFilename exclusion set
    // (UploadDiskIOThread.cpp:664-684), case-insensitive extension match.
    !matches!(
        extension.as_str(),
        "7z" | "aac"
            | "ace"
            | "apk"
            | "avi"
            | "bz2"
            | "cab"
            | "cbr"
            | "cbz"
            | "docx"
            | "flac"
            | "flv"
            | "gif"
            | "gz"
            | "jar"
            | "jpeg"
            | "jpg"
            | "lz"
            | "lzma"
            | "m2ts"
            | "m4a"
            | "m4v"
            | "mkv"
            | "mov"
            | "mp3"
            | "mp4"
            | "mpeg"
            | "mpg"
            | "mts"
            | "odp"
            | "ods"
            | "odt"
            | "ogg"
            | "ogm"
            | "opus"
            | "pdf"
            | "png"
            | "pptx"
            | "rar"
            | "ts"
            | "vob"
            | "webm"
            | "webp"
            | "wma"
            | "wmv"
            | "xlsx"
            | "xz"
            | "zip"
            | "zst"
    )
}

fn compress_upload_payload(display_name: &str, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    if !should_attempt_upload_compression(display_name) {
        return Ok(None);
    }

    let mut compressor = Compress::new(Compression::new(1), true);
    let mut compressed = Vec::with_capacity(bytes.len().saturating_add(300));
    let mut remaining = bytes;
    let mut output = [0u8; 16 * 1024];
    loop {
        let total_in_before = compressor.total_in();
        let total_out_before = compressor.total_out();
        let status = compressor
            .compress(remaining, &mut output, FlushCompress::Finish)
            .context("failed to deflate ED2K upload payload")?;
        let consumed = usize::try_from(compressor.total_in() - total_in_before).unwrap_or(0);
        let produced = usize::try_from(compressor.total_out() - total_out_before).unwrap_or(0);
        if produced != 0 {
            compressed.extend_from_slice(&output[..produced]);
        }
        remaining = &remaining[consumed..];
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if consumed == 0 && produced == 0 {
                    anyhow::bail!("ED2K upload compression made no progress");
                }
            }
        }
    }

    if compressed.len() >= bytes.len() {
        return Ok(None);
    }

    Ok(Some(compressed))
}

pub(in crate::ed2k_tcp) fn build_upload_part_packets(
    file_hash: &Ed2kHash,
    display_name: &str,
    start: u64,
    end: u64,
    bytes: &[u8],
) -> Result<Vec<EncodedUploadPartPacket>> {
    let range_len = usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX);
    if range_len != bytes.len() {
        anyhow::bail!(
            "upload payload length {} does not match requested range {}..{}",
            bytes.len(),
            start,
            end
        );
    }

    if let Some(compressed) = compress_upload_payload(display_name, bytes)? {
        // Compressed reply opcode is selected PER BLOCK from the block's end
        // offset, matching CUploadDiskIOThread::CreatePackedPackets
        // (UploadDiskIOThread.cpp:770 `if (uEndOffset > UINT32_MAX)`). Every
        // fragment of this block carries the same OP_COMPRESSEDPART[_I64] opcode
        // because the header advertises the block start + total compressed size.
        let block_i64 = end > u64::from(u32::MAX);
        let mut packets = Vec::new();
        let mut offset = 0usize;
        while offset < compressed.len() {
            let fragment_len = upload_packet_fragment_len(compressed.len() - offset);
            let packet = encode_compressed_part_fragment(
                file_hash,
                start,
                compressed.len(),
                &compressed[offset..offset + fragment_len],
                block_i64,
            )?;
            packets.push(EncodedUploadPartPacket {
                phase: "compressed_part",
                packet,
            });
            offset += fragment_len;
        }
        return Ok(packets);
    }

    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let fragment_len = upload_packet_fragment_len(bytes.len() - offset);
        let fragment_start = start + u64::try_from(offset).unwrap_or(u64::MAX);
        let fragment_end = fragment_start + u64::try_from(fragment_len).unwrap_or(u64::MAX);
        // Standard reply opcode is selected PER PACKET from this fragment's
        // exclusive end offset, matching CUploadDiskIOThread::CreateStandardPackets
        // (UploadDiskIOThread.cpp:705 `if (endpos > _UI32_MAX)`). A fragment
        // ending above 4 GiB (u32::MAX) uses OP_SENDINGPART_I64 with 8-byte
        // offsets; a fragment entirely at or below 4 GiB uses the 32-bit
        // OP_SENDINGPART even when the request was OP_REQUESTPARTS_I64.
        let fragment_i64 = fragment_end > u64::from(u32::MAX);
        let packet = encode_sending_part(
            file_hash,
            fragment_start,
            fragment_end,
            &bytes[offset..offset + fragment_len],
            fragment_i64,
        )?;
        packets.push(EncodedUploadPartPacket {
            phase: "sending_part",
            packet,
        });
        offset += fragment_len;
    }
    Ok(packets)
}

pub(in crate::ed2k_tcp) fn encode_sending_part(
    file_hash: &Ed2kHash,
    start: u64,
    end: u64,
    bytes: &[u8],
    use_i64: bool,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(16 + if use_i64 { 16 } else { 8 } + bytes.len());
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        payload.extend_from_slice(&start.to_le_bytes());
        payload.extend_from_slice(&end.to_le_bytes());
        payload.extend_from_slice(bytes);
        return Ok(encode_packet(OP_EMULEPROT, OP_SENDINGPART_I64, &payload));
    }
    let start = u32::try_from(start).context("start offset exceeds OP_SENDINGPART limit")?;
    let end = u32::try_from(end).context("end offset exceeds OP_SENDINGPART limit")?;
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&end.to_le_bytes());
    payload.extend_from_slice(bytes);
    Ok(encode_packet(OP_EDONKEYPROT, OP_SENDINGPART, &payload))
}

pub(in crate::ed2k_tcp) fn encode_compressed_part_fragment(
    file_hash: &Ed2kHash,
    start: u64,
    advertised_compressed_len: usize,
    compressed_fragment: &[u8],
    use_i64: bool,
) -> Result<Vec<u8>> {
    let advertised_compressed_len = u32::try_from(advertised_compressed_len)
        .context("compressed payload exceeds OP_COMPRESSEDPART length field")?;
    let mut payload =
        Vec::with_capacity(16 + if use_i64 { 12 } else { 8 } + compressed_fragment.len());
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        payload.extend_from_slice(&start.to_le_bytes());
        payload.extend_from_slice(&advertised_compressed_len.to_le_bytes());
        payload.extend_from_slice(compressed_fragment);
        return Ok(encode_packet(OP_EMULEPROT, OP_COMPRESSEDPART_I64, &payload));
    }

    let start = u32::try_from(start).context("start offset exceeds OP_COMPRESSEDPART limit")?;
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&advertised_compressed_len.to_le_bytes());
    payload.extend_from_slice(compressed_fragment);
    Ok(encode_packet(OP_EMULEPROT, OP_COMPRESSEDPART, &payload))
}

#[cfg(test)]
mod tests {
    use super::should_attempt_upload_compression;

    #[test]
    fn already_compressed_media_is_skipped() {
        // Representative entries from the master ShouldCompressBasedOnFilename set;
        // the extension match is case-insensitive.
        for name in [
            "movie.mp4",
            "movie.MKV",
            "photo.jpg",
            "song.mp3",
            "song.flac",
            "archive.zip",
            "archive.rar",
            "book.cbz",
        ] {
            assert!(
                !should_attempt_upload_compression(name),
                "{name} should not be compressed"
            );
        }
    }

    #[test]
    fn compressible_types_are_attempted() {
        for name in ["notes.txt", "payload.bin", "noextension", "data.dat"] {
            assert!(
                should_attempt_upload_compression(name),
                "{name} should be compressed"
            );
        }
    }
}
