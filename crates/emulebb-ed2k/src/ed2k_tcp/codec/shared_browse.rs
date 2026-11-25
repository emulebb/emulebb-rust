//! eD2K peer shared-list records and opaque directory labels.
use anyhow::{Context, Result, ensure};
use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_server::{
        FT_FILENAME, FT_FILESIZE, FT_FILETYPE, TAGTYPE_UINT64, ed2k_file_type_search_term,
        ed2k_offer_file_type,
        tag_codec::{
            DecodedTagValue, decode_tag_value, push_short_int_tag, push_short_string_tag,
            push_string_tag, push_u32_tag,
        },
    },
    ed2k_string::Ed2kStringEncoding,
    ed2k_tcp::{
        MAX_ED2K_PACKET_LEN, OP_ASKSHAREDDIRSANS, OP_ASKSHAREDFILESANSWER, OP_ASKSHAREDFILESDIR,
        OP_ASKSHAREDFILESDIRANS, OP_EDONKEYPROT,
    },
    ed2k_transfer::{ED2K_LEGACY_FILE_SIZE_MAX, is_low_id_client_id},
};

use super::encode_packet;

pub(in crate::ed2k_tcp) const BROWSE_MAX_PAYLOAD: usize = MAX_ED2K_PACKET_LEN;
const OFFER_HEADER_SIZE: usize = 16 + 4 + 2 + 4;
const FT_FILEFORMAT: u8 = 0x04;

/// Public metadata in an offered peer file record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerBrowseFile {
    pub file_hash: Ed2kHash,
    pub display_name: String,
    pub file_size: u64,
}

/// Negotiated wire capabilities and this client's reachable HighID endpoint.
#[derive(Clone, Copy, Debug)]
pub(in crate::ed2k_tcp) struct PeerBrowseEncoding {
    pub strings: Ed2kStringEncoding,
    pub compact_tags: bool,
    pub emule_family: bool,
    pub supports_large_files: bool,
    pub local_endpoint: Option<(u32, u16)>,
}

#[derive(Debug)]
pub(in crate::ed2k_tcp) struct BrowseReplyTooLarge;

impl std::fmt::Display for BrowseReplyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("complete shared-file browse reply exceeds the peer packet limit")
    }
}

impl std::error::Error for BrowseReplyTooLarge {}

fn check_size(size: usize) -> Result<()> {
    if size > BROWSE_MAX_PAYLOAD {
        return Err(BrowseReplyTooLarge.into());
    }
    Ok(())
}

fn check_display_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && !name.contains(['/', '\\', '\0']) && name != "." && name != "..",
        "expected a shared-file display name"
    );
    Ok(())
}

fn write_file(
    payload: &mut Vec<u8>,
    file: &PeerBrowseFile,
    peer: PeerBrowseEncoding,
) -> Result<bool> {
    let large = file.file_size > ED2K_LEGACY_FILE_SIZE_MAX;
    if large && !peer.supports_large_files {
        return Ok(false);
    }
    check_display_name(&file.display_name)?;
    // A display name is a wire string. Validate before calling the shared tag writers.
    ensure!(
        u16::try_from(peer.strings.encode(&file.display_name).len()).is_ok(),
        "shared filename exceeds u16 wire length"
    );
    let (id, port) = peer
        .local_endpoint
        .filter(|(id, port)| *id != 0 && !is_low_id_client_id(*id) && *port != 0)
        .unwrap_or_default();
    let file_type = ed2k_file_type_search_term(ed2k_offer_file_type(&file.display_name));
    let file_format = (!peer.emule_family)
        .then(|| file.display_name.rsplit_once('.'))
        .flatten()
        .map(|(_, suffix)| suffix)
        .filter(|suffix| !suffix.is_empty());
    let count = 2 + u32::from(file_type.is_some()) + u32::from(file_format.is_some());
    payload.extend_from_slice(&file.file_hash.0);
    payload.extend_from_slice(&id.to_le_bytes());
    payload.extend_from_slice(&port.to_le_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    let write_string = if peer.compact_tags {
        push_short_string_tag
    } else {
        push_string_tag
    };
    write_string(payload, FT_FILENAME, &file.display_name, peer.strings);
    if peer.compact_tags {
        push_short_int_tag(payload, FT_FILESIZE, file.file_size);
    } else if large {
        payload.extend_from_slice(&[TAGTYPE_UINT64, 1, 0, FT_FILESIZE]);
        payload.extend_from_slice(&file.file_size.to_le_bytes());
    } else {
        push_u32_tag(payload, FT_FILESIZE, u32::try_from(file.file_size)?);
    }
    if let Some(term) = file_type {
        write_string(payload, FT_FILETYPE, term, peer.strings);
    }
    if let Some(extension) = file_format {
        write_string(
            payload,
            FT_FILEFORMAT,
            &extension.to_ascii_lowercase(),
            peer.strings,
        );
    }
    Ok(true)
}

/// Exact catalog preflight cost. A file excluded by the large-file gate occupies zero bytes.
pub(in crate::ed2k_tcp) fn browse_file_entry_len(
    file: &PeerBrowseFile,
    peer: PeerBrowseEncoding,
) -> Result<usize> {
    let mut entry = Vec::new();
    write_file(&mut entry, file, peer)?;
    Ok(entry.len())
}

/// Encode one complete flat or per-directory reply. A directory is its original wire label.
pub(in crate::ed2k_tcp) fn encode_browse_files(
    files: &[PeerBrowseFile],
    directory: Option<&[u8]>,
    peer: PeerBrowseEncoding,
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    if let Some(label) = directory {
        write_directory(&mut payload, label)?;
    }
    let count_offset = payload.len();
    payload.extend_from_slice(&0u32.to_le_bytes());
    let mut count = 0u32;
    for file in files {
        if write_file(&mut payload, file, peer)? {
            check_size(payload.len())?;
            count += 1;
        }
    }
    payload[count_offset..count_offset + 4].copy_from_slice(&count.to_le_bytes());
    let opcode = if directory.is_some() {
        OP_ASKSHAREDFILESDIRANS
    } else {
        OP_ASKSHAREDFILESANSWER
    };
    Ok(encode_packet(OP_EDONKEYPROT, opcode, &payload))
}

/// Parse the files after the optional directory prefix. Validate before reserving output storage.
pub(in crate::ed2k_tcp) fn decode_browse_files(
    payload: &[u8],
    strings: Ed2kStringEncoding,
    max_files: usize,
) -> Result<Vec<PeerBrowseFile>> {
    let (count, mut rest) = read_count(payload, max_files, OFFER_HEADER_SIZE)?;
    let mut files = Vec::new();
    for _ in 0..count {
        let (header, mut tags) = rest
            .split_at_checked(OFFER_HEADER_SIZE)
            .context("short offered file header")?;
        let file_hash = Ed2kHash::from_bytes(header[..16].try_into()?);
        let tag_count = u32::from_le_bytes(header[22..26].try_into()?);
        let mut name = None;
        let mut size = None;
        for _ in 0..tag_count {
            let (key, value, next) = decode_tag_value(tags, strings)?;
            match (key, value) {
                (Some(FT_FILENAME), Some(DecodedTagValue::String(value))) => {
                    ensure!(name.is_none(), "duplicate offered filename");
                    check_display_name(&value)?;
                    name = Some(value);
                }
                (Some(FT_FILESIZE), Some(DecodedTagValue::Unsigned(value))) => {
                    ensure!(size.replace(value).is_none(), "duplicate offered filesize");
                }
                _ => {}
            }
            tags = next;
        }
        files.push(PeerBrowseFile {
            file_hash,
            display_name: name.context("missing offered filename")?,
            file_size: size.context("missing offered filesize")?,
        });
        rest = tags;
    }
    ensure!(rest.is_empty(), "trailing shared-file list data");
    Ok(files)
}

fn read_count(payload: &[u8], limit: usize, minimum_size: usize) -> Result<(usize, &[u8])> {
    check_size(payload.len())?;
    let (prefix, rest) = payload
        .split_at_checked(4)
        .context("short shared-list count")?;
    let count = usize::try_from(u32::from_le_bytes(prefix.try_into()?))?;
    ensure!(
        count <= limit && count <= rest.len() / minimum_size,
        "shared-list count exceeds available records or browse limit"
    );
    Ok((count, rest))
}

fn write_directory(payload: &mut Vec<u8>, label: &[u8]) -> Result<()> {
    let len = u16::try_from(label.len()).context("browse directory exceeds u16 wire length")?;
    check_size(payload.len() + 2 + label.len())?;
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(label);
    Ok(())
}

/// Preserve the exact directory bytes, including legacy strings that decode ambiguously.
pub(in crate::ed2k_tcp) fn split_browse_directory(payload: &[u8]) -> Result<(&[u8], &[u8])> {
    check_size(payload.len())?;
    let (prefix, rest) = payload
        .split_at_checked(2)
        .context("short directory length")?;
    let len = usize::from(u16::from_le_bytes(prefix.try_into()?));
    rest.split_at_checked(len).context("short directory label")
}

pub(in crate::ed2k_tcp) fn encode_browse_dir_request(raw: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    write_directory(&mut payload, raw)?;
    Ok(encode_packet(
        OP_EDONKEYPROT,
        OP_ASKSHAREDFILESDIR,
        &payload,
    ))
}

pub(in crate::ed2k_tcp) fn encode_browse_dirs(labels: &[Vec<u8>]) -> Result<Vec<u8>> {
    let count = u32::try_from(labels.len()).map_err(|_| BrowseReplyTooLarge)?;
    let mut payload = count.to_le_bytes().to_vec();
    for label in labels {
        write_directory(&mut payload, label)?;
    }
    Ok(encode_packet(OP_EDONKEYPROT, OP_ASKSHAREDDIRSANS, &payload))
}

pub(in crate::ed2k_tcp) fn decode_browse_dirs(
    payload: &[u8],
    max_dirs: usize,
) -> Result<Vec<Vec<u8>>> {
    let (count, mut rest) = read_count(payload, max_dirs, 2)?;
    let mut dirs = Vec::new();
    for _ in 0..count {
        let (label, next) = split_browse_directory(rest)?;
        dirs.push(label.to_vec());
        rest = next;
    }
    ensure!(rest.is_empty(), "trailing shared-directory list data");
    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerBrowseEncoding {
        PeerBrowseEncoding {
            strings: Ed2kStringEncoding::Utf8,
            compact_tags: true,
            emule_family: true,
            supports_large_files: true,
            local_endpoint: Some((0x1234_5678, 4662)),
        }
    }

    fn file(size: u64) -> PeerBrowseFile {
        PeerBrowseFile {
            file_hash: Ed2kHash([0x45; 16]),
            display_name: "A".into(),
            file_size: size,
        }
    }

    #[test]
    fn compact_peer_entry_matches_known_bytes() {
        let offered = file(254);
        let frame = encode_browse_files(std::slice::from_ref(&offered), None, peer()).unwrap();
        let mut expected = vec![1, 0, 0, 0];
        expected.extend_from_slice(&[0x45; 16]);
        expected.extend_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0x36, 0x12, 2, 0, 0, 0, 0x91, 1, b'A', 0x89, 2, 254,
        ]);
        assert_eq!(frame[5], OP_ASKSHAREDFILESANSWER);
        assert_eq!(frame[6..], expected);
        assert_eq!(
            browse_file_entry_len(&offered, peer()).unwrap(),
            expected.len() - 4
        );
        assert_eq!(
            decode_browse_files(&expected, peer().strings, 1).unwrap(),
            vec![offered]
        );
    }

    #[test]
    fn peer_file_size_is_one_tag_and_large_file_capability_controls_inclusion() {
        for (size, legacy_type, compact_type) in [
            (ED2K_LEGACY_FILE_SIZE_MAX, 0x03, 0x83),
            (ED2K_LEGACY_FILE_SIZE_MAX + 1, 0x0B, 0x83),
            (u64::from(u32::MAX) + 1, 0x0B, 0x8B),
        ] {
            let offered = file(size);
            for compact in [false, true] {
                let wire = PeerBrowseEncoding {
                    compact_tags: compact,
                    ..peer()
                };
                let encoded =
                    encode_browse_files(std::slice::from_ref(&offered), None, wire).unwrap();
                let tags = &encoded[6 + 4 + OFFER_HEADER_SIZE..];
                let (_, _, size_tag) = decode_tag_value(tags, wire.strings).unwrap();
                assert_eq!(
                    size_tag[0],
                    if compact { compact_type } else { legacy_type }
                );
                let (key, value, rest) = decode_tag_value(size_tag, wire.strings).unwrap();
                assert_eq!(key, Some(FT_FILESIZE));
                assert_eq!(value, Some(DecodedTagValue::Unsigned(size)));
                assert!(rest.is_empty());
            }
            let legacy = PeerBrowseEncoding {
                supports_large_files: false,
                ..peer()
            };
            let frame = encode_browse_files(std::slice::from_ref(&offered), None, legacy).unwrap();
            let decoded = decode_browse_files(&frame[6..], legacy.strings, 1).unwrap();
            assert_eq!(
                decoded.len(),
                usize::from(size <= ED2K_LEGACY_FILE_SIZE_MAX)
            );
        }
    }

    #[test]
    fn only_reachable_high_id_has_an_endpoint() {
        for endpoint in [
            None,
            Some((0, 4662)),
            Some((0xFF_FFFF, 4662)),
            Some((0x100_0000, 0)),
        ] {
            let wire = PeerBrowseEncoding {
                local_endpoint: endpoint,
                ..peer()
            };
            let frame = encode_browse_files(&[file(1)], None, wire).unwrap();
            assert_eq!(frame[26..32], [0; 6]);
        }
    }

    #[test]
    fn directory_labels_are_echoed_byte_for_byte() {
        let raw = vec![0xE9, 0x81, 0xEF, 0xBB, 0xBF];
        let list = encode_browse_dirs(std::slice::from_ref(&raw)).unwrap();
        let decoded = decode_browse_dirs(&list[6..], 1).unwrap();
        assert_eq!(decoded, vec![raw.clone()]);
        let request = encode_browse_dir_request(&decoded[0]).unwrap();
        assert_eq!(
            split_browse_directory(&request[6..]).unwrap(),
            (raw.as_slice(), &[][..])
        );
        let frame = encode_browse_files(&[file(12)], Some(&raw), peer()).unwrap();
        let (label, body) = split_browse_directory(&frame[6..]).unwrap();
        assert_eq!(label, raw);
        assert_eq!(
            decode_browse_files(body, peer().strings, 1).unwrap(),
            vec![file(12)]
        );
    }

    #[test]
    fn full_directory_reply_fits_at_payload_limit() {
        let mut labels = vec![vec![b'a'; 62_498]; 32];
        labels[0].truncate(62_494);
        let frame = encode_browse_dirs(&labels).unwrap();
        assert_eq!(frame.len() - 6, BROWSE_MAX_PAYLOAD);
        labels[0].push(b'b');
        assert!(
            encode_browse_dirs(&labels)
                .unwrap_err()
                .is::<BrowseReplyTooLarge>()
        );
    }

    #[test]
    fn filename_uses_negotiated_legacy_encoding() {
        let wire = PeerBrowseEncoding {
            compact_tags: false,
            strings: Ed2kStringEncoding::Legacy,
            ..peer()
        };
        let mut offered = file(1);
        offered.display_name = "Café".into();
        let frame = encode_browse_files(std::slice::from_ref(&offered), None, wire).unwrap();
        let expected = wire.strings.encode(&offered.display_name);
        let name_start = 6 + 4 + OFFER_HEADER_SIZE + 6;
        assert_eq!(&frame[name_start..name_start + expected.len()], expected);
        let decoded = decode_browse_files(&frame[6..], wire.strings, 1).unwrap();
        assert_eq!(decoded[0].display_name, wire.strings.decode(&expected));
    }

    #[test]
    fn legacy_peer_receives_type_and_lowercase_format_tags() {
        let wire = PeerBrowseEncoding {
            compact_tags: false,
            strings: Ed2kStringEncoding::Legacy,
            emule_family: false,
            ..peer()
        };
        let mut offered = file(1);
        offered.display_name = "Alpha.PDF".into();
        let frame = encode_browse_files(std::slice::from_ref(&offered), None, wire).unwrap();
        let mut tags = &frame[6 + 4 + OFFER_HEADER_SIZE..];
        let mut values = Vec::new();
        while !tags.is_empty() {
            let (name, value, rest) = decode_tag_value(tags, wire.strings).unwrap();
            values.push((name, value));
            tags = rest;
        }
        assert_eq!(
            values[2],
            (
                Some(FT_FILETYPE),
                Some(DecodedTagValue::String("Doc".into()))
            )
        );
        assert_eq!(
            values[3],
            (
                Some(FT_FILEFORMAT),
                Some(DecodedTagValue::String("pdf".into()))
            )
        );
        assert_eq!(
            decode_browse_files(&frame[6..], wire.strings, 1).unwrap(),
            vec![offered]
        );
    }

    #[test]
    fn reject_truncated_uncounted_and_overbudget_replies() {
        let mut payload = encode_browse_files(&[file(1)], None, peer())
            .unwrap()
            .split_off(6);
        assert!(decode_browse_files(&payload, peer().strings, 0).is_err());
        payload.push(0);
        assert!(decode_browse_files(&payload, peer().strings, 1).is_err());
        payload.truncate(payload.len() - 2);
        assert!(decode_browse_files(&payload, peer().strings, 1).is_err());
        assert!(decode_browse_dirs(&[1, 0, 0, 0, 2, 0, 1], 1).is_err());
        let labels = vec![vec![b'x'; 62_500]; 32];
        assert!(
            encode_browse_dirs(&labels)
                .unwrap_err()
                .is::<BrowseReplyTooLarge>()
        );
        let mut entry = file(1);
        entry.display_name = "A".repeat(62_500);
        let oversized = vec![entry; 32];
        assert!(
            encode_browse_files(&oversized, None, peer())
                .unwrap_err()
                .is::<BrowseReplyTooLarge>()
        );
    }
}
