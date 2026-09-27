use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use super::flags::is_low_id;
use super::tag_codec::{DecodedTagValue, decode_tag_value};
use super::{
    Ed2kFoundSource, Ed2kSearchFile, FT_AICH_HASH, FT_COMPLETE_SOURCES, FT_FILENAME, FT_FILERATING,
    FT_FILESIZE, FT_FILESIZE_HI, FT_FILETYPE, FT_FOLDERNAME, FT_SOURCES, OP_EDONKEYPROT,
    OP_GLOBFOUNDSOURCES, OP_GLOBSEARCHRES, SOURCE_OBFUSCATION_USER_HASH_PRESENT,
    ipv4_from_client_id,
};

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SearchResultSummary {
    pub(super) count: u32,
    pub(super) sample_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SearchResultPage {
    pub(super) files: Vec<Ed2kSearchFile>,
    pub(super) more_results_available: bool,
}

#[cfg(test)]
pub(super) fn decode_search_results(payload: &[u8]) -> Result<SearchResultSummary> {
    let page = decode_search_result_page(payload)?;
    let sample_names = page
        .files
        .iter()
        .filter_map(|file| file.file_name.clone())
        .take(3)
        .collect::<Vec<_>>();
    Ok(SearchResultSummary {
        count: u32::try_from(page.files.len()).expect("search result count fits in u32"),
        sample_names,
    })
}

pub(super) fn decode_search_result_page(payload: &[u8]) -> Result<SearchResultPage> {
    let (page, _) = decode_search_result_page_from(payload)?;
    Ok(page)
}

pub(super) fn decode_udp_search_result_pages(payload: &[u8]) -> Result<Vec<SearchResultPage>> {
    let mut cursor = payload;
    let mut files = Vec::new();
    while !cursor.is_empty() {
        if udp_chain_matches(cursor, OP_GLOBSEARCHRES) {
            cursor = &cursor[2..];
            continue;
        }
        let (file, rest) = decode_search_result_entry(cursor)?;
        files.push(file);
        cursor = if udp_chain_matches(rest, OP_GLOBSEARCHRES) {
            &rest[2..]
        } else {
            rest
        };
    }
    if files.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![SearchResultPage {
        files,
        more_results_available: false,
    }])
}

pub(super) fn decode_udp_found_source_sets(payload: &[u8]) -> Result<Vec<Vec<Ed2kFoundSource>>> {
    let mut cursor = payload;
    let mut sets = Vec::new();
    while !cursor.is_empty() {
        let (sources, rest) = decode_found_sources_from(cursor, false)?;
        sets.push(sources);
        cursor = rest;
    }
    Ok(sets)
}

pub(super) fn decode_found_sources(
    payload: &[u8],
    obfuscated: bool,
) -> Result<Vec<Ed2kFoundSource>> {
    let (results, rest) = decode_found_sources_from(payload, obfuscated)?;
    if !rest.is_empty() {
        anyhow::bail!(
            "unexpected ED2K found-sources trailing data len={}",
            rest.len()
        );
    }
    Ok(results)
}

fn decode_search_result_page_from(payload: &[u8]) -> Result<(SearchResultPage, &[u8])> {
    if payload.len() < 4 {
        anyhow::bail!("short ED2K search results payload");
    }
    let count = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let mut cursor = &payload[4..];
    // `count` is attacker-controlled (it heads an OP_SEARCHRESULT /
    // OP_GLOBSEARCHRES payload). The smallest possible result entry is
    // MIN_SEARCH_ENTRY_SIZE bytes (the per-entry short-input guard below), so a
    // payload can never carry more than `cursor.len() / MIN_SEARCH_ENTRY_SIZE`
    // entries. Cap the pre-allocation to that bound so a bogus count (e.g.
    // 0xFFFFFFFF) cannot trigger a multi-hundred-GB `Vec::with_capacity` reserve
    // that would abort the process. Legitimate packets are unaffected: their real
    // entries always fit within the bound, so nothing is dropped.
    const MIN_SEARCH_ENTRY_SIZE: usize = 26;
    let mut files = Vec::with_capacity((count as usize).min(cursor.len() / MIN_SEARCH_ENTRY_SIZE));

    for _ in 0..count {
        let (file, rest) = decode_search_result_entry(cursor)?;
        files.push(file);
        cursor = rest;
    }

    // Stock treats the tail as a More flag only when exactly one byte remains
    // and that byte is 0 or 1. A different one-byte value or any longer tail is
    // diagnostic add-data: it is ignored and the page completes normally.
    let more_results_available = match cursor {
        [0x00] => false,
        [0x01] => true,
        _ => false,
    };

    Ok((
        SearchResultPage {
            files,
            more_results_available,
        },
        &[][..],
    ))
}

fn decode_search_result_entry(payload: &[u8]) -> Result<(Ed2kSearchFile, &[u8])> {
    const MIN_SEARCH_ENTRY_SIZE: usize = 26;
    if payload.len() < MIN_SEARCH_ENTRY_SIZE {
        anyhow::bail!("short ED2K search result entry");
    }
    let file_hash = Ed2kHash(payload[..16].try_into().unwrap());
    let client_id = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    let client_port = u16::from_le_bytes(payload[20..22].try_into().unwrap());
    let mut cursor = &payload[22..];
    let tag_count = u32::from_le_bytes(cursor[..4].try_into().unwrap());
    cursor = &cursor[4..];
    let mut name = None;
    let mut size = None;
    let mut size_hi = None;
    let mut file_type = None;
    let mut source_count = None;
    let mut complete_source_count = None;
    let mut rating = None;
    let mut aich_hash = None;
    let mut directory = None;
    for _ in 0..tag_count {
        let (tag_name, tag_value, rest) = decode_tag_value(cursor)?;
        cursor = rest;
        match (tag_name, tag_value) {
            (Some(FT_FILENAME), Some(DecodedTagValue::String(value))) if name.is_none() => {
                name = Some(value);
            }
            (Some(FT_FILESIZE), Some(DecodedTagValue::Unsigned(value))) => {
                size = Some(value);
            }
            (Some(FT_FILESIZE_HI), Some(DecodedTagValue::Unsigned(value))) => {
                size_hi = Some(value);
            }
            (Some(FT_FILETYPE), Some(DecodedTagValue::String(value))) if file_type.is_none() => {
                file_type = Some(value);
            }
            (Some(FT_SOURCES), Some(DecodedTagValue::Unsigned(value))) => {
                source_count = Some(u32::try_from(value).context("ED2K source count overflow")?);
            }
            (Some(FT_COMPLETE_SOURCES), Some(DecodedTagValue::Unsigned(value))) => {
                complete_source_count =
                    Some(u32::try_from(value).context("ED2K complete source count overflow")?);
            }
            (Some(FT_FILERATING), Some(DecodedTagValue::Unsigned(value))) => {
                let packed_average = (value & u64::from(u8::MAX)) as u8;
                rating = Some((packed_average / (u8::MAX / 5)).min(5));
            }
            (Some(FT_AICH_HASH), Some(DecodedTagValue::String(value))) => {
                aich_hash = canonical_aich_hash(&value);
            }
            (Some(FT_FOLDERNAME), Some(DecodedTagValue::String(value)))
                if directory.is_none() && !value.is_empty() =>
            {
                directory = Some(value);
            }
            _ => {}
        }
    }
    let file_size = match (size, size_hi) {
        (Some(value), Some(upper)) if value <= u32::MAX as u64 && upper != 0 => {
            Some((upper << 32) | value)
        }
        (Some(value), _) => Some(value),
        (None, Some(upper)) => Some(upper << 32),
        (None, None) => None,
    };
    Ok((
        Ed2kSearchFile {
            file_hash,
            client_id,
            client_port,
            file_name: name,
            file_size,
            file_type,
            source_count,
            complete_source_count,
            rating,
            aich_hash,
            directory,
        },
        cursor,
    ))
}

fn canonical_aich_hash(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || (b'2'..=b'7').contains(&byte)))
    .then(|| value.to_ascii_uppercase())
}

fn decode_found_sources_from(
    payload: &[u8],
    obfuscated: bool,
) -> Result<(Vec<Ed2kFoundSource>, &[u8])> {
    if payload.len() < 17 {
        anyhow::bail!("short ED2K found-sources payload");
    }
    let file_hash = Ed2kHash(payload[..16].try_into().unwrap());
    let count = usize::from(payload[16]);
    let mut cursor = &payload[17..];
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor.len() < 6 {
            anyhow::bail!("short ED2K found-sources entry");
        }
        let client_id = u32::from_le_bytes(cursor[..4].try_into().unwrap());
        let ip = ipv4_from_client_id(client_id);
        let tcp_port = u16::from_le_bytes(cursor[4..6].try_into().unwrap());
        let low_id = is_low_id(client_id);
        cursor = &cursor[6..];
        let mut obfuscation_options = None;
        let mut user_hash = None;
        if obfuscated {
            if cursor.is_empty() {
                anyhow::bail!("short ED2K obfuscated source options");
            }
            let options = cursor[0];
            cursor = &cursor[1..];
            obfuscation_options = Some(options);
            if options & SOURCE_OBFUSCATION_USER_HASH_PRESENT != 0 {
                if cursor.len() < 16 {
                    anyhow::bail!("short ED2K obfuscated source user hash");
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&cursor[..16]);
                cursor = &cursor[16..];
                user_hash = Some(hash);
            }
        }
        results.push(Ed2kFoundSource {
            file_hash,
            ip,
            tcp_port,
            client_id,
            low_id,
            obfuscated,
            obfuscation_options,
            user_hash,
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        });
    }

    let rest = if udp_chain_matches(cursor, OP_GLOBFOUNDSOURCES) {
        &cursor[2..]
    } else {
        cursor
    };
    Ok((results, rest))
}

fn udp_chain_matches(payload: &[u8], opcode: u8) -> bool {
    payload.len() >= 2 && payload[0] == OP_EDONKEYPROT && payload[1] == opcode
}

#[cfg(test)]
mod tests {
    use super::super::tag_codec::push_short_string_tag;
    use super::*;

    #[test]
    fn huge_search_count_does_not_over_allocate() {
        // A malicious server sends a 4-byte payload claiming 0xFFFFFFFF results.
        // Without the pre-allocation cap this would request ~378 GB via
        // `Vec::with_capacity` and abort the process. With the cap it must decode
        // to a clean error (the very first entry is short) and never abort.
        let payload = [0xFFu8, 0xFF, 0xFF, 0xFF];
        let result = decode_search_result_page(&payload);
        assert!(
            result.is_err(),
            "tiny payload with a bogus count must error, not panic/abort"
        );
    }

    #[test]
    fn legitimate_search_count_still_decodes() {
        // Header count=1 followed by one well-formed entry with a single
        // filename tag. The cap must not drop the legitimate result.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // count
        payload.extend_from_slice(&[0u8; 16]); // file hash
        payload.extend_from_slice(&[0u8; 4]); // client id
        payload.extend_from_slice(&[0u8; 2]); // port
        payload.extend_from_slice(&1u32.to_le_bytes()); // tag count = 1
        push_short_string_tag(&mut payload, FT_FILENAME, "a.txt"); // one filename tag
        payload.push(0x00); // more-results marker

        let page = decode_search_result_page(&payload).expect("legitimate page decodes");
        assert_eq!(page.files.len(), 1);
        assert_eq!(page.files[0].file_name.as_deref(), Some("a.txt"));
    }

    #[test]
    fn udp_search_result_decodes_single_entry_without_count_prefix() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x11; 16]); // file hash
        payload.extend_from_slice(&[0u8; 4]); // client id
        payload.extend_from_slice(&[0u8; 2]); // port
        payload.extend_from_slice(&2u32.to_le_bytes()); // tag count
        push_short_string_tag(&mut payload, FT_FILENAME, "Sample Payload.bin");
        super::super::tag_codec::push_u32_tag(&mut payload, FT_FILESIZE, 12345);

        let pages = decode_udp_search_result_pages(&payload).expect("UDP result decodes");

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].files.len(), 1);
        assert_eq!(
            pages[0].files[0].file_name.as_deref(),
            Some("Sample Payload.bin")
        );
        assert_eq!(pages[0].files[0].file_size, Some(12345));
    }
}
