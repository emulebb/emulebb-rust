use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use super::flags::is_low_id;
use super::tag_codec::{DecodedTagValue, decode_tag_value};
use super::{
    Ed2kFoundSource, Ed2kSearchFile, FT_FILENAME, FT_FILESIZE, FT_FILESIZE_HI, FT_FILETYPE,
    FT_SOURCES, OP_EDONKEYPROT, OP_GLOBFOUNDSOURCES, OP_GLOBSEARCHRES,
    SOURCE_OBFUSCATION_USER_HASH_PRESENT, ipv4_from_client_id,
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
    let (page, rest) = decode_search_result_page_from(payload)?;
    if !rest.is_empty() {
        anyhow::bail!(
            "unexpected ED2K search trailing data len={} after result page",
            rest.len()
        );
    }
    Ok(page)
}

pub(super) fn decode_udp_search_result_pages(payload: &[u8]) -> Result<Vec<SearchResultPage>> {
    let mut cursor = payload;
    let mut pages = Vec::new();
    while !cursor.is_empty() {
        let (page, rest) = decode_search_result_page_from(cursor)?;
        pages.push(page);
        cursor = rest;
    }
    Ok(pages)
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
    let mut files = Vec::with_capacity(count as usize);

    for _ in 0..count {
        if cursor.len() < 26 {
            anyhow::bail!("short ED2K search result entry");
        }
        let file_hash = Ed2kHash(cursor[..16].try_into().unwrap());
        cursor = &cursor[16..];
        cursor = &cursor[4..];
        cursor = &cursor[2..];
        let tag_count = u32::from_le_bytes(cursor[..4].try_into().unwrap());
        cursor = &cursor[4..];
        let mut name = None;
        let mut size = None;
        let mut size_hi = None;
        let mut file_type = None;
        let mut source_count = None;
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
                (Some(FT_FILETYPE), Some(DecodedTagValue::String(value)))
                    if file_type.is_none() =>
                {
                    file_type = Some(value);
                }
                (Some(FT_SOURCES), Some(DecodedTagValue::Unsigned(value))) => {
                    source_count =
                        Some(u32::try_from(value).context("ED2K source count overflow")?);
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
        files.push(Ed2kSearchFile {
            file_hash,
            file_name: name,
            file_size,
            file_type,
            source_count,
        });
    }

    let (more_results_available, rest) = match cursor {
        [] => (false, &[][..]),
        [marker @ (0x00 | 0x01)] => (*marker != 0, &[][..]),
        [marker @ (0x00 | 0x01), rest @ ..] if udp_chain_matches(rest, OP_GLOBSEARCHRES) => {
            (*marker != 0, &rest[2..])
        }
        rest if udp_chain_matches(rest, OP_GLOBSEARCHRES) => (false, &rest[2..]),
        [marker] => anyhow::bail!("invalid ED2K search More marker 0x{marker:02X}"),
        _ => anyhow::bail!(
            "unexpected ED2K search trailing data len={} after result page",
            cursor.len()
        ),
    };

    Ok((
        SearchResultPage {
            files,
            more_results_available,
        },
        rest,
    ))
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
