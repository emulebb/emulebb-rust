use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use super::flags::is_low_id;
use super::tag_codec::{DecodedTagName, DecodedTagValue, decode_tag_details};
use super::{
    Ed2kFoundSource, Ed2kSearchFile, FT_AICH_HASH, FT_COMPLETE_SOURCES, FT_FILENAME, FT_FILERATING,
    FT_FILESIZE, FT_FILESIZE_HI, FT_FILETYPE, FT_FOLDERNAME, FT_MEDIA_ALBUM, FT_MEDIA_ARTIST,
    FT_MEDIA_BITRATE, FT_MEDIA_CODEC, FT_MEDIA_LENGTH, FT_MEDIA_TITLE, FT_SOURCES, OP_EDONKEYPROT,
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
    let mut media_artist = None;
    let mut media_album = None;
    let mut media_title = None;
    let mut media_length_seconds = None;
    let mut media_bitrate_kbps = None;
    let mut media_codec = None;
    let mut source_count = None;
    let mut complete_source_count = None;
    let mut rating = None;
    let mut aich_hash = None;
    let mut directory = None;
    for _ in 0..tag_count {
        let (tag, rest) = decode_tag_details(cursor)?;
        cursor = rest;
        match (&tag.name, &tag.value) {
            (DecodedTagName::Numeric(FT_FILENAME), Some(DecodedTagValue::String(value)))
                if name.is_none() =>
            {
                name = Some(value.clone());
            }
            (DecodedTagName::Numeric(FT_FILESIZE), Some(DecodedTagValue::Unsigned(value))) => {
                size = Some(*value);
            }
            (DecodedTagName::Numeric(FT_FILESIZE_HI), Some(DecodedTagValue::Unsigned(value))) => {
                size_hi = Some(*value);
            }
            (DecodedTagName::Numeric(FT_FILETYPE), Some(DecodedTagValue::String(value)))
                if file_type.is_none() =>
            {
                file_type = Some(value.clone());
            }
            (DecodedTagName::Numeric(FT_MEDIA_ARTIST), Some(DecodedTagValue::String(value)))
                if media_artist.is_none() && !value.is_empty() =>
            {
                media_artist = Some(value.clone());
            }
            (DecodedTagName::Text(tag_name), Some(DecodedTagValue::String(value)))
                if tag_name.eq_ignore_ascii_case("artist")
                    && media_artist.is_none()
                    && !value.is_empty() =>
            {
                media_artist = Some(value.clone());
            }
            (DecodedTagName::Numeric(FT_MEDIA_ALBUM), Some(DecodedTagValue::String(value)))
                if media_album.is_none() && !value.is_empty() =>
            {
                media_album = Some(value.clone());
            }
            (DecodedTagName::Text(tag_name), Some(DecodedTagValue::String(value)))
                if tag_name.eq_ignore_ascii_case("album")
                    && media_album.is_none()
                    && !value.is_empty() =>
            {
                media_album = Some(value.clone());
            }
            (DecodedTagName::Numeric(FT_MEDIA_TITLE), Some(DecodedTagValue::String(value)))
                if media_title.is_none() && !value.is_empty() =>
            {
                media_title = Some(value.clone());
            }
            (DecodedTagName::Text(tag_name), Some(DecodedTagValue::String(value)))
                if tag_name.eq_ignore_ascii_case("title")
                    && media_title.is_none()
                    && !value.is_empty() =>
            {
                media_title = Some(value.clone());
            }
            (DecodedTagName::Numeric(FT_MEDIA_LENGTH), Some(value))
                if media_length_seconds.is_none() =>
            {
                media_length_seconds = decode_media_length(value)?;
            }
            (DecodedTagName::Text(tag_name), Some(value))
                if tag_name.eq_ignore_ascii_case("length") && media_length_seconds.is_none() =>
            {
                media_length_seconds = decode_media_length(value)?;
            }
            (DecodedTagName::Numeric(FT_MEDIA_BITRATE), Some(value))
                if media_bitrate_kbps.is_none() =>
            {
                media_bitrate_kbps = decode_media_u32(value, "bitrate")?;
            }
            (DecodedTagName::Text(tag_name), Some(value))
                if tag_name.eq_ignore_ascii_case("bitrate") && media_bitrate_kbps.is_none() =>
            {
                media_bitrate_kbps = decode_media_u32(value, "bitrate")?;
            }
            (DecodedTagName::Numeric(FT_MEDIA_CODEC), Some(DecodedTagValue::String(value)))
                if media_codec.is_none() && !value.is_empty() =>
            {
                media_codec = Some(value.clone());
            }
            (DecodedTagName::Text(tag_name), Some(DecodedTagValue::String(value)))
                if tag_name.eq_ignore_ascii_case("codec")
                    && media_codec.is_none()
                    && !value.is_empty() =>
            {
                media_codec = Some(value.clone());
            }
            (DecodedTagName::Numeric(FT_SOURCES), Some(DecodedTagValue::Unsigned(value))) => {
                source_count = Some(u32::try_from(*value).context("ED2K source count overflow")?);
            }
            (
                DecodedTagName::Numeric(FT_COMPLETE_SOURCES),
                Some(DecodedTagValue::Unsigned(value)),
            ) => {
                complete_source_count =
                    Some(u32::try_from(*value).context("ED2K complete source count overflow")?);
            }
            (DecodedTagName::Numeric(FT_FILERATING), Some(DecodedTagValue::Unsigned(value))) => {
                let packed_average = (*value & u64::from(u8::MAX)) as u8;
                rating = Some((packed_average / (u8::MAX / 5)).min(5));
            }
            (DecodedTagName::Numeric(FT_AICH_HASH), Some(DecodedTagValue::String(value))) => {
                aich_hash = canonical_aich_hash(value);
            }
            (DecodedTagName::Numeric(FT_FOLDERNAME), Some(DecodedTagValue::String(value)))
                if directory.is_none() && !value.is_empty() =>
            {
                directory = Some(value.clone());
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
            media_artist,
            media_album,
            media_title,
            media_length_seconds,
            media_bitrate_kbps,
            media_codec,
            source_count,
            complete_source_count,
            rating,
            aich_hash,
            directory,
        },
        cursor,
    ))
}

fn decode_media_length(value: &DecodedTagValue) -> Result<Option<u32>> {
    match value {
        DecodedTagValue::Unsigned(_) => decode_media_u32(value, "length"),
        DecodedTagValue::String(value) => Ok(parse_media_length(value)),
        _ => Ok(None),
    }
}

fn decode_media_u32(value: &DecodedTagValue, field: &str) -> Result<Option<u32>> {
    match value {
        DecodedTagValue::Unsigned(value) => Ok(Some(
            u32::try_from(*value).with_context(|| format!("ED2K media {field} overflow"))?,
        )),
        DecodedTagValue::String(value) => Ok(value.trim().parse::<u32>().ok()),
        _ => Ok(None),
    }
}

fn parse_media_length(value: &str) -> Option<u32> {
    let parts = value
        .trim()
        .split(':')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    match parts.as_slice() {
        [seconds] => Some(*seconds),
        [minutes, seconds] if *seconds < 60 => minutes.checked_mul(60)?.checked_add(*seconds),
        [hours, minutes, seconds] if *minutes < 60 && *seconds < 60 => hours
            .checked_mul(3_600)?
            .checked_add(minutes.checked_mul(60)?)?
            .checked_add(*seconds),
        _ => None,
    }
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
    use super::super::tag_codec::{
        push_named_int_tag, push_named_string_tag, push_short_int_tag, push_short_string_tag,
    };
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

    #[test]
    fn search_result_decodes_stock_media_tags() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0x22; 16]);
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(&[0u8; 2]);
        payload.extend_from_slice(&7u32.to_le_bytes());
        push_short_string_tag(&mut payload, FT_FILENAME, "Example.mp3");
        push_short_string_tag(&mut payload, FT_MEDIA_ARTIST, "Example Artist");
        push_short_string_tag(&mut payload, FT_MEDIA_ALBUM, "Example Album");
        push_short_string_tag(&mut payload, FT_MEDIA_TITLE, "Example Title");
        push_short_int_tag(&mut payload, FT_MEDIA_LENGTH, 321);
        push_short_int_tag(&mut payload, FT_MEDIA_BITRATE, 192);
        push_short_string_tag(&mut payload, FT_MEDIA_CODEC, "MP3");
        payload.push(0x00);

        let page = decode_search_result_page(&payload).expect("media result decodes");
        let file = &page.files[0];
        assert_eq!(file.media_artist.as_deref(), Some("Example Artist"));
        assert_eq!(file.media_album.as_deref(), Some("Example Album"));
        assert_eq!(file.media_title.as_deref(), Some("Example Title"));
        assert_eq!(file.media_length_seconds, Some(321));
        assert_eq!(file.media_bitrate_kbps, Some(192));
        assert_eq!(file.media_codec.as_deref(), Some("MP3"));
    }

    #[test]
    fn legacy_media_length_text_parses_stock_clock_formats() {
        assert_eq!(parse_media_length("321"), Some(321));
        assert_eq!(parse_media_length("05:21"), Some(321));
        assert_eq!(parse_media_length("01:05:21"), Some(3_921));
        assert_eq!(parse_media_length("05:99"), None);
        assert_eq!(parse_media_length("not-a-duration"), None);
    }

    #[test]
    fn search_result_decodes_legacy_named_media_tags() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0x33; 16]);
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(&[0u8; 2]);
        payload.extend_from_slice(&7u32.to_le_bytes());
        push_short_string_tag(&mut payload, FT_FILENAME, "Legacy.mp3");
        push_named_string_tag(&mut payload, "artist", "Example Artist");
        push_named_string_tag(&mut payload, "album", "Example Album");
        push_named_string_tag(&mut payload, "title", "Example Title");
        push_named_string_tag(&mut payload, "length", "05:21");
        push_named_int_tag(&mut payload, "bitrate", 192);
        push_named_string_tag(&mut payload, "codec", "MP3");
        payload.push(0x00);

        let page = decode_search_result_page(&payload).expect("legacy media result decodes");
        let file = &page.files[0];
        assert_eq!(file.media_artist.as_deref(), Some("Example Artist"));
        assert_eq!(file.media_album.as_deref(), Some("Example Album"));
        assert_eq!(file.media_title.as_deref(), Some("Example Title"));
        assert_eq!(file.media_length_seconds, Some(321));
        assert_eq!(file.media_bitrate_kbps, Some(192));
        assert_eq!(file.media_codec.as_deref(), Some("MP3"));
    }
}
