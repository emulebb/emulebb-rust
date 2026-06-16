//! Shared tag/size helpers used across the keyword, source, and notes publish
//! stores. These operate purely on `&[Tag]` slices and never touch the stored
//! publish records, so they sit below the per-domain submodules.

use emulebb_kad_proto::{
    NodeId, SearchRes, SearchResultEntry, Tag, TagName, TagValue, tag_name,
};

pub(super) fn is_integer_tag_value(value: &TagValue) -> bool {
    matches!(
        value,
        TagValue::UInt(_)
            | TagValue::U64(_)
            | TagValue::U32(_)
            | TagValue::U16(_)
            | TagValue::U8(_)
    )
}

pub(super) fn stock_stored_publish_tags(tags: &[Tag]) -> Vec<Tag> {
    tags.iter()
        .filter(|tag| {
            !matches!(
                tag.name,
                TagName::Short(tag_name::PUBLISHINFO | tag_name::KADAICHHASHRESULT)
            )
        })
        .cloned()
        .collect()
}

pub(super) fn search_response(
    sender_id: NodeId,
    target: NodeId,
    results: Vec<SearchResultEntry>,
) -> Option<SearchRes> {
    if results.is_empty() {
        None
    } else {
        Some(SearchRes {
            sender_id,
            target,
            results,
        })
    }
}

pub(super) fn stock_first_filename(tags: &[Tag]) -> Option<String> {
    tags.iter().find_map(|tag| {
        if !matches!(tag.name, TagName::Short(tag_name::FILENAME)) {
            return None;
        }
        match &tag.value {
            TagValue::String(value) if !value.is_empty() => Some(value.clone()),
            _ => None,
        }
    })
}

pub(super) fn stock_first_file_size(tags: &[Tag]) -> Option<u64> {
    stock_first_file_size_impl(tags, false)
}

pub(super) fn stock_first_keyword_source_file_size(tags: &[Tag]) -> Option<u64> {
    stock_first_file_size_impl(tags, true)
}

pub(super) fn stock_first_file_size_impl(tags: &[Tag], accept_bsob_file_size: bool) -> Option<u64> {
    let mut size = None;
    let mut size_low = None;
    let mut size_high = None;

    for tag in tags {
        match (&tag.name, &tag.value) {
            (TagName::Short(name), TagValue::UInt(value)) if *name == tag_name::FILESIZE => {
                if u32::try_from(*value).is_ok() {
                    size_low.get_or_insert(*value as u32);
                } else {
                    size.get_or_insert(*value);
                }
            }
            (TagName::Short(name), TagValue::U64(value)) if *name == tag_name::FILESIZE => {
                size.get_or_insert(*value);
            }
            (TagName::Short(name), TagValue::U32(value)) if *name == tag_name::FILESIZE => {
                size_low.get_or_insert(*value);
            }
            (TagName::Short(name), TagValue::U16(value)) if *name == tag_name::FILESIZE => {
                size_low.get_or_insert(u32::from(*value));
            }
            (TagName::Short(name), TagValue::U8(value)) if *name == tag_name::FILESIZE => {
                size_low.get_or_insert(u32::from(*value));
            }
            (TagName::Short(name), TagValue::Blob(bytes) | TagValue::SmallBlob(bytes))
                if *name == tag_name::FILESIZE && accept_bsob_file_size && bytes.len() == 8 =>
            {
                size.get_or_insert(u64::from_le_bytes(bytes.as_slice().try_into().ok()?));
            }
            (TagName::Short(name), TagValue::UInt(value))
                if *name == tag_name::FILESIZE_HI && u32::try_from(*value).is_ok() =>
            {
                size_high.get_or_insert(*value as u32);
            }
            (TagName::Short(name), TagValue::U32(value)) if *name == tag_name::FILESIZE_HI => {
                size_high.get_or_insert(*value);
            }
            (TagName::Short(name), TagValue::U16(value)) if *name == tag_name::FILESIZE_HI => {
                size_high.get_or_insert(u32::from(*value));
            }
            (TagName::Short(name), TagValue::U8(value)) if *name == tag_name::FILESIZE_HI => {
                size_high.get_or_insert(u32::from(*value));
            }
            _ => {}
        }
    }

    size.or_else(|| {
        size_low.map(|low| {
            let high = size_high.unwrap_or(0);
            (u64::from(high) << 32) | u64::from(low)
        })
    })
}

pub(super) fn stock_source_file_size_matches_request(tags: &[Tag], request_size: u64) -> bool {
    stock_file_size_matches_request(tags, request_size, true)
}

pub(super) fn stock_notes_file_size_matches_request(tags: &[Tag], request_size: u64) -> bool {
    stock_file_size_matches_request(tags, request_size, false)
}

pub(super) fn stock_file_size_matches_request(
    tags: &[Tag],
    request_size: u64,
    accept_bsob_file_size: bool,
) -> bool {
    request_size == 0
        || stock_first_file_size_impl(tags, accept_bsob_file_size)
            .map(|size| size == request_size)
            .unwrap_or(true)
}
