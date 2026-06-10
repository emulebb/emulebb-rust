use std::io::{Cursor, Read};

use emulebb_kad_proto::{Tag, TagName, TagValue, tag_name};

const MAX_SEARCH_EXPR_DEPTH: u8 = 24;
const INVALID_KAD_KEYWORD_CHARS: &str = " ()[]{}<>,._-!?:;\\/\"";

#[derive(Debug, Clone, PartialEq)]
enum SearchTerm {
    And(Box<SearchTerm>, Box<SearchTerm>),
    Or(Box<SearchTerm>, Box<SearchTerm>),
    Not(Box<SearchTerm>, Box<SearchTerm>),
    String(Vec<String>),
    MetaString {
        name: TagName,
        value: String,
    },
    Numeric {
        name: TagName,
        op: NumericOp,
        value: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumericOp {
    Equal,
    Greater,
    Less,
    GreaterEqual,
    LessEqual,
    NotEqual,
}

pub fn matches_restrictive_keyword_payload(filename: &str, tags: &[Tag], payload: &[u8]) -> bool {
    let mut cursor = Cursor::new(payload);
    let Ok(term) = parse_search_term(&mut cursor, 0) else {
        return false;
    };
    term.matches(filename, tags)
}

impl SearchTerm {
    fn matches(&self, filename: &str, tags: &[Tag]) -> bool {
        let filename_lower = filename.to_lowercase();
        self.matches_with_lower_filename(&filename_lower, tags)
    }

    fn matches_with_lower_filename(&self, filename_lower: &str, tags: &[Tag]) -> bool {
        match self {
            SearchTerm::And(left, right) => {
                left.matches_with_lower_filename(filename_lower, tags)
                    && right.matches_with_lower_filename(filename_lower, tags)
            }
            SearchTerm::Or(left, right) => {
                left.matches_with_lower_filename(filename_lower, tags)
                    || right.matches_with_lower_filename(filename_lower, tags)
            }
            SearchTerm::Not(left, right) => {
                left.matches_with_lower_filename(filename_lower, tags)
                    && !right.matches_with_lower_filename(filename_lower, tags)
            }
            SearchTerm::String(terms) => string_terms_match(filename_lower, terms),
            SearchTerm::MetaString { name, value } => {
                meta_string_matches(filename_lower, tags, name, value)
            }
            SearchTerm::Numeric { name, op, value } => numeric_matches(tags, name, *op, *value),
        }
    }
}

fn parse_search_term(cursor: &mut Cursor<&[u8]>, depth: u8) -> Result<SearchTerm, ()> {
    if depth >= MAX_SEARCH_EXPR_DEPTH {
        return Err(());
    }
    let op = read_u8(cursor)?;
    match op {
        0x00 => parse_boolean_term(cursor, depth + 1),
        0x01 => {
            let value = read_lower_string(cursor)?;
            Ok(SearchTerm::String(tokenize_opt_quoted_search_term(&value)))
        }
        0x02 => {
            let value = read_lower_string(cursor)?;
            let name = read_tag_name(cursor)?;
            Ok(SearchTerm::MetaString { name, value })
        }
        0x03 => {
            let value = read_u32(cursor)?;
            parse_numeric_term(cursor, value.into())
        }
        0x08 => {
            let value = read_u64(cursor)?;
            parse_numeric_term(cursor, value)
        }
        _ => Err(()),
    }
}

fn parse_boolean_term(cursor: &mut Cursor<&[u8]>, depth: u8) -> Result<SearchTerm, ()> {
    let bool_op = read_u8(cursor)?;
    let left = Box::new(parse_search_term(cursor, depth)?);
    let right = Box::new(parse_search_term(cursor, depth)?);
    match bool_op {
        0x00 => Ok(SearchTerm::And(left, right)),
        0x01 => Ok(SearchTerm::Or(left, right)),
        0x02 => Ok(SearchTerm::Not(left, right)),
        _ => Err(()),
    }
}

fn parse_numeric_term(cursor: &mut Cursor<&[u8]>, value: u64) -> Result<SearchTerm, ()> {
    let op = match read_u8(cursor)? {
        0x00 => NumericOp::Equal,
        0x01 => NumericOp::Greater,
        0x02 => NumericOp::Less,
        0x03 => NumericOp::GreaterEqual,
        0x04 => NumericOp::LessEqual,
        0x05 => NumericOp::NotEqual,
        _ => return Err(()),
    };
    let name = read_tag_name(cursor)?;
    Ok(SearchTerm::Numeric { name, op, value })
}

fn string_terms_match(filename_lower: &str, terms: &[String]) -> bool {
    !terms.is_empty()
        && terms
            .iter()
            .all(|term| filename_lower.contains(term.as_str()))
}

fn meta_string_matches(filename_lower: &str, tags: &[Tag], name: &TagName, value: &str) -> bool {
    if matches!(name, TagName::Short(name) if *name == tag_name::FILEFORMAT) {
        return filename_lower
            .rsplit_once('.')
            .map(|(_, extension)| extension == value)
            .unwrap_or(false);
    }

    tags.iter().any(|tag| {
        tag.name == *name
            && matches!(
                &tag.value,
                TagValue::String(tag_value) if tag_value.to_lowercase() == value
            )
    })
}

fn numeric_matches(tags: &[Tag], name: &TagName, op: NumericOp, expected: u64) -> bool {
    let Some(actual) = int_tag_value(tags, name) else {
        return false;
    };
    match op {
        NumericOp::Equal => actual == expected,
        NumericOp::Greater => actual > expected,
        NumericOp::Less => actual < expected,
        NumericOp::GreaterEqual => actual >= expected,
        NumericOp::LessEqual => actual <= expected,
        NumericOp::NotEqual => actual != expected,
    }
}

fn int_tag_value(tags: &[Tag], name: &TagName) -> Option<u64> {
    if matches!(name, TagName::Short(name) if *name == tag_name::FILESIZE) {
        return file_size_tag_value(tags);
    }

    tags.iter().find_map(|tag| {
        if tag.name != *name {
            return None;
        }
        match tag.value {
            TagValue::UInt(value) | TagValue::U64(value) => Some(value),
            TagValue::U32(value) => Some(u64::from(value)),
            TagValue::U16(value) => Some(u64::from(value)),
            TagValue::U8(value) => Some(u64::from(value)),
            _ => None,
        }
    })
}

fn file_size_tag_value(tags: &[Tag]) -> Option<u64> {
    let mut size = None;
    let mut size_low = None;
    let mut size_high = None;

    for tag in tags {
        match (&tag.name, &tag.value) {
            (TagName::Short(name), TagValue::UInt(value))
                if *name == tag_name::FILESIZE && u32::try_from(*value).is_ok() =>
            {
                size_low.get_or_insert(*value as u32);
            }
            (TagName::Short(name), TagValue::UInt(value)) if *name == tag_name::FILESIZE => {
                size.get_or_insert(*value);
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
                if *name == tag_name::FILESIZE && bytes.len() == 8 =>
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

fn tokenize_opt_quoted_search_term(value: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars = value.chars().collect::<Vec<_>>();
    let mut index = 0;

    while index < chars.len() {
        if chars[index] == '"' {
            index += 1;
            let start = index;
            while index < chars.len() && chars[index] != '"' {
                index += 1;
            }
            if index < chars.len() && index > start {
                terms.push(chars[start..index].iter().collect());
            }
            if index < chars.len() {
                index += 1;
            }
            continue;
        }

        let start = index;
        while index < chars.len() && !INVALID_KAD_KEYWORD_CHARS.contains(chars[index]) {
            index += 1;
        }
        if index > start {
            terms.push(chars[start..index].iter().collect());
        }
        if index < chars.len() && chars[index] == '"' {
            continue;
        }
        index += 1;
    }

    terms
}

fn read_tag_name(cursor: &mut Cursor<&[u8]>) -> Result<TagName, ()> {
    let len = usize::from(read_u16(cursor)?);
    let mut bytes = vec![0; len];
    cursor.read_exact(&mut bytes).map_err(|_| ())?;
    if let [name] = bytes.as_slice() {
        Ok(TagName::Short(*name))
    } else {
        Ok(TagName::Long(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

fn read_lower_string(cursor: &mut Cursor<&[u8]>) -> Result<String, ()> {
    let len = usize::from(read_u16(cursor)?);
    let mut bytes = vec![0; len];
    cursor.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(String::from_utf8_lossy(&bytes).to_lowercase())
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, ()> {
    let mut bytes = [0; 1];
    cursor.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, ()> {
    let mut bytes = [0; 2];
    cursor.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, ()> {
    let mut bytes = [0; 4];
    cursor.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, ()> {
    let mut bytes = [0; 8];
    cursor.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::matches_restrictive_keyword_payload;
    use emulebb_kad_proto::{Tag, TagValue, tag_name};

    #[test]
    fn string_terms_match_common_filename_like_stock() {
        let payload = string_term("Ubuntu Linux");
        assert!(matches_restrictive_keyword_payload(
            "ubuntu-22.04-linux.iso",
            &[],
            &payload
        ));
        assert!(!matches_restrictive_keyword_payload(
            "ubuntu-22.04.iso",
            &[],
            &payload
        ));
    }

    #[test]
    fn quoted_string_terms_stay_grouped() {
        let payload = string_term("\"live set\" flac");
        assert!(matches_restrictive_keyword_payload(
            "artist live set 2026.flac",
            &[],
            &payload
        ));
        assert!(!matches_restrictive_keyword_payload(
            "artist live final set 2026.flac",
            &[],
            &payload
        ));
    }

    #[test]
    fn binary_not_requires_left_and_excludes_right() {
        let payload = bool_term(0x02, string_term("linux"), string_term("beta"));
        assert!(matches_restrictive_keyword_payload(
            "ubuntu-linux.iso",
            &[],
            &payload
        ));
        assert!(!matches_restrictive_keyword_payload(
            "ubuntu-linux-beta.iso",
            &[],
            &payload
        ));
        assert!(!matches_restrictive_keyword_payload(
            "ubuntu.iso",
            &[],
            &payload
        ));
    }

    #[test]
    fn meta_fileformat_matches_filename_extension_like_stock() {
        let payload = meta_string_term(tag_name::FILEFORMAT, "iso");
        assert!(matches_restrictive_keyword_payload(
            "ubuntu-linux.ISO",
            &[],
            &payload
        ));
        assert!(!matches_restrictive_keyword_payload(
            "ubuntu-linux.iso.zip",
            &[],
            &payload
        ));
    }

    #[test]
    fn numeric_terms_compare_integer_tags() {
        let payload = numeric_u64_term(tag_name::FILESIZE, 0x03, 900);
        assert!(matches_restrictive_keyword_payload(
            "ubuntu.iso",
            &[Tag::filesize(900)],
            &payload
        ));
        assert!(!matches_restrictive_keyword_payload(
            "ubuntu.iso",
            &[Tag::filesize(899)],
            &payload
        ));
    }

    #[test]
    fn numeric_filesize_terms_compare_split_large_file_size() {
        let size = (2_u64 << 32) | 1;
        let payload = numeric_u64_term(tag_name::FILESIZE, 0x00, size);
        assert!(matches_restrictive_keyword_payload(
            "large.bin",
            &[
                Tag::new_short(tag_name::FILESIZE, TagValue::U32(1)),
                Tag::new_short(tag_name::FILESIZE_HI, TagValue::U32(2)),
            ],
            &payload
        ));
    }

    #[test]
    fn numeric_filesize_terms_compare_bsob_file_size_like_stock() {
        let size = (2_u64 << 32) | 1;
        let payload = numeric_u64_term(tag_name::FILESIZE, 0x00, size);
        assert!(matches_restrictive_keyword_payload(
            "large.bin",
            &[Tag::new_short(
                tag_name::FILESIZE,
                TagValue::SmallBlob(size.to_le_bytes().into()),
            )],
            &payload
        ));
    }

    #[test]
    fn invalid_expression_does_not_match() {
        assert!(!matches_restrictive_keyword_payload(
            "ubuntu.iso",
            &[Tag::new_short(tag_name::FILESIZE, TagValue::U32(900))],
            &[0x00, 0x99]
        ));
    }

    fn bool_term(op: u8, left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0x00, op];
        out.extend(left);
        out.extend(right);
        out
    }

    fn string_term(value: &str) -> Vec<u8> {
        let mut out = vec![0x01];
        write_string(&mut out, value);
        out
    }

    fn meta_string_term(name: u8, value: &str) -> Vec<u8> {
        let mut out = vec![0x02];
        write_string(&mut out, value);
        write_short_name(&mut out, name);
        out
    }

    fn numeric_u64_term(name: u8, op: u8, value: u64) -> Vec<u8> {
        let mut out = vec![0x08];
        out.extend(value.to_le_bytes());
        out.push(op);
        write_short_name(&mut out, name);
        out
    }

    fn write_string(out: &mut Vec<u8>, value: &str) {
        out.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
        out.extend(value.as_bytes());
    }

    fn write_short_name(out: &mut Vec<u8>, name: u8) {
        out.extend(1_u16.to_le_bytes());
        out.push(name);
    }
}
