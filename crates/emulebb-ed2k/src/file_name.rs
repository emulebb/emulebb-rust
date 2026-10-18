use encoding_rs::WINDOWS_1252;
use unicode_normalization::UnicodeNormalization;

const MAX_FILE_NAME_BYTES: usize = 4096;

/// Repair the bounded legacy encodings commonly observed in ED2K file names.
///
/// The order is intentional and shared by every network intake path: HTML
/// entities, percent-encoded UTF-8, Windows-1252/UTF-8 mojibake, then Unicode
/// NFC. Unknown entities and invalid encodings are preserved verbatim.
pub fn normalize_ed2k_file_name(raw: &str) -> String {
    let bounded = bounded_utf8(raw.trim(), MAX_FILE_NAME_BYTES);
    let html_decoded = decode_html_entities(bounded);
    let percent_decoded = decode_percent_utf8(&html_decoded).unwrap_or(html_decoded);
    let repaired = repair_windows_1252_mojibake(percent_decoded);
    repaired.nfc().collect()
}

fn bounded_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn decode_html_entities(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(entity_start) = remaining.find('&') {
        output.push_str(&remaining[..entity_start]);
        remaining = &remaining[entity_start..];
        let Some(entity_end) = remaining.find(';').filter(|end| *end <= 16) else {
            output.push('&');
            remaining = &remaining[1..];
            continue;
        };
        let entity = &remaining[1..entity_end];
        if let Some(decoded) = decode_html_entity(entity) {
            output.push(decoded);
            remaining = &remaining[entity_end + 1..];
        } else {
            output.push_str(&remaining[..=entity_end]);
            remaining = &remaining[entity_end + 1..];
        }
    }
    output.push_str(remaining);
    output
}

fn decode_html_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "apos" => Some('\''),
        "gt" => Some('>'),
        "lt" => Some('<'),
        "nbsp" => Some('\u{00a0}'),
        "quot" => Some('"'),
        _ => entity
            .strip_prefix("#x")
            .or_else(|| entity.strip_prefix("#X"))
            .and_then(|digits| u32::from_str_radix(digits, 16).ok())
            .or_else(|| {
                entity
                    .strip_prefix('#')
                    .and_then(|digits| digits.parse::<u32>().ok())
            })
            .and_then(char::from_u32),
    }
}

fn decode_percent_utf8(value: &str) -> Option<String> {
    if !value.as_bytes().contains(&b'%') {
        return None;
    }
    let input = value.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    let mut decoded_any = false;
    while index < input.len() {
        if input[index] == b'%'
            && index + 2 < input.len()
            && let (Some(high), Some(low)) =
                (hex_nibble(input[index + 1]), hex_nibble(input[index + 2]))
        {
            output.push((high << 4) | low);
            index += 3;
            decoded_any = true;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    decoded_any
        .then(|| String::from_utf8(output).ok())
        .flatten()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn repair_windows_1252_mojibake(value: String) -> String {
    if mojibake_score(&value) == 0 {
        return value;
    }
    value
        .split_inclusive(char::is_whitespace)
        .map(repair_windows_1252_chunk)
        .collect()
}

fn repair_windows_1252_chunk(value: &str) -> String {
    let original_score = mojibake_score(value);
    if original_score == 0 {
        return value.to_string();
    }
    let (bytes, _, had_errors) = WINDOWS_1252.encode(value);
    if had_errors {
        return value.to_string();
    }
    let Ok(candidate) = String::from_utf8(bytes.into_owned()) else {
        return value.to_string();
    };
    if mojibake_score(&candidate) < original_score {
        candidate
    } else {
        value.to_string()
    }
}

fn mojibake_score(value: &str) -> usize {
    value
        .chars()
        .filter(|character| matches!(character, 'Ã' | 'Â' | 'â' | 'ð' | '�'))
        .count()
}

#[cfg(test)]
mod tests {
    use super::normalize_ed2k_file_name;

    #[test]
    fn repairs_entities_percent_encoding_mojibake_and_nfc() {
        assert_eq!(
            normalize_ed2k_file_name("  Caf&amp;e%CC%81%20%E2%80%93%20FranÃ§ais.mkv  "),
            "Caf&é – Français.mkv"
        );
        assert_eq!(normalize_ed2k_file_name("Cafe\u{301}.mkv"), "Café.mkv");
    }

    #[test]
    fn preserves_unknown_or_invalid_encodings() {
        assert_eq!(
            normalize_ed2k_file_name("A&future;B%ZZ.bin"),
            "A&future;B%ZZ.bin"
        );
        assert_eq!(normalize_ed2k_file_name("中文-🚀.bin"), "中文-🚀.bin");
    }
}
