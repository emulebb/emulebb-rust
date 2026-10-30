use encoding_rs::WINDOWS_1252;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Ed2kStringEncoding {
    #[default]
    Legacy,
    Utf8,
}

impl Ed2kStringEncoding {
    pub(crate) const fn from_unicode_support(supports_unicode: bool) -> Self {
        if supports_unicode {
            Self::Utf8
        } else {
            Self::Legacy
        }
    }

    pub(crate) fn decode(self, bytes: &[u8]) -> String {
        if let Some(utf8) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF])
            && let Ok(value) = std::str::from_utf8(utf8)
        {
            return value.to_owned();
        }
        if self == Self::Utf8
            && let Ok(value) = std::str::from_utf8(bytes)
        {
            return value.to_owned();
        }
        decode_legacy(bytes)
    }

    pub(crate) fn encode(self, value: &str) -> Vec<u8> {
        match self {
            Self::Legacy => encode_legacy(value),
            Self::Utf8 => value.as_bytes().to_vec(),
        }
    }
}

#[cfg(windows)]
fn decode_legacy(bytes: &[u8]) -> String {
    use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};

    if bytes.is_empty() {
        return String::new();
    }
    let Ok(source_len) = i32::try_from(bytes.len()) else {
        return WINDOWS_1252.decode(bytes).0.into_owned();
    };
    // SAFETY: the source slice is valid for `source_len` bytes and a null
    // destination with length zero requests the required UTF-16 capacity.
    let wide_len = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            source_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if wide_len <= 0 {
        return WINDOWS_1252.decode(bytes).0.into_owned();
    }
    let wide_capacity = usize::try_from(wide_len).expect("positive UTF-16 length fits usize");
    let mut wide = vec![0u16; wide_capacity];
    // SAFETY: `wide` has exactly the positive capacity returned by the query
    // above and both buffers remain valid for the duration of the call.
    let converted = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            source_len,
            wide.as_mut_ptr(),
            wide_len,
        )
    };
    if converted <= 0 {
        return WINDOWS_1252.decode(bytes).0.into_owned();
    }
    let converted = usize::try_from(converted).expect("positive UTF-16 length fits usize");
    String::from_utf16_lossy(&wide[..converted])
}

#[cfg(not(windows))]
fn decode_legacy(bytes: &[u8]) -> String {
    WINDOWS_1252.decode(bytes).0.into_owned()
}

#[cfg(windows)]
fn encode_legacy(value: &str) -> Vec<u8> {
    use windows_sys::Win32::Globalization::{CP_ACP, WideCharToMultiByte};

    if value.is_empty() {
        return Vec::new();
    }
    let wide: Vec<u16> = value.encode_utf16().collect();
    let Ok(wide_len) = i32::try_from(wide.len()) else {
        return encode_windows_1252(value);
    };
    // SAFETY: the UTF-16 source is valid for `wide_len` code units and a null
    // destination with length zero requests the required byte capacity.
    let byte_len = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            wide_len,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    if byte_len <= 0 {
        return encode_windows_1252(value);
    }
    let byte_capacity = usize::try_from(byte_len).expect("positive byte length fits usize");
    let mut bytes = vec![0u8; byte_capacity];
    // SAFETY: `bytes` has exactly the positive capacity returned by the query
    // above and both buffers remain valid for the duration of the call.
    let converted = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            wide_len,
            bytes.as_mut_ptr(),
            byte_len,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    if converted <= 0 {
        return encode_windows_1252(value);
    }
    let converted = usize::try_from(converted).expect("positive byte length fits usize");
    bytes.truncate(converted);
    bytes
}

#[cfg(not(windows))]
fn encode_legacy(value: &str) -> Vec<u8> {
    encode_windows_1252(value)
}

fn encode_windows_1252(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len());
    for character in value.chars() {
        let mut utf8 = [0u8; 4];
        let encoded_character = character.encode_utf8(&mut utf8);
        let (encoded, _, had_errors) = WINDOWS_1252.encode(encoded_character);
        if had_errors {
            bytes.push(b'?');
        } else {
            bytes.extend_from_slice(&encoded);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::Ed2kStringEncoding;

    #[test]
    fn unicode_mode_round_trips_raw_utf8() {
        let value = "Grüße-漢字";
        let encoded = Ed2kStringEncoding::Utf8.encode(value);
        assert_eq!(encoded, value.as_bytes());
        assert_eq!(Ed2kStringEncoding::Utf8.decode(&encoded), value);
    }

    #[test]
    fn utf8_bom_is_honored_even_for_legacy_sessions() {
        let mut encoded = vec![0xEF, 0xBB, 0xBF];
        encoded.extend_from_slice("Grüße".as_bytes());
        assert_eq!(Ed2kStringEncoding::Legacy.decode(&encoded), "Grüße");
    }

    #[test]
    fn malformed_unicode_input_uses_the_legacy_codepage_without_replacement() {
        let decoded = Ed2kStringEncoding::Utf8.decode(b"caf\xE9");
        assert_eq!(Ed2kStringEncoding::Legacy.decode(b"caf\xE9"), decoded);
        #[cfg(not(windows))]
        assert_eq!(decoded, "café");
    }

    #[test]
    fn legacy_mode_encodes_through_the_same_codepage_it_decodes() {
        let encoded = Ed2kStringEncoding::Legacy.encode("café-漢");
        let decoded = Ed2kStringEncoding::Legacy.decode(&encoded);
        assert_eq!(Ed2kStringEncoding::Legacy.encode(&decoded), encoded);
        #[cfg(not(windows))]
        {
            assert_eq!(encoded, b"caf\xE9-?");
            assert_eq!(decoded, "café-?");
        }
    }
}
