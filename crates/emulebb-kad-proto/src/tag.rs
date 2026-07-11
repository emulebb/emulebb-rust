use std::io::{Read, Seek};

use binrw::{BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt, Endian};
use encoding_rs::WINDOWS_1252;

use crate::constants::tag_name;
use crate::error::ProtoError;
use crate::hash::Ed2kHash;

/// Kad tag-name representation.
///
/// eMule mostly uses one-byte FT_* tag identifiers, but some packet families
/// also carry longer string names. The codec keeps both forms explicit so
/// wire-level meaning is not lost during decode.
#[derive(Debug, Clone, PartialEq)]
pub enum TagName {
    /// One-byte FT_* tag identifier.
    Short(u8),
    /// String tag name used by the long-name branch of the Kad tag codec.
    Long(String),
}

/// Typed Kad tag value.
///
/// The oracle reuses the same generic tag envelope across search results,
/// publish packets, HELLO metadata, and ED2K-side metadata. This enum keeps the
/// raw storage class visible so callers can preserve or reinterpret tags
/// without reserializing from a lossy intermediate model.
#[derive(Debug, Clone, PartialEq)]
pub enum TagValue {
    Hash(Ed2kHash),
    String(String),
    UInt(u64),
    U64(u64),
    U32(u32),
    U16(u16),
    U8(u8),
    Float(f32),
    Bool(bool),
    Blob(Vec<u8>),
    SmallBlob(Vec<u8>),
}

/// One decoded Kad tag.
#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    /// Wire tag name, either a short FT_* code or a long string.
    pub name: TagName,
    /// Typed wire value payload.
    pub value: TagValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StringDecodeMode {
    LossyUtf8,
    SearchResult,
}

fn decode_string_bytes(bytes: &[u8], mode: StringDecodeMode) -> String {
    match mode {
        StringDecodeMode::LossyUtf8 => String::from_utf8_lossy(bytes).into_owned(),
        // eMule/aMule special-case SEARCH_RES string decoding: try UTF-8 first and
        // only then fall back to the local ANSI code page for legacy display-only data.
        // Reference:
        // - eMule srchybrid/kademlia/io/DataIO.cpp CDataIO::ReadStringUTF8(bool bOptACP)
        // - eMule srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_RES
        // - aMule src/kademlia/net/KademliaUDPListener.cpp ProcessSearchResponse
        StringDecodeMode::SearchResult => match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => decode_legacy_search_result_string(bytes),
        },
    }
}

#[cfg(windows)]
fn decode_legacy_search_result_string(bytes: &[u8]) -> String {
    use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};

    if bytes.is_empty() {
        return String::new();
    }

    let src_len = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    // SAFETY: `bytes` is valid for `src_len` bytes, and Windows permits a null
    // output pointer with capacity zero for this required-length query.
    let wide_len =
        unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), src_len, std::ptr::null_mut(), 0) };
    if wide_len <= 0 {
        return WINDOWS_1252.decode(bytes).0.into_owned();
    }

    let wide_len_i32 = wide_len;
    let wide_len = usize::try_from(wide_len_i32).expect("wide_len is positive");
    let mut wide = vec![0u16; wide_len];
    // SAFETY: the input slice remains valid, and `wide` was allocated to the
    // exact positive capacity returned by the length query above.
    let converted = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            0,
            bytes.as_ptr(),
            src_len,
            wide.as_mut_ptr(),
            wide_len_i32,
        )
    };
    if converted <= 0 {
        return WINDOWS_1252.decode(bytes).0.into_owned();
    }

    let converted = usize::try_from(converted).expect("converted length is positive");
    String::from_utf16_lossy(&wide[..converted])
}

#[cfg(not(windows))]
fn decode_legacy_search_result_string(bytes: &[u8]) -> String {
    WINDOWS_1252.decode(bytes).0.into_owned()
}

impl Tag {
    /// Create a short-name Kad tag from a one-byte FT_* identifier.
    #[must_use]
    pub fn new_short(name_byte: u8, value: TagValue) -> Self {
        Tag {
            name: TagName::Short(name_byte),
            value,
        }
    }

    /// Create a long-name Kad tag from a string identifier.
    #[must_use]
    pub fn new_long(name: impl Into<String>, value: TagValue) -> Self {
        Tag {
            name: TagName::Long(name.into()),
            value,
        }
    }

    /// Create a `FILENAME` tag.
    #[must_use]
    pub fn filename(name: impl Into<String>) -> Self {
        Tag::new_short(tag_name::FILENAME, TagValue::String(name.into()))
    }

    /// Create a `FILESIZE` tag using the compact numeric representation chosen by the codec.
    #[must_use]
    pub fn filesize(size: u64) -> Self {
        Tag::new_short(tag_name::FILESIZE, TagValue::UInt(size))
    }

    /// Create a `FILETYPE` tag.
    #[must_use]
    pub fn filetype(t: impl Into<String>) -> Self {
        Tag::new_short(tag_name::FILETYPE, TagValue::String(t.into()))
    }

    /// Create a `SOURCES` source-count tag.
    #[must_use]
    pub fn sources(n: u32) -> Self {
        Tag::new_short(tag_name::SOURCES, TagValue::UInt(u64::from(n)))
    }

    /// Create the Kad keyword-publish AICH tag used for Kad v9+ peers.
    #[must_use]
    pub fn kad_aich_hash_pub(hash: [u8; 20]) -> Self {
        Tag::new_short(tag_name::KADAICHHASHPUB, TagValue::SmallBlob(hash.to_vec()))
    }
}

/// Map `TagValue` to its raw type byte (without the `0x80` name flag).
fn value_type_byte(v: &TagValue) -> u8 {
    match v {
        TagValue::Hash(_) => 0x01,
        TagValue::String(_) => 0x02,
        TagValue::UInt(value) => {
            if *value <= u64::from(u8::MAX) {
                0x09
            } else if *value <= u64::from(u16::MAX) {
                0x08
            } else if *value <= u64::from(u32::MAX) {
                0x03
            } else {
                0x0B
            }
        }
        TagValue::U32(_) => 0x03,
        TagValue::Float(_) => 0x04,
        TagValue::Bool(_) => 0x05,
        TagValue::Blob(_) => 0x07,
        TagValue::SmallBlob(_) => 0x0A,
        TagValue::U16(_) => 0x08,
        TagValue::U8(_) => 0x09,
        TagValue::U64(_) => 0x0B,
    }
}

impl BinRead for Tag {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(reader: &mut R, endian: Endian, _args: ()) -> BinResult<Self> {
        Self::read_with_mode(reader, endian, StringDecodeMode::LossyUtf8)
    }
}

/// Bytes still readable from `reader` between the current position and the end.
fn remaining_bytes<R: Read + Seek>(reader: &mut R) -> std::io::Result<u64> {
    let pos = reader.stream_position()?;
    let end = reader.seek(std::io::SeekFrom::End(0))?;
    reader.seek(std::io::SeekFrom::Start(pos))?;
    Ok(end.saturating_sub(pos))
}

/// Reads `len` bytes, but never pre-allocates beyond the bytes that actually
/// remain in the stream. A bogus length (e.g. a tag claiming ~4 GB on a short
/// cursor) cannot succeed, so we reject it up front instead of committing a
/// huge zeroed `Vec` that `read_exact` would only fail on afterwards.
/// Legitimate tags (len <= remaining) read exactly `len` bytes.
fn read_len_capped_bytes<R: Read + Seek>(reader: &mut R, len: usize) -> BinResult<Vec<u8>> {
    let remaining = remaining_bytes(reader).map_err(binrw::Error::Io)? as usize;
    if len > remaining {
        let pos = reader.stream_position().unwrap_or(0);
        return Err(binrw::Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("tag declares {len} bytes but only {remaining} remain at pos {pos}"),
        )));
    }
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .map_err(|e| binrw::Error::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    Ok(data)
}

impl Tag {
    pub(crate) fn read_with_mode<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        mode: StringDecodeMode,
    ) -> BinResult<Self> {
        let type_byte: u8 = reader.read_type(endian)?;
        let short_name = (type_byte & 0x80) != 0;
        let tag_type = type_byte & 0x7F;

        let name = if short_name {
            let name_byte: u8 = reader.read_type(endian)?;
            TagName::Short(name_byte)
        } else {
            let name_len: u16 = reader.read_type(endian)?;
            let name_bytes = read_len_capped_bytes(reader, name_len as usize)?;
            // eMule often writes single-byte numeric IDs as a 1-byte "long" name
            // instead of using the 0x80 short-name flag. Normalize to Short.
            if name_bytes.len() == 1 {
                TagName::Short(name_bytes[0])
            } else {
                TagName::Long(decode_string_bytes(&name_bytes, mode))
            }
        };

        let value = match tag_type {
            0x01 => {
                // Hash16
                let h = Ed2kHash::read_options(reader, endian, ())?;
                TagValue::Hash(h)
            }
            0x02 => {
                // String: u16 length + bytes
                let str_len: u16 = reader.read_type(endian)?;
                let str_bytes = read_len_capped_bytes(reader, str_len as usize)?;
                TagValue::String(decode_string_bytes(&str_bytes, mode))
            }
            0x03 => {
                let v: u32 = reader.read_type(endian)?;
                TagValue::U32(v)
            }
            0x04 => {
                let v: f32 = reader.read_type(endian)?;
                TagValue::Float(v)
            }
            0x05 => {
                let v: u8 = reader.read_type(endian)?;
                TagValue::Bool(v != 0)
            }
            0x06 => {
                // BOOLARRAY: u16 len + skip bytes => store as Blob
                let arr_len: u16 = reader.read_type(endian)?;
                let byte_count = (arr_len as usize).div_ceil(8);
                let data = read_len_capped_bytes(reader, byte_count)?;
                TagValue::Blob(data)
            }
            0x07 => {
                // BLOB: u32 len + bytes
                let blob_len: u32 = reader.read_type(endian)?;
                let data = read_len_capped_bytes(reader, blob_len as usize)?;
                TagValue::Blob(data)
            }
            0x08 => {
                let v: u16 = reader.read_type(endian)?;
                TagValue::U16(v)
            }
            0x09 => {
                let v: u8 = reader.read_type(endian)?;
                TagValue::U8(v)
            }
            0x0A => {
                // BSOB: u8 len + bytes
                let bsob_len: u8 = reader.read_type(endian)?;
                let data = read_len_capped_bytes(reader, bsob_len as usize)?;
                TagValue::SmallBlob(data)
            }
            0x0B => {
                let v: u64 = reader.read_type(endian)?;
                TagValue::U64(v)
            }
            other => {
                let pos = reader.stream_position().unwrap_or(0);
                return Err(binrw::Error::Custom {
                    pos,
                    err: Box::new(ProtoError::UnknownTagType(other)),
                });
            }
        };

        Ok(Tag { name, value })
    }
}

impl BinWrite for Tag {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _args: (),
    ) -> BinResult<()> {
        // Kad tags always encode the tag name as a u16 length followed by the
        // raw bytes. eMule does not use the eD2k short-name marker bit here.
        let type_byte: u8 = value_type_byte(&self.value);

        writer.write_type(&type_byte, endian)?;

        match &self.name {
            TagName::Short(b) => {
                let len: u16 = 1;
                writer.write_type(&len, endian)?;
                writer.write_type(b, endian)?;
            }
            TagName::Long(s) => {
                let bytes = s.as_bytes();
                let len = u16::try_from(bytes.len()).expect("tag name length exceeds u16");
                writer.write_type(&len, endian)?;
                writer.write_all(bytes).map_err(binrw::Error::Io)?;
            }
        }

        match &self.value {
            TagValue::Hash(h) => {
                h.write_options(writer, endian, ())?;
            }
            TagValue::String(s) => {
                let bytes = s.as_bytes();
                let len = u16::try_from(bytes.len()).expect("string tag length exceeds u16");
                writer.write_type(&len, endian)?;
                writer.write_all(bytes).map_err(binrw::Error::Io)?;
            }
            TagValue::UInt(v) => {
                if *v <= u64::from(u8::MAX) {
                    writer.write_type(&u8::try_from(*v).expect("value fits into u8"), endian)?;
                } else if *v <= u64::from(u16::MAX) {
                    writer.write_type(&u16::try_from(*v).expect("value fits into u16"), endian)?;
                } else if *v <= u64::from(u32::MAX) {
                    writer.write_type(&u32::try_from(*v).expect("value fits into u32"), endian)?;
                } else {
                    writer.write_type(v, endian)?;
                }
            }
            TagValue::U32(v) => {
                writer.write_type(v, endian)?;
            }
            TagValue::Float(v) => {
                writer.write_type(v, endian)?;
            }
            TagValue::Bool(v) => {
                let b = u8::from(*v);
                writer.write_type(&b, endian)?;
            }
            TagValue::Blob(data) => {
                let len = u32::try_from(data.len()).expect("blob tag length exceeds u32");
                writer.write_type(&len, endian)?;
                writer.write_all(data).map_err(binrw::Error::Io)?;
            }
            TagValue::SmallBlob(data) => {
                let len = u8::try_from(data.len()).expect("small blob tag length exceeds Kad BSOB");
                writer.write_type(&len, endian)?;
                writer.write_all(data).map_err(binrw::Error::Io)?;
            }
            TagValue::U16(v) => {
                writer.write_type(v, endian)?;
            }
            TagValue::U8(v) => {
                writer.write_type(v, endian)?;
            }
            TagValue::U64(v) => {
                writer.write_type(v, endian)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::{BinRead, BinWrite};
    use std::io::Cursor;

    fn roundtrip(tag: &Tag) -> Tag {
        let mut buf = Cursor::new(Vec::new());
        tag.write_le(&mut buf).unwrap();
        buf.set_position(0);
        Tag::read_le(&mut buf).unwrap()
    }

    #[test]
    fn test_single_byte_name_string_roundtrip() {
        let t = Tag::filename("hello.txt");
        let mut buf = Cursor::new(Vec::new());
        t.write_le(&mut buf).unwrap();
        assert_eq!(
            &buf.into_inner()[..5],
            &[0x02, 0x01, 0x00, tag_name::FILENAME, 0x09]
        );
    }

    #[test]
    fn test_filesize_uses_dynamic_integer_width_on_wire() {
        let t = Tag::filesize(1_234_567_890);
        let mut buf = Cursor::new(Vec::new());
        t.write_le(&mut buf).unwrap();
        assert_eq!(
            &buf.into_inner()[..4],
            &[0x03, 0x01, 0x00, tag_name::FILESIZE]
        );
    }

    #[test]
    fn test_sources_uses_dynamic_integer_width_on_wire() {
        let t = Tag::sources(42);
        let mut buf = Cursor::new(Vec::new());
        t.write_le(&mut buf).unwrap();
        assert_eq!(
            &buf.into_inner()[..5],
            &[0x09, 0x01, 0x00, tag_name::SOURCES, 42]
        );
    }

    #[test]
    fn test_long_name_string() {
        let t = Tag::new_long("my-tag", TagValue::String("value".to_string()));
        let t2 = roundtrip(&t);
        assert_eq!(t, t2);
    }

    #[test]
    fn test_hash_value() {
        let h = Ed2kHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let t = Tag::new_short(0x01, TagValue::Hash(h));
        let t2 = roundtrip(&t);
        assert_eq!(t, t2);
    }

    #[test]
    fn test_u16_value() {
        let t = Tag::new_short(0x22, TagValue::U16(65000));
        let t2 = roundtrip(&t);
        assert_eq!(t, t2);
    }

    #[test]
    fn test_u8_value() {
        let t = Tag::new_short(0x20, TagValue::U8(7));
        let t2 = roundtrip(&t);
        assert_eq!(t, t2);
    }

    #[test]
    fn test_float_value() {
        let t = Tag::new_short(0x10, TagValue::Float(std::f32::consts::PI));
        let t2 = roundtrip(&t);
        // Float comparison needs tolerance
        if let (TagValue::Float(a), TagValue::Float(b)) = (&t.value, &t2.value) {
            assert!((a - b).abs() < 1e-5);
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn test_bool_value() {
        let t_true = Tag::new_short(0x05, TagValue::Bool(true));
        let t_false = Tag::new_short(0x05, TagValue::Bool(false));
        assert_eq!(roundtrip(&t_true), t_true);
        assert_eq!(roundtrip(&t_false), t_false);
    }

    #[test]
    fn test_blob_value() {
        let t = Tag::new_short(0x07, TagValue::Blob(vec![0xAA, 0xBB, 0xCC]));
        let t2 = roundtrip(&t);
        assert_eq!(t, t2);
    }

    #[test]
    fn test_small_blob_value_uses_bsob_wire_type() {
        let t = Tag::new_short(
            tag_name::KADAICHHASHPUB,
            TagValue::SmallBlob(vec![0x11; 20]),
        );
        let mut buf = Cursor::new(Vec::new());
        t.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes[0], 0x0A);
        assert_eq!(bytes[1..4], [0x01, 0x00, tag_name::KADAICHHASHPUB]);
        assert_eq!(bytes[4], 20);

        let mut cursor = Cursor::new(bytes);
        let decoded = Tag::read_le(&mut cursor).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn test_long_name_u32() {
        let t = Tag::new_long("bitrate", TagValue::U32(320));
        let t2 = roundtrip(&t);
        assert_eq!(t, t2);
    }

    #[test]
    fn test_long_name_u64() {
        let t = Tag::new_long("filesize", TagValue::U64(u64::MAX));
        let t2 = roundtrip(&t);
        assert_eq!(t, t2);
    }

    #[test]
    fn test_reader_accepts_legacy_short_name_marker() {
        let mut buf = Cursor::new(vec![0x89, tag_name::SOURCES, 0x07]);
        let tag = Tag::read_le(&mut buf).unwrap();
        assert_eq!(tag, Tag::new_short(tag_name::SOURCES, TagValue::U8(7)));
    }

    #[test]
    fn test_blob_tag_with_bogus_length_errors_without_huge_alloc() {
        // type 0x07 (BLOB), short name marker, name byte, then a u32 length of
        // 0xFFFFFFFF (~4 GB) with no payload following. The capped reader must
        // reject this immediately instead of pre-allocating a 4 GB Vec.
        let mut buf = Cursor::new(vec![0x80 | 0x07, tag_name::SOURCES, 0xFF, 0xFF, 0xFF, 0xFF]);
        let result = Tag::read_le(&mut buf);
        assert!(
            result.is_err(),
            "a blob length far beyond the cursor must error, not allocate"
        );
    }

    #[test]
    fn test_string_tag_with_bogus_length_errors_without_huge_alloc() {
        // type 0x02 (String), short name marker, name byte, then a u16 length of
        // 0xFFFF with no payload following.
        let mut buf = Cursor::new(vec![0x80 | 0x02, tag_name::FILENAME, 0xFF, 0xFF]);
        let result = Tag::read_le(&mut buf);
        assert!(
            result.is_err(),
            "a string length far beyond the cursor must error, not allocate"
        );
    }

    #[test]
    fn test_blob_tag_with_valid_length_still_decodes() {
        // A well-formed BLOB tag must still round-trip through the capped reader.
        let t = Tag::new_short(tag_name::SOURCES, TagValue::Blob(vec![1, 2, 3, 4]));
        assert_eq!(roundtrip(&t), t);
    }
}
