use emulebb_kad_proto::{Ed2kHash, Tag, TagName, TagValue, tag_name};
use std::net::Ipv4Addr;

/// A file entry found by keyword search.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub hash: Ed2kHash,
    pub names: Vec<String>,
    pub size: Option<u64>,
    /// Remote complete-source count parsed from the oracle `TAG_SOURCES` tag.
    pub source_count: Option<u32>,
    pub tags: Vec<Tag>,
}

impl SearchResult {
    pub fn from_tags(hash: Ed2kHash, tags: Vec<Tag>) -> Self {
        let mut names = Vec::new();
        let mut size: Option<u64> = None;
        let mut size_low: Option<u32> = None;
        let mut size_high: Option<u32> = None;
        let mut source_count: Option<u32> = None;

        for tag in &tags {
            match &tag.name {
                TagName::Short(n) if *n == tag_name::FILENAME => {
                    if let TagValue::String(s) = &tag.value {
                        names.push(s.clone());
                    }
                }
                TagName::Short(n) if *n == tag_name::FILESIZE => match &tag.value {
                    TagValue::UInt(v) => size = Some(*v),
                    TagValue::U64(v) => size = Some(*v),
                    TagValue::U32(v) => size_low = Some(*v),
                    TagValue::U16(v) => size_low = Some((*v).into()),
                    TagValue::U8(v) => size_low = Some((*v).into()),
                    _ => {}
                },
                TagName::Short(n) if *n == tag_name::FILESIZE_HI => match &tag.value {
                    TagValue::UInt(v) => size_high = Some(*v as u32),
                    TagValue::U32(v) => size_high = Some(*v),
                    TagValue::U16(v) => size_high = Some((*v).into()),
                    TagValue::U8(v) => size_high = Some((*v).into()),
                    _ => {}
                },
                TagName::Short(n) if *n == tag_name::SOURCES => match &tag.value {
                    TagValue::UInt(v) => source_count = Some(*v as u32),
                    TagValue::U32(v) => source_count = Some(*v),
                    TagValue::U16(v) => source_count = Some((*v).into()),
                    TagValue::U8(v) => source_count = Some((*v).into()),
                    _ => {}
                },
                _ => {}
            }
        }

        if size.is_none()
            && let Some(low) = size_low
        {
            let high = size_high.unwrap_or(0);
            size = Some(((high as u64) << 32) | low as u64);
        }

        SearchResult {
            hash,
            names,
            size,
            source_count,
            tags,
        }
    }
}

/// A peer known to have a specific file (from source search).
#[derive(Debug, Clone)]
pub struct SourceResult {
    pub file_hash: Ed2kHash,
    pub source_id: Ed2kHash,
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub obfuscation_options: Option<u8>,
}

impl SourceResult {
    pub fn from_tags(file_hash: Ed2kHash, source_id: Ed2kHash, tags: Vec<Tag>) -> Option<Self> {
        let mut ip: Option<Ipv4Addr> = None;
        let mut tcp_port: u16 = 0;
        let mut udp_port: u16 = 0;
        let mut obfuscation_options = None;

        for tag in &tags {
            match &tag.name {
                TagName::Short(n) if *n == tag_name::SOURCEIP => match &tag.value {
                    TagValue::UInt(v) if u32::try_from(*v).is_ok() => {
                        ip = Some(Ipv4Addr::from((*v as u32).to_be_bytes()));
                    }
                    TagValue::U32(v) => ip = Some(Ipv4Addr::from(v.to_be_bytes())),
                    _ => {}
                },
                TagName::Short(n) if *n == tag_name::SOURCEPORT => match &tag.value {
                    TagValue::UInt(v) => tcp_port = *v as u16,
                    TagValue::U16(v) => tcp_port = *v,
                    TagValue::U32(v) => tcp_port = *v as u16,
                    TagValue::U8(v) => tcp_port = (*v).into(),
                    _ => {}
                },
                TagName::Short(n) if *n == tag_name::SOURCEUPORT => match &tag.value {
                    TagValue::UInt(v) => udp_port = *v as u16,
                    TagValue::U16(v) => udp_port = *v,
                    TagValue::U32(v) => udp_port = *v as u16,
                    TagValue::U8(v) => udp_port = (*v).into(),
                    _ => {}
                },
                TagName::Short(n) if *n == tag_name::ENCRYPTION => match &tag.value {
                    TagValue::UInt(v) if u8::try_from(*v).is_ok() => {
                        obfuscation_options = Some(*v as u8)
                    }
                    TagValue::U32(v) if u8::try_from(*v).is_ok() => {
                        obfuscation_options = Some(*v as u8)
                    }
                    TagValue::U16(v) if u8::try_from(*v).is_ok() => {
                        obfuscation_options = Some(*v as u8)
                    }
                    TagValue::U8(v) => obfuscation_options = Some(*v),
                    _ => {}
                },
                _ => {}
            }
        }

        let ip = ip?;
        if tcp_port == 0 {
            return None;
        }
        // If udp_port is 0, fall back to tcp_port
        if udp_port == 0 {
            udp_port = tcp_port;
        }

        Some(SourceResult {
            file_hash,
            source_id,
            ip,
            tcp_port,
            udp_port,
            obfuscation_options,
        })
    }
}

/// A note/rating for a file (from notes search).
#[derive(Debug, Clone)]
pub struct NoteResult {
    pub file_hash: Ed2kHash,
    /// Oracle-style note/source identity from the `SEARCH_RES` entry ID slot.
    pub source_id: Ed2kHash,
    pub rating: Option<u8>,
    pub comment: Option<String>,
    pub source_tags: Vec<Tag>,
}

impl NoteResult {
    pub fn from_tags(file_hash: Ed2kHash, source_id: Ed2kHash, tags: Vec<Tag>) -> Option<Self> {
        let mut rating = None;
        let mut comment = None;

        for tag in &tags {
            match &tag.name {
                TagName::Short(n) if *n == tag_name::FILERATING => match &tag.value {
                    TagValue::UInt(v) => rating = Some(*v as u8),
                    TagValue::U8(v) => rating = Some(*v),
                    TagValue::U32(v) => rating = Some(*v as u8),
                    TagValue::U16(v) => rating = Some(*v as u8),
                    _ => {}
                },
                TagName::Short(n) if *n == tag_name::DESCRIPTION => {
                    if let TagValue::String(s) = &tag.value {
                        comment = Some(s.clone());
                    }
                }
                _ => {}
            }
        }

        let comment = comment.and_then(|text| {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        // eMule notes are only meaningful if they carry a non-empty comment or
        // a rating. Empty payloads are ignored. Reference:
        // srchybrid/kademlia/kademlia/Search.cpp CSearch::ProcessResultNotes.
        if rating.is_none() && comment.is_none() {
            return None;
        }

        Some(NoteResult {
            file_hash,
            source_id,
            rating,
            comment,
            source_tags: tags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::{Ed2kHash, Tag};

    #[test]
    fn test_search_result_from_tags() {
        let hash = Ed2kHash::from_bytes([1u8; 16]);
        let tags = vec![
            Tag::filename("test.mp3"),
            Tag::filesize(1_000_000),
            Tag::sources(5),
        ];
        let result = SearchResult::from_tags(hash, tags);
        assert_eq!(result.names, vec!["test.mp3".to_string()]);
        assert_eq!(result.size, Some(1_000_000));
        assert_eq!(result.source_count, Some(5));
    }

    #[test]
    fn test_search_result_no_filename() {
        let hash = Ed2kHash::from_bytes([2u8; 16]);
        let tags = vec![Tag::filesize(999)];
        let result = SearchResult::from_tags(hash, tags);
        assert!(result.names.is_empty());
        assert_eq!(result.size, Some(999));
    }

    #[test]
    fn test_search_result_combines_filesize_hi() {
        let hash = Ed2kHash::from_bytes([3u8; 16]);
        let tags = vec![
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(1)),
            Tag::new_short(tag_name::FILESIZE_HI, TagValue::U32(2)),
        ];
        let result = SearchResult::from_tags(hash, tags);
        assert_eq!(result.size, Some((2u64 << 32) | 1));
    }

    #[test]
    fn test_source_result_from_emule_source_tags() {
        let hash = Ed2kHash::from_bytes([4u8; 16]);
        let source_id = Ed2kHash::from_bytes([5u8; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x01020304)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(4672)),
            Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(1)),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0x03)),
        ];
        let result = SourceResult::from_tags(hash, source_id, tags).expect("source result");
        assert_eq!(result.source_id, source_id);
        assert_eq!(result.ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(result.tcp_port, 4662);
        assert_eq!(result.udp_port, 4672);
        assert_eq!(result.obfuscation_options, Some(0x03));
    }

    #[test]
    fn test_source_result_accepts_unknown_source_type_when_endpoint_is_valid() {
        let hash = Ed2kHash::from_bytes([7u8; 16]);
        let source_id = Ed2kHash::from_bytes([8u8; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x01020304)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
            Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(2)),
        ];
        let result = SourceResult::from_tags(hash, source_id, tags).expect("harvest source result");
        assert_eq!(result.ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(result.udp_port, 4662);
        assert_eq!(result.obfuscation_options, None);
    }

    #[test]
    fn test_note_result_from_emule_note_tags() {
        let file_hash = Ed2kHash::from_bytes([5u8; 16]);
        let source_id = Ed2kHash::from_bytes([6u8; 16]);
        let tags = vec![
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("nice".to_string())),
            Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
        ];
        let result = NoteResult::from_tags(file_hash, source_id, tags).expect("note result");
        assert_eq!(result.file_hash, file_hash);
        assert_eq!(result.source_id, source_id);
        assert_eq!(result.rating, Some(4));
        assert_eq!(result.comment.as_deref(), Some("nice"));
    }

    #[test]
    fn test_note_result_rejects_empty_payload() {
        let file_hash = Ed2kHash::from_bytes([8u8; 16]);
        let source_id = Ed2kHash::from_bytes([9u8; 16]);
        let tags = vec![Tag::new_short(
            tag_name::DESCRIPTION,
            TagValue::String("   ".to_string()),
        )];
        assert!(NoteResult::from_tags(file_hash, source_id, tags).is_none());
    }
}
