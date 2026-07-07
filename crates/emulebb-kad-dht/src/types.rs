use emulebb_kad_proto::{Ed2kHash, NodeId, Tag, TagName, TagValue, tag_name};
use std::net::Ipv4Addr;

/// One peer chosen to run an outbound Kad UDP firewall check against us.
///
/// The oracle (`CUDPFirewallTester::QueryNextClient`) only asks contacts that
/// support the UDP firewall check (Kad version > 5 / `>` `KADEMLIA_VERSION5_48a`)
/// and that are not themselves UDP firewalled, then opens an eD2k TCP session to
/// each and sends `OP_FWCHECKUDPREQ`. This struct carries exactly the endpoints
/// and identity that outbound path needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallCheckHelper {
    /// Peer Kad node id.
    pub id: NodeId,
    /// Peer IPv4 address.
    pub ip: Ipv4Addr,
    /// Peer Kad UDP port (where its firewall reply originates).
    pub udp_port: u16,
    /// Peer eD2k TCP port (where we open the firewall-check session).
    pub tcp_port: u16,
    /// Highest Kad version observed for the peer.
    pub kad_version: u8,
}

fn read_u16_tag_value(value: &TagValue) -> Option<u16> {
    match value {
        TagValue::U16(port) => Some(*port),
        TagValue::U32(port) => u16::try_from(*port).ok(),
        TagValue::U8(port) => Some(u16::from(*port)),
        TagValue::UInt(port) => u16::try_from(*port).ok(),
        _ => None,
    }
}

fn read_u8_tag_value(value: &TagValue) -> Option<u8> {
    match value {
        TagValue::U8(bits) => Some(*bits),
        TagValue::U16(bits) => u8::try_from(*bits).ok(),
        TagValue::U32(bits) => u8::try_from(*bits).ok(),
        TagValue::UInt(bits) => u8::try_from(*bits).ok(),
        _ => None,
    }
}

/// Kad HELLO metadata carried in oracle `SOURCEUPORT` and `KADMISCOPTIONS` tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HelloPeerMetadata {
    pub hello_source_udp_port: Option<u16>,
    pub udp_firewalled: bool,
    pub tcp_firewalled: bool,
    pub requests_hello_res_ack: bool,
}

pub fn parse_hello_peer_metadata(tags: &[Tag]) -> HelloPeerMetadata {
    let mut metadata = HelloPeerMetadata::default();

    for tag in tags {
        match &tag.name {
            TagName::Short(name) if *name == tag_name::SOURCEUPORT => {
                metadata.hello_source_udp_port =
                    read_u16_tag_value(&tag.value).filter(|port| *port != 0);
            }
            TagName::Short(name) if *name == tag_name::KADMISCOPTIONS => {
                let Some(bits) = read_u8_tag_value(&tag.value) else {
                    continue;
                };
                metadata.udp_firewalled = (bits & 0x01) != 0;
                metadata.tcp_firewalled = (bits & 0x02) != 0;
                metadata.requests_hello_res_ack = (bits & 0x04) != 0;
            }
            _ => {}
        }
    }

    metadata
}

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
    /// Kad `FT_SOURCETYPE`: 1/4 = HighID/non-firewalled (direct TCP); 3/5 =
    /// firewalled LowID reachable only via its Kad buddy (server-/buddy-assisted
    /// callback); 6 = firewalled with direct-UDP-callback support; 2 = ignored.
    /// Oracle `CSearch::ProcessResultFile` / `CDownloadQueue::KademliaSearchFile`.
    pub source_type: u8,
    /// Buddy's Kad id (`FT_BUDDYHASH`), present only for firewalled types 3/5.
    pub buddy_id: Option<[u8; 16]>,
    /// Buddy relay endpoint (`FT_SERVERIP`/`FT_SERVERPORT`) for types 3/5.
    pub buddy_ip: Option<Ipv4Addr>,
    pub buddy_port: u16,
}

/// Parse an `FT_BUDDYHASH` 32-char hex string into a 16-byte MD4 buddy id,
/// mirroring oracle `strmd4`. Returns `None` on a malformed/short string.
fn parse_buddy_hash(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        let hex = value.get(index * 2..index * 2 + 2)?;
        *byte = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(out)
}

impl SourceResult {
    /// Whether this Kad source is a firewalled LowID peer reachable only through
    /// its Kad buddy (oracle source types 3 and 5).
    #[must_use]
    pub fn is_firewalled_buddy_source(&self) -> bool {
        matches!(self.source_type, 3 | 5)
    }
}

impl SourceResult {
    pub fn from_tags(file_hash: Ed2kHash, source_id: Ed2kHash, tags: Vec<Tag>) -> Option<Self> {
        let mut ip: Option<Ipv4Addr> = None;
        let mut tcp_port: u16 = 0;
        let mut udp_port: u16 = 0;
        let mut obfuscation_options = None;
        let mut source_type: u8 = 0;
        let mut buddy_id: Option<[u8; 16]> = None;
        let mut buddy_ip: Option<Ipv4Addr> = None;
        let mut buddy_port: u16 = 0;

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
                TagName::Short(n) if *n == tag_name::SOURCETYPE => match &tag.value {
                    TagValue::UInt(v) if u8::try_from(*v).is_ok() => source_type = *v as u8,
                    TagValue::U32(v) if u8::try_from(*v).is_ok() => source_type = *v as u8,
                    TagValue::U16(v) if u8::try_from(*v).is_ok() => source_type = *v as u8,
                    TagValue::U8(v) => source_type = *v,
                    _ => {}
                },
                // For a firewalled buddy source (types 3/5) the buddy relay
                // endpoint is carried in FT_SERVERIP/FT_SERVERPORT (oracle
                // CSearch::ProcessResultFile maps these to uBuddyIP/uBuddyPort).
                // Unlike FT_SOURCEIP (Kad host order, `htonl`-ed on consume),
                // FT_SERVERIP carries the publisher's `GetBuddy()->GetIP()`
                // in_addr DWORD verbatim (first octet in the low byte): the
                // oracle feeds it straight to `ipstr`/`IsFiltered` with no
                // byte swap (DownloadQueue.cpp KademliaSearchFile).
                TagName::Short(n) if *n == tag_name::SERVERIP => match &tag.value {
                    TagValue::UInt(v) if u32::try_from(*v).is_ok() => {
                        buddy_ip = Some(Ipv4Addr::from((*v as u32).to_le_bytes()));
                    }
                    TagValue::U32(v) => buddy_ip = Some(Ipv4Addr::from(v.to_le_bytes())),
                    _ => {}
                },
                TagName::Short(n) if *n == tag_name::SERVERPORT => match &tag.value {
                    TagValue::UInt(v) => buddy_port = *v as u16,
                    TagValue::U16(v) => buddy_port = *v,
                    TagValue::U32(v) => buddy_port = *v as u16,
                    TagValue::U8(v) => buddy_port = (*v).into(),
                    _ => {}
                },
                // FT_BUDDYHASH is a 32-char hex MD4 string (oracle strmd4).
                TagName::Short(n) if *n == tag_name::BUDDYHASH => {
                    if let TagValue::String(s) = &tag.value {
                        buddy_id = parse_buddy_hash(s);
                    }
                }
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
            source_type,
            buddy_id,
            buddy_ip,
            buddy_port,
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
    fn hello_metadata_parses_source_udp_port_and_misc_bits() {
        let metadata = parse_hello_peer_metadata(&[
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::UInt(41_000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
        ]);

        assert_eq!(metadata.hello_source_udp_port, Some(41_000));
        assert!(metadata.udp_firewalled);
        assert!(metadata.tcp_firewalled);
        assert!(metadata.requests_hello_res_ack);
    }

    #[test]
    fn hello_metadata_ignores_zero_source_udp_port() {
        let metadata =
            parse_hello_peer_metadata(&[Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(0))]);

        assert_eq!(metadata.hello_source_udp_port, None);
        assert!(!metadata.udp_firewalled);
        assert!(!metadata.tcp_firewalled);
        assert!(!metadata.requests_hello_res_ack);
    }

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
    fn test_source_result_parses_firewalled_buddy_fields() {
        // A master-shaped firewalled LowID source entry (CSearch::ProcessResultFile
        // type 3): FT_SOURCETYPE + buddy id (FT_BUDDYHASH) + buddy relay endpoint
        // (FT_SERVERIP/FT_SERVERPORT). FT_SERVERIP is an in_addr DWORD (low
        // byte = first octet), NOT the Kad host order FT_SOURCEIP uses.
        let hash = Ed2kHash::from_bytes([9u8; 16]);
        let source_id = Ed2kHash::from_bytes([10u8; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x0A0B0C0D)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
            Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(3)),
            Tag::new_short(tag_name::SERVERIP, TagValue::U32(0x886433C6)),
            Tag::new_short(tag_name::SERVERPORT, TagValue::U16(5000)),
            Tag::new_short(
                tag_name::BUDDYHASH,
                TagValue::String("0123456789abcdef0123456789abcdef".to_string()),
            ),
        ];
        let result = SourceResult::from_tags(hash, source_id, tags).expect("buddy source result");
        assert_eq!(result.source_type, 3);
        assert!(result.is_firewalled_buddy_source());
        assert_eq!(
            result.buddy_id,
            Some([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef
            ])
        );
        assert_eq!(result.buddy_ip, Some(Ipv4Addr::new(198, 51, 100, 136)));
        assert_eq!(result.buddy_port, 5000);
        assert_eq!(result.ip, Ipv4Addr::new(10, 11, 12, 13));
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
