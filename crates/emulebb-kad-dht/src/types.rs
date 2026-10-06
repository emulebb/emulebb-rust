use emulebb_kad_proto::{
    Ed2kHash, NodeId, Tag, TagName, TagValue, constants::KAD_VERSION_AICH_KEYWORD_PUBLISH, tag_name,
};
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

/// One plausible AICH root observation from the Kad storage contact that
/// returned a keyword result. Reported publisher popularity is deliberately
/// not retained as votes: the responder itself contributes exactly one
/// observation to the transfer-time corroboration layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KadAichCandidate {
    pub root: [u8; 20],
    pub responder_ip: Ipv4Addr,
}

/// A file entry found by keyword search.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub hash: Ed2kHash,
    pub names: Vec<String>,
    pub size: Option<u64>,
    pub file_type: Option<String>,
    /// Remote complete-source count parsed from the oracle `TAG_SOURCES` tag.
    pub source_count: Option<u32>,
    pub media_artist: Option<String>,
    pub media_album: Option<String>,
    pub media_title: Option<String>,
    pub media_length_seconds: Option<u32>,
    pub media_bitrate_kbps: Option<u32>,
    pub media_codec: Option<String>,
    pub aich_candidate: Option<KadAichCandidate>,
    pub tags: Vec<Tag>,
}

impl SearchResult {
    pub fn from_tags(hash: Ed2kHash, tags: Vec<Tag>) -> Self {
        let mut names = Vec::new();
        let mut size: Option<u64> = None;
        let mut size_low: Option<u32> = None;
        let mut size_high: Option<u32> = None;
        let mut file_type = None;
        let mut source_count: Option<u32> = None;
        let mut media_artist = None;
        let mut media_album = None;
        let mut media_title = None;
        let mut media_length_seconds = None;
        let mut media_bitrate_kbps = None;
        let mut media_codec = None;

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
                TagName::Short(n) if *n == tag_name::FILETYPE && file_type.is_none() => {
                    file_type = nonempty_string(&tag.value);
                }
                TagName::Short(n) if *n == tag_name::SOURCES => {
                    if let Some(value) = unsigned_u32(&tag.value) {
                        source_count = Some(value);
                    }
                }
                TagName::Short(n) if *n == tag_name::MEDIA_ARTIST && media_artist.is_none() => {
                    media_artist = nonempty_string(&tag.value);
                }
                TagName::Short(n) if *n == tag_name::MEDIA_ALBUM && media_album.is_none() => {
                    media_album = nonempty_string(&tag.value);
                }
                TagName::Short(n) if *n == tag_name::MEDIA_TITLE && media_title.is_none() => {
                    media_title = nonempty_string(&tag.value);
                }
                TagName::Short(n)
                    if *n == tag_name::MEDIA_LENGTH && media_length_seconds.is_none() =>
                {
                    media_length_seconds = unsigned_u32(&tag.value);
                }
                TagName::Short(n)
                    if *n == tag_name::MEDIA_BITRATE && media_bitrate_kbps.is_none() =>
                {
                    media_bitrate_kbps = unsigned_u32(&tag.value);
                }
                TagName::Short(n) if *n == tag_name::MEDIA_CODEC && media_codec.is_none() => {
                    media_codec = nonempty_string(&tag.value);
                }
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
            file_type,
            source_count,
            media_artist,
            media_album,
            media_title,
            media_length_seconds,
            media_bitrate_kbps,
            media_codec,
            aich_candidate: None,
            tags,
        }
    }

    pub(crate) fn from_observation(
        hash: Ed2kHash,
        tags: Vec<Tag>,
        responder_ip: Ipv4Addr,
        responder_version: u8,
    ) -> Self {
        let candidate = kad_aich_candidate(&tags, responder_ip, responder_version);
        let mut result = Self::from_tags(hash, tags);
        result.aich_candidate = candidate;
        result
    }
}

const MAX_AICH_RESULT_HASHES: usize = 11;

fn kad_aich_candidate(
    tags: &[Tag],
    responder_ip: Ipv4Addr,
    responder_version: u8,
) -> Option<KadAichCandidate> {
    if responder_version < KAD_VERSION_AICH_KEYWORD_PUBLISH {
        return None;
    }

    let publishers_known = tags.iter().find_map(|tag| {
        if tag.name != TagName::Short(tag_name::PUBLISHINFO) {
            return None;
        }
        unsigned_u32(&tag.value).map(|value| ((value >> 16) & 0xFF) as u8)
    })?;

    let mut result_payload = None;
    for tag in tags {
        if tag.name != TagName::Short(tag_name::KADAICHHASHRESULT) {
            continue;
        }
        if result_payload.is_some() {
            return None;
        }
        let TagValue::SmallBlob(payload) = &tag.value else {
            return None;
        };
        result_payload = Some(payload.as_slice());
    }
    let roots = decode_aich_result_payload(result_payload?)?;
    let [(popularity, root)] = roots.as_slice() else {
        return None;
    };

    // These unauthenticated counts are only a plausibility filter. They never
    // become signer votes; this response is one observation from responder_ip.
    if publishers_known < 2 || *popularity < 2 {
        return None;
    }
    if publishers_known / *popularity > 3 {
        return None;
    }

    Some(KadAichCandidate {
        root: *root,
        responder_ip,
    })
}

fn unsigned_u32(value: &TagValue) -> Option<u32> {
    match value {
        TagValue::U8(value) => Some(u32::from(*value)),
        TagValue::U16(value) => Some(u32::from(*value)),
        TagValue::U32(value) => Some(*value),
        TagValue::UInt(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}

fn nonempty_string(value: &TagValue) -> Option<String> {
    let TagValue::String(value) = value else {
        return None;
    };
    (!value.trim().is_empty()).then(|| value.clone())
}

fn decode_aich_result_payload(payload: &[u8]) -> Option<Vec<(u8, [u8; 20])>> {
    let (&count, body) = payload.split_first()?;
    let count = usize::from(count);
    if count > MAX_AICH_RESULT_HASHES || body.len() < count * 21 {
        return None;
    }

    let mut roots = Vec::with_capacity(count);
    for record in body[..count * 21].as_chunks::<21>().0 {
        let popularity = record[0];
        if popularity == 0 {
            continue;
        }
        let root = record[1..].try_into().ok()?;
        roots.push((popularity, root));
    }
    Some(roots)
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

    fn aich_result_tags(publishers: u8, records: &[(u8, [u8; 20])]) -> Vec<Tag> {
        let mut payload = vec![records.len() as u8];
        for (popularity, root) in records {
            payload.push(*popularity);
            payload.extend_from_slice(root);
        }
        vec![
            Tag::filename("candidate.iso"),
            Tag::filesize(123),
            Tag::new_short(
                tag_name::PUBLISHINFO,
                TagValue::U32((1 << 24) | (u32::from(publishers) << 16) | 1000),
            ),
            Tag::new_short(tag_name::KADAICHHASHRESULT, TagValue::SmallBlob(payload)),
        ]
    }

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
            Tag::filetype("Audio"),
            Tag::sources(5),
            Tag::new_short(
                tag_name::MEDIA_ARTIST,
                TagValue::String("Example Artist".to_string()),
            ),
            Tag::new_short(
                tag_name::MEDIA_ALBUM,
                TagValue::String("Example Album".to_string()),
            ),
            Tag::new_short(
                tag_name::MEDIA_TITLE,
                TagValue::String("Example Title".to_string()),
            ),
            Tag::new_short(tag_name::MEDIA_LENGTH, TagValue::UInt(321)),
            Tag::new_short(tag_name::MEDIA_BITRATE, TagValue::UInt(192)),
            Tag::new_short(tag_name::MEDIA_CODEC, TagValue::String("MP3".to_string())),
        ];
        let result = SearchResult::from_tags(hash, tags);
        assert_eq!(result.names, vec!["test.mp3".to_string()]);
        assert_eq!(result.size, Some(1_000_000));
        assert_eq!(result.file_type.as_deref(), Some("Audio"));
        assert_eq!(result.source_count, Some(5));
        assert_eq!(result.media_artist.as_deref(), Some("Example Artist"));
        assert_eq!(result.media_album.as_deref(), Some("Example Album"));
        assert_eq!(result.media_title.as_deref(), Some("Example Title"));
        assert_eq!(result.media_length_seconds, Some(321));
        assert_eq!(result.media_bitrate_kbps, Some(192));
        assert_eq!(result.media_codec.as_deref(), Some("MP3"));
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
    fn kad_aich_candidate_requires_supported_responder_and_preserves_provenance() {
        let hash = Ed2kHash::from_bytes([4u8; 16]);
        let responder = Ipv4Addr::new(203, 0, 113, 9);
        let root = [0xAB; 20];
        let mut tags = aich_result_tags(3, &[(2, root)]);
        let TagValue::SmallBlob(payload) = &mut tags[3].value else {
            unreachable!();
        };
        payload.extend_from_slice(&[0xFE, 0xED]);

        let result = SearchResult::from_observation(hash, tags.clone(), responder, 9);
        assert_eq!(
            result.aich_candidate,
            Some(KadAichCandidate {
                root,
                responder_ip: responder,
            })
        );
        assert_eq!(
            SearchResult::from_observation(hash, tags.clone(), responder, 8).aich_candidate,
            None
        );
        assert_eq!(
            SearchResult::from_observation(hash, tags, responder, 0).aich_candidate,
            None
        );
    }

    #[test]
    fn kad_aich_candidate_rejects_conflicts_and_implausible_counts() {
        let hash = Ed2kHash::from_bytes([4u8; 16]);
        let responder = Ipv4Addr::new(203, 0, 113, 9);
        assert!(
            SearchResult::from_observation(
                hash,
                aich_result_tags(4, &[(2, [0xAA; 20]), (2, [0xBB; 20])]),
                responder,
                9,
            )
            .aich_candidate
            .is_none()
        );
        for (publishers, popularity) in [(1, 1), (2, 1), (8, 2), (0, 2)] {
            assert!(
                SearchResult::from_observation(
                    hash,
                    aich_result_tags(publishers, &[(popularity, [0xAA; 20])]),
                    responder,
                    9,
                )
                .aich_candidate
                .is_none(),
                "publishers={publishers} popularity={popularity}"
            );
        }
        assert!(
            SearchResult::from_observation(
                hash,
                aich_result_tags(7, &[(2, [0xAA; 20])]),
                responder,
                9,
            )
            .aich_candidate
            .is_some(),
            "integer ratio 7/2 matches current aMule"
        );
    }

    #[test]
    fn malformed_kad_aich_data_does_not_reject_the_search_result() {
        let hash = Ed2kHash::from_bytes([4u8; 16]);
        let responder = Ipv4Addr::new(203, 0, 113, 9);
        let malformed_payloads = vec![Vec::new(), vec![12], vec![1, 2, 0xAA], {
            let mut payload = vec![2, 2];
            payload.extend_from_slice(&[0xAA; 20]);
            payload
        }];
        for payload in malformed_payloads {
            let tags = vec![
                Tag::filename("still-usable.iso"),
                Tag::filesize(123),
                Tag::new_short(tag_name::PUBLISHINFO, TagValue::U32(0x0102_03E8)),
                Tag::new_short(tag_name::KADAICHHASHRESULT, TagValue::SmallBlob(payload)),
            ];
            let result = SearchResult::from_observation(hash, tags, responder, 9);
            assert_eq!(result.names, vec!["still-usable.iso"]);
            assert_eq!(result.size, Some(123));
            assert!(result.aich_candidate.is_none());
        }
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
