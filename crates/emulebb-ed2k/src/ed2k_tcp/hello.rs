use anyhow::{Context, Result};

use std::sync::atomic::{AtomicBool, Ordering};

use super::hello_buddy::hello_buddy_snapshot;
use super::{
    CT_EMULE_BUDDYIP, CT_EMULE_BUDDYUDP, CT_EMULE_MISCOPTIONS1, CT_EMULE_MISCOPTIONS2,
    CT_EMULE_UDPPORTS, CT_EMULE_VERSION, CT_MOD_VERSION, CT_NAME,
    CT_VERSION, EDONKEY_VERSION, EMULE_ADVERTISED_KAD_VERSION, EMULE_CRYPT_REQUESTS,
    EMULE_CRYPT_SUPPORTS, EMULE_INFO_FEATURES, EMULE_PROTOCOL_VERSION, EMULE_SECURE_IDENT_VERSION,
    EMULE_VERSION_MAJOR, EMULE_VERSION_MINOR, EMULE_VERSION_SHORT, EMULE_VERSION_UPDATE,
    ET_COMMENTS, ET_COMPRESSION, ET_EXTENDEDREQUEST, ET_FEATURES, ET_SOURCEEXCHANGE, ET_UDPPORT,
    ET_UDPVER, Ed2kHelloIdentity, HELLO_NICKNAME, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER,
    OP_EMULEPROT, OP_HELLO, OP_HELLOANSWER, TAG_SHORT_NAME_MASK, TAGTYPE_BLOB, TAGTYPE_BOOL,
    TAGTYPE_BOOLARRAY, TAGTYPE_FLOAT32, TAGTYPE_STR1, TAGTYPE_STRING, TAGTYPE_UINT8,
    TAGTYPE_UINT16, TAGTYPE_UINT32, TAGTYPE_UINT64, encode_packet,
};

pub(super) fn encode_hello_request(identity: Ed2kHelloIdentity) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.push(16);
    payload.extend_from_slice(&encode_hello_type_payload(
        identity,
        append_emule_hello_request_tags,
    ));
    encode_packet(OP_EDONKEYPROT, OP_HELLO, &payload)
}

fn encode_hello_type_payload(
    identity: Ed2kHelloIdentity,
    append_tags: fn(&mut Vec<u8>, Ed2kHelloIdentity),
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(&identity.user_hash);
    payload.extend_from_slice(&identity.client_id.to_le_bytes());
    payload.extend_from_slice(&identity.tcp_port.to_le_bytes());
    append_tags(&mut payload, identity);
    payload.extend_from_slice(&identity.server_ip.to_le_bytes());
    payload.extend_from_slice(&identity.server_port.to_le_bytes());
    payload
}

fn encode_ed2k_short_tag_header(payload: &mut Vec<u8>, type_byte: u8, name: u8) {
    payload.push(type_byte);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(name);
}

fn push_ed2k_u32_tag(payload: &mut Vec<u8>, name: u8, value: u32) {
    encode_ed2k_short_tag_header(payload, TAGTYPE_UINT32, name);
    payload.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn ed2k_string_tag_type(len: usize) -> u8 {
    if (1..=16).contains(&len) {
        TAGTYPE_STR1 + u8::try_from(len - 1).expect("string tag length fits in u8")
    } else {
        TAGTYPE_STRING
    }
}

fn push_ed2k_string_tag(payload: &mut Vec<u8>, name: u8, value: &str) {
    let value_bytes = value.as_bytes();
    let type_byte = ed2k_string_tag_type(value_bytes.len());
    encode_ed2k_short_tag_header(payload, type_byte, name);
    if type_byte == TAGTYPE_STRING {
        payload.extend_from_slice(
            &u16::try_from(value_bytes.len())
                .expect("string tag length fits in u16")
                .to_le_bytes(),
        );
    }
    payload.extend_from_slice(value_bytes);
}

pub(super) fn emule_misc_options1() -> u32 {
    let supports_aich = 1u32;
    let supports_unicode = 1u32;
    let udp_version = 4u32;
    let data_compression_version = 1u32;
    let secure_ident_version = EMULE_SECURE_IDENT_VERSION;
    let source_exchange_version = 4u32;
    let extended_requests_version = 2u32;
    // Stock v0.72a advertises comment/rating packet acceptance here. The
    // Rust client accepts and decodes OP_FILEDESC, while sending local comments still
    // depends on a future local metadata surface.
    let comments_version = 1u32;
    // Recent stock eMule no longer advertises peer cache support.
    let peer_cache = 0u32;
    let no_view_shared_files = 1u32;
    // Recent live-network captures and the local 0.72a source both advertise
    // the packed/multipacket startup profile on the peer hello path.
    let multipacket = 1u32;
    let preview_supported = 0u32;
    (supports_aich << 29)
        | (supports_unicode << 28)
        | (udp_version << 24)
        | (data_compression_version << 20)
        | (secure_ident_version << 16)
        | (source_exchange_version << 12)
        | (extended_requests_version << 8)
        | (comments_version << 4)
        | (peer_cache << 3)
        | (no_view_shared_files << 2)
        | (multipacket << 1)
        | preview_supported
}

pub(super) fn emule_misc_options2(connect_options: u8, direct_udp_callback: bool) -> u32 {
    // Mirror the recent eMule hello profile instead of the older conservative
    // advert. The runtime already exchanges the newer sources2, EXT2, and
    // hashset-request2 startup path that recent peers expect.
    let supports_file_identifiers = 1u32;
    let direct_udp_callback = u32::from(direct_udp_callback);
    // Chat/captcha is still an `ITEM_032` parity gap, so do not advertise it
    // until the peer-facing challenge/response surface exists.
    let supports_captcha = 0u32;
    let supports_source_exchange2 = 1u32;
    let requires_crypt_layer = 0u32;
    let requests_crypt_layer = u32::from((connect_options & EMULE_CRYPT_REQUESTS) != 0);
    let supports_crypt_layer = u32::from((connect_options & EMULE_CRYPT_SUPPORTS) != 0);
    let ext_multipacket = 1u32;
    let supports_large_files = 1u32;
    let kad_version = EMULE_ADVERTISED_KAD_VERSION;
    (supports_file_identifiers << 13)
        | (direct_udp_callback << 12)
        | (supports_captcha << 11)
        | (supports_source_exchange2 << 10)
        | (requires_crypt_layer << 9)
        | (requests_crypt_layer << 8)
        | (supports_crypt_layer << 7)
        | (ext_multipacket << 5)
        | (supports_large_files << 4)
        | kad_version
}

pub(super) fn emule_version_tag() -> u32 {
    (EMULE_VERSION_MAJOR << 17) | (EMULE_VERSION_MINOR << 10) | (EMULE_VERSION_UPDATE << 7)
}

fn append_emule_hello_request_tags(payload: &mut Vec<u8>, identity: Ed2kHelloIdentity) {
    append_recent_emule_hello_tags(payload, identity);
}

fn append_emule_hello_answer_tags(payload: &mut Vec<u8>, identity: Ed2kHelloIdentity) {
    append_recent_emule_hello_tags(payload, identity);
}

/// Mod-version string published only when the operator opts in to the real
/// identity. Left off by default so the hello carries exactly the standard
/// eMule tag set (i.e. an eMule Community 0.7-series client, which sends no
/// CT_MOD_VERSION string).
const RUST_MOD_VERSION: &str = "emule-rust";

/// Process-wide identity mode: when true, the hello adds a CT_MOD_VERSION tag
/// publishing the real `emule-rust` identity; when false (default) the hello is
/// the plain eMule tag set, indistinguishable from eMule Community. Set once
/// from `Ed2kConfig.publish_emule_rust_identity` at startup.
static PUBLISH_RUST_IDENTITY: AtomicBool = AtomicBool::new(false);

/// Select the advertised eD2k client identity (plain eMule/Community vs the real
/// emule-rust mod). Idempotent; called by core from the daemon config at startup.
pub fn set_publish_rust_identity(publish_rust: bool) {
    PUBLISH_RUST_IDENTITY.store(publish_rust, Ordering::Relaxed);
}

fn append_recent_emule_hello_tags(payload: &mut Vec<u8>, identity: Ed2kHelloIdentity) {
    // Default: the exact standard eMule hello tag set (6 tags) so we appear as a
    // stock eMule Community 0.7-series client. Only when the operator opts in do
    // we append a CT_MOD_VERSION="emule-rust" tag to publish the real identity.
    let publish_rust = PUBLISH_RUST_IDENTITY.load(Ordering::Relaxed);
    // Advertise the buddy link only while firewalled with a buddy (the snapshot
    // is `Some` exactly then), mirroring `buddySnapshot.bShouldAdvertise` and the
    // matching `GetHelloTagCount` +2 bump (CT_EMULE_BUDDYIP + CT_EMULE_BUDDYUDP).
    let buddy = hello_buddy_snapshot();
    let mut tag_count: u32 = if publish_rust { 7 } else { 6 };
    if buddy.is_some() {
        tag_count += 2;
    }
    payload.extend_from_slice(&tag_count.to_le_bytes());
    push_ed2k_string_tag(payload, CT_NAME, HELLO_NICKNAME);
    push_ed2k_u32_tag(payload, CT_VERSION, EDONKEY_VERSION);
    if publish_rust {
        push_ed2k_string_tag(payload, CT_MOD_VERSION, RUST_MOD_VERSION);
    }
    // The Rust client only exposes one UDP surface today, so advertise the Kad port
    // in both halves until a separate eD2k UDP listener exists.
    push_ed2k_u32_tag(
        payload,
        CT_EMULE_UDPPORTS,
        (u32::from(identity.udp_port) << 16) | u32::from(identity.udp_port),
    );
    if let Some(buddy) = buddy {
        // eMule stores GetIP() (network-byte-order in_addr); the tag value is that
        // uint32, which equals the octets read little-endian (matching how the
        // server source/client-id IPs are encoded elsewhere in the protocol).
        push_ed2k_u32_tag(
            payload,
            CT_EMULE_BUDDYIP,
            u32::from_le_bytes(buddy.ip.octets()),
        );
        // Low 16 bits = buddy UDP port; high 16 reserved (eMule writes 0).
        push_ed2k_u32_tag(payload, CT_EMULE_BUDDYUDP, u32::from(buddy.udp_port));
    }
    push_ed2k_u32_tag(payload, CT_EMULE_MISCOPTIONS1, emule_misc_options1());
    push_ed2k_u32_tag(
        payload,
        CT_EMULE_MISCOPTIONS2,
        emule_misc_options2(identity.connect_options, identity.direct_udp_callback),
    );
    push_ed2k_u32_tag(payload, CT_EMULE_VERSION, emule_version_tag());
}

pub(super) fn encode_hello_answer(identity: Ed2kHelloIdentity) -> Vec<u8> {
    encode_packet(
        OP_EDONKEYPROT,
        OP_HELLOANSWER,
        &encode_hello_type_payload(identity, append_emule_hello_answer_tags),
    )
}

fn encode_emule_info_payload(kad_udp_port: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    payload.push(EMULE_VERSION_SHORT);
    payload.push(EMULE_PROTOCOL_VERSION);
    payload.extend_from_slice(&7u32.to_le_bytes());
    push_ed2k_u32_tag(&mut payload, ET_COMPRESSION, 1);
    push_ed2k_u32_tag(&mut payload, ET_UDPVER, 4);
    push_ed2k_u32_tag(&mut payload, ET_UDPPORT, u32::from(kad_udp_port));
    push_ed2k_u32_tag(&mut payload, ET_SOURCEEXCHANGE, 3);
    push_ed2k_u32_tag(&mut payload, ET_COMMENTS, 1);
    push_ed2k_u32_tag(&mut payload, ET_EXTENDEDREQUEST, 2);
    push_ed2k_u32_tag(&mut payload, ET_FEATURES, EMULE_INFO_FEATURES);
    payload
}

pub(super) fn encode_emule_info_request(kad_udp_port: u16) -> Vec<u8> {
    encode_packet(
        OP_EMULEPROT,
        OP_EMULEINFO,
        &encode_emule_info_payload(kad_udp_port),
    )
}

pub(super) fn encode_emule_info_answer(kad_udp_port: u16) -> Vec<u8> {
    encode_packet(
        OP_EMULEPROT,
        OP_EMULEINFOANSWER,
        &encode_emule_info_payload(kad_udp_port),
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DecodedEmuleInfoProfile {
    pub(super) data_compression_version: u8,
    pub(super) udp_version: u8,
    pub(super) udp_port: u16,
    pub(super) source_exchange_version: u8,
    pub(super) supports_source_exchange: bool,
    pub(super) extended_requests_version: u8,
    pub(super) accepts_comments: bool,
    pub(super) supports_secure_ident: bool,
    pub(super) supports_preview: bool,
    /// Peer eMule compatibility version byte (eMule `m_byEmuleVersion`, the
    /// leading byte of OP_EMULEINFO). Feeds the old-client upload-score penalty.
    pub(super) emule_version: u8,
}

struct DecodedHelloTag<'a> {
    tag_name: Option<u8>,
    base_type: u8,
    value: &'a [u8],
    remaining: &'a [u8],
}

fn decode_hello_tag(mut bytes: &[u8]) -> Result<DecodedHelloTag<'_>> {
    if bytes.len() < 2 {
        anyhow::bail!("short eD2k hello tag header");
    }
    let type_byte = bytes[0];
    let short_name = (type_byte & TAG_SHORT_NAME_MASK) != 0;
    let base_type = type_byte & !TAG_SHORT_NAME_MASK;
    bytes = &bytes[1..];

    let tag_name = if short_name {
        let name = bytes[0];
        bytes = &bytes[1..];
        Some(name)
    } else {
        if bytes.len() < 2 {
            anyhow::bail!("short eD2k hello long-name length");
        }
        let name_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        bytes = &bytes[2..];
        if bytes.len() < name_len {
            anyhow::bail!("short eD2k hello long-name bytes");
        }
        let name = if name_len == 1 { Some(bytes[0]) } else { None };
        bytes = &bytes[name_len..];
        name
    };

    let (value, remaining) = match base_type {
        TAGTYPE_STRING => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello string tag length");
            }
            let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            if bytes.len() < 2 + len {
                anyhow::bail!("short eD2k hello string tag value");
            }
            (&bytes[2..2 + len], &bytes[2 + len..])
        }
        TAGTYPE_STR1..=0x20 => {
            let len = usize::from(base_type - TAGTYPE_STR1 + 1);
            if bytes.len() < len {
                anyhow::bail!("short eD2k hello compact string tag value");
            }
            (&bytes[..len], &bytes[len..])
        }
        TAGTYPE_UINT32 | TAGTYPE_FLOAT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short eD2k hello 32-bit tag value");
            }
            (&bytes[..4], &bytes[4..])
        }
        TAGTYPE_UINT64 => {
            if bytes.len() < 8 {
                anyhow::bail!("short eD2k hello uint64 tag value");
            }
            (&bytes[..8], &bytes[8..])
        }
        TAGTYPE_UINT16 => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello uint16 tag value");
            }
            (&bytes[..2], &bytes[2..])
        }
        TAGTYPE_UINT8 | TAGTYPE_BOOL => {
            if bytes.is_empty() {
                anyhow::bail!("short eD2k hello uint8/bool tag value");
            }
            (&bytes[..1], &bytes[1..])
        }
        TAGTYPE_BOOLARRAY => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello bool-array tag length");
            }
            let bit_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            let byte_len = (bit_len / 8).saturating_add(1);
            if bytes.len() < 2 + byte_len {
                anyhow::bail!("short eD2k hello bool-array tag value");
            }
            (&bytes[..2 + byte_len], &bytes[2 + byte_len..])
        }
        TAGTYPE_BLOB => {
            if bytes.len() < 4 {
                anyhow::bail!("short eD2k hello blob tag length");
            }
            let blob_len = usize::try_from(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
                .context("eD2k hello blob length overflow")?;
            if bytes.len() < 4 + blob_len {
                anyhow::bail!("short eD2k hello blob tag value");
            }
            (&bytes[4..4 + blob_len], &bytes[4 + blob_len..])
        }
        0x01 => {
            if bytes.len() < 16 {
                anyhow::bail!("short eD2k hello hash tag value");
            }
            (&bytes[..16], &bytes[16..])
        }
        _ => anyhow::bail!("unsupported eD2k hello tag type 0x{base_type:02X}"),
    };

    Ok(DecodedHelloTag {
        tag_name,
        base_type,
        value,
        remaining,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DecodedHelloIdentity {
    pub(super) user_hash: [u8; 16],
    pub(super) client_id: u32,
    pub(super) tcp_port: u16,
    /// Peer's eD2k client UDP port, from the low 16 bits of `CT_EMULE_UDPPORTS`
    /// (eMule `m_nUDPPort`); `0` when not advertised. Threaded into the upload
    /// queue to correlate inbound UDP source-reask by `(ip, udp_port)`.
    pub(super) udp_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DecodedHelloProfile {
    pub(super) identity: DecodedHelloIdentity,
    pub(super) is_mule_hello: bool,
    pub(super) supports_aich: bool,
    pub(super) supports_secure_ident: bool,
    pub(super) supports_multipacket: bool,
    pub(super) supports_ext_multipacket: bool,
    pub(super) source_exchange_version: u8,
    pub(super) supports_source_exchange: bool,
    pub(super) supports_source_exchange2: bool,
    pub(super) supports_file_identifiers: bool,
    /// Peer advertised a known GPL-breaker mod-version (eMule
    /// `CUpDownClient::CheckForGPLEvilDoer`): its upload score is zeroed.
    pub(super) gpl_evildoer: bool,
}

fn decode_hello_tag_u32(tag: &DecodedHelloTag<'_>) -> Option<u32> {
    match tag.base_type {
        TAGTYPE_UINT32 | TAGTYPE_FLOAT32 => Some(u32::from_le_bytes(tag.value.try_into().ok()?)),
        TAGTYPE_UINT16 => Some(u16::from_le_bytes(tag.value.try_into().ok()?).into()),
        TAGTYPE_UINT8 | TAGTYPE_BOOL => Some(u32::from(tag.value.first().copied()?)),
        _ => None,
    }
}

pub(super) fn decode_emule_info_profile(payload: &[u8]) -> Result<DecodedEmuleInfoProfile> {
    if payload.len() < 2 + 4 {
        anyhow::bail!("short eMule info payload {}", payload.len());
    }
    // eMule ProcessMuleInfoPacket: the leading byte is m_byEmuleVersion, with the
    // 0x2B -> 0x22 legacy normalisation; it is read before the protocol check.
    let emule_version = if payload[0] == 0x2B { 0x22 } else { payload[0] };
    if payload[1] != EMULE_PROTOCOL_VERSION {
        return Ok(DecodedEmuleInfoProfile {
            emule_version,
            ..DecodedEmuleInfoProfile::default()
        });
    }
    let mut cursor = &payload[2..];
    let tag_count = usize::try_from(u32::from_le_bytes(cursor[..4].try_into().unwrap()))
        .context("eMule info tag count overflow")?;
    cursor = &cursor[4..];

    let mut profile = DecodedEmuleInfoProfile {
        emule_version,
        ..DecodedEmuleInfoProfile::default()
    };
    for _ in 0..tag_count {
        let tag = decode_hello_tag(cursor)?;
        if let Some(value) = decode_hello_tag_u32(&tag) {
            match tag.tag_name {
                Some(ET_COMPRESSION) => profile.data_compression_version = value as u8,
                Some(ET_UDPVER) => profile.udp_version = value as u8,
                Some(ET_UDPPORT) => profile.udp_port = value as u16,
                Some(ET_SOURCEEXCHANGE) => {
                    profile.source_exchange_version = value as u8;
                    profile.supports_source_exchange = value != 0;
                }
                Some(ET_COMMENTS) => profile.accepts_comments = value != 0,
                Some(ET_EXTENDEDREQUEST) => profile.extended_requests_version = value as u8,
                Some(ET_FEATURES) => {
                    profile.supports_secure_ident = (value & 0x03) != 0;
                    profile.supports_preview = ((value >> 7) & 1) != 0;
                }
                _ => {}
            }
        }
        cursor = tag.remaining;
    }
    if profile.data_compression_version == 0 {
        profile.source_exchange_version = 0;
        profile.supports_source_exchange = false;
        profile.extended_requests_version = 0;
        profile.accepts_comments = false;
        profile.udp_port = 0;
    }
    Ok(profile)
}

fn decode_hello_profile_from_type_payload(type_payload: &[u8]) -> Result<DecodedHelloProfile> {
    if type_payload.len() < 16 + 4 + 2 + 4 {
        anyhow::bail!("short eD2k hello identity payload");
    }
    let mut identity = DecodedHelloIdentity {
        user_hash: type_payload[..16]
            .try_into()
            .context("short eD2k hello user hash")?,
        client_id: u32::from_le_bytes([
            type_payload[16],
            type_payload[17],
            type_payload[18],
            type_payload[19],
        ]),
        tcp_port: u16::from_le_bytes([type_payload[20], type_payload[21]]),
        udp_port: 0,
    };

    let mut cursor = &type_payload[22..];
    let tag_count = usize::try_from(u32::from_le_bytes(cursor[..4].try_into().unwrap()))
        .context("eD2k hello tag count overflow")?;
    cursor = &cursor[4..];

    let mut is_mule_hello = false;
    let mut supports_aich = false;
    let mut supports_secure_ident = false;
    let mut supports_multipacket = false;
    let mut supports_ext_multipacket = false;
    let mut source_exchange_version = 0;
    let mut supports_source_exchange = false;
    let mut supports_source_exchange2 = false;
    let mut supports_file_identifiers = false;
    let mut gpl_evildoer = false;
    for _ in 0..tag_count {
        let tag = decode_hello_tag(cursor)?;
        if tag.tag_name == Some(CT_EMULE_VERSION) {
            is_mule_hello = true;
        }
        if tag.tag_name == Some(CT_MOD_VERSION)
            && let Ok(mod_version) = std::str::from_utf8(tag.value)
            && super::hello_gpl::is_gpl_evildoer_mod_version(mod_version)
        {
            gpl_evildoer = true;
        }
        if tag.tag_name == Some(CT_EMULE_MISCOPTIONS2)
            && let Some(misc_options2) = decode_hello_tag_u32(&tag)
        {
            supports_file_identifiers = ((misc_options2 >> 13) & 1) != 0;
            supports_source_exchange2 = ((misc_options2 >> 10) & 1) != 0;
            supports_ext_multipacket = ((misc_options2 >> 5) & 1) != 0;
        }
        if tag.tag_name == Some(CT_EMULE_MISCOPTIONS1)
            && let Some(misc_options1) = decode_hello_tag_u32(&tag)
        {
            supports_aich = ((misc_options1 >> 29) & 0x07) & 0x01 != 0;
            supports_secure_ident = ((misc_options1 >> 16) & 0x0F) != 0;
            source_exchange_version = ((misc_options1 >> 12) & 0x0F) as u8;
            supports_source_exchange = source_exchange_version != 0;
            supports_multipacket = ((misc_options1 >> 1) & 1) != 0;
        }
        if tag.tag_name == Some(CT_EMULE_UDPPORTS)
            && let Some(udp_ports) = decode_hello_tag_u32(&tag)
        {
            // eMule CT_EMULE_UDPPORTS: high 16 = Kad port, low 16 = eD2k UDP port.
            identity.udp_port = udp_ports as u16;
        }
        cursor = tag.remaining;
    }

    Ok(DecodedHelloProfile {
        identity,
        is_mule_hello,
        supports_aich,
        supports_secure_ident,
        supports_multipacket,
        supports_ext_multipacket,
        source_exchange_version,
        supports_source_exchange,
        supports_source_exchange2,
        supports_file_identifiers,
        gpl_evildoer,
    })
}

pub(super) fn decode_hello_profile(payload: &[u8]) -> Result<DecodedHelloProfile> {
    let type_payload = match payload.split_first() {
        Some((&16, rest)) => rest,
        _ => payload,
    };
    decode_hello_profile_from_type_payload(type_payload)
}

pub(super) fn decode_hello_answer_profile(payload: &[u8]) -> Result<DecodedHelloProfile> {
    decode_hello_profile_from_type_payload(payload)
}

fn is_mule_hello_type_payload(payload: &[u8]) -> Result<bool> {
    Ok(decode_hello_profile_from_type_payload(payload)?.is_mule_hello)
}

pub(super) fn is_mule_hello(payload: &[u8]) -> Result<bool> {
    if payload.len() < 1 + 16 + 4 + 2 + 4 {
        anyhow::bail!("short eD2k OP_HELLO payload");
    }
    is_mule_hello_type_payload(&payload[1..])
}

pub(super) fn build_hello_responses(
    incoming_payload: &[u8],
    response_identity: Ed2kHelloIdentity,
) -> Result<Vec<Vec<u8>>> {
    let is_mule_hello = is_mule_hello(incoming_payload)?;
    let mut replies = Vec::with_capacity(2);
    if !is_mule_hello {
        replies.push(encode_emule_info_request(response_identity.udp_port));
    }
    replies.push(encode_hello_answer(response_identity));
    Ok(replies)
}
