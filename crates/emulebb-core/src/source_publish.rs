//! Kad source-publish tag builders.
//!
//! Pure helpers that build the KADEMLIA2_PUBLISH source tag set and the
//! supporting eMule conventions: the reachability-dependent source type, the
//! byte-swapped Kad chunk order used to derive the publisher client hash, and
//! the source encryption-options byte. The tag set mirrors the oracle
//! STOREFILE branches (`CSearch::SendFindValue`, Search.cpp:700-745):
//!
//! - not TCP-firewalled: `SOURCETYPE 1/4` + own TCP port,
//! - TCP-firewalled with verified-open Kad UDP: `SOURCETYPE 6` (direct UDP
//!   callback) + the direct-callback connect-options bit,
//! - TCP-firewalled with an outgoing buddy: `SOURCETYPE 3/5` + the buddy relay
//!   endpoint (`SERVERIP`/`SERVERPORT`) + the buddy id (`BUDDYHASH`).
//!
//! Re-exported `pub(crate)` from the crate root so the publish loop and the
//! test module reach them by their bare names.

use std::net::Ipv4Addr;

use emulebb_ed2k::ed2k_tcp::emule_connect_options;
use emulebb_kad_proto::{NodeId, Tag, TagValue, tag_name};

use crate::EMULE_LARGE_FILE_SIZE_THRESHOLD;
use crate::kad_buddy::buddy_search_target;

/// Direct-UDP-callback bit of the connect-options byte
/// (`GetMyConnectOptions`: `uDirectUDPCallback << 3`).
const EMULE_CONNECT_OPTIONS_DIRECT_CALLBACK: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourcePublishSettings {
    pub(crate) tcp_port: u16,
    pub(crate) obfuscation_enabled: bool,
}

/// How remote downloaders can reach us, selecting the oracle STOREFILE publish
/// branch. Derived once per publish cycle from the live firewall/buddy state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourcePublishReachability {
    /// Not TCP-firewalled: direct-connect source (`SOURCETYPE` 1, or 4 for
    /// large files).
    Open,
    /// TCP-firewalled but Kad UDP verified-open: direct-UDP-callback source
    /// (`SOURCETYPE` 6, connect options carry the direct-callback bit).
    DirectUdpCallback,
    /// TCP-firewalled with an outgoing buddy: buddy-relayed source
    /// (`SOURCETYPE` 3, or 5 for large files). The relay endpoint is the
    /// buddy's Kad UDP address (`FINDBUDDY_RES` source), published as
    /// `SERVERIP`/`SERVERPORT`.
    BuddyRelay {
        buddy_ip: Ipv4Addr,
        buddy_kad_port: u16,
    },
}

pub(crate) fn emule_high_id_source_type(file_size: u64) -> u32 {
    if file_size > EMULE_LARGE_FILE_SIZE_THRESHOLD {
        4
    } else {
        1
    }
}

/// Buddy-relayed source type (oracle `pFile->GetFileSize() >
/// OLD_MAX_EMULE_FILE_SIZE ? 5 : 3`).
fn emule_buddy_source_type(file_size: u64) -> u8 {
    if file_size > EMULE_LARGE_FILE_SIZE_THRESHOLD {
        5
    } else {
        3
    }
}

pub(crate) fn emule_kad_chunk_order(bytes: [u8; 16]) -> [u8; 16] {
    let mut ordered = [0u8; 16];
    for (dst, src) in ordered.chunks_exact_mut(4).zip(bytes.chunks_exact(4)) {
        dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
    }
    ordered
}

pub(crate) fn source_publish_client_hash(ed2k_user_hash: [u8; 16]) -> NodeId {
    NodeId::from_bytes(emule_kad_chunk_order(ed2k_user_hash))
}

pub(crate) fn emule_source_encryption_options(obfuscation_enabled: bool) -> u8 {
    emule_connect_options(obfuscation_enabled)
}

/// `TAG_BUDDYHASH` string for our own buddy-relayed publish: the oracle sends
/// `md4str(CUInt128(true).Xor(GetKadID()).GetData())` — the uppercase hex of
/// the complement of our Kad id, in the same byte order `WriteUInt128` puts on
/// the wire (which is exactly the raw `NodeId` layout).
fn buddy_publish_hash_hex(own_kad_id: NodeId) -> String {
    let target = buddy_search_target(own_kad_id);
    let mut hex = String::with_capacity(32);
    for byte in target.0 {
        hex.push_str(&format!("{byte:02X}"));
    }
    hex
}

pub(crate) fn build_source_publish_tags(
    kad_udp_port: u16,
    source_publish_settings: SourcePublishSettings,
    file_size: u64,
    reachability: SourcePublishReachability,
    own_kad_id: NodeId,
) -> Vec<Tag> {
    let mut connect_options =
        emule_source_encryption_options(source_publish_settings.obfuscation_enabled);
    let mut tags = Vec::with_capacity(8);
    match reachability {
        SourcePublishReachability::Open => {
            tags.push(Tag::new_short(
                tag_name::SOURCETYPE,
                TagValue::UInt(u64::from(emule_high_id_source_type(file_size))),
            ));
        }
        SourcePublishReachability::DirectUdpCallback => {
            tags.push(Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(6)));
            // Consumers warn and drop type-6 sources whose connect options do
            // not carry the direct-callback bit (`byCryptOptions & 0x08`,
            // CDownloadQueue::KademliaSearchFile case 6).
            connect_options |= EMULE_CONNECT_OPTIONS_DIRECT_CALLBACK;
        }
        SourcePublishReachability::BuddyRelay {
            buddy_ip,
            buddy_kad_port,
        } => {
            // Oracle order: SOURCETYPE (forced uint8), SERVERIP, SERVERPORT,
            // BUDDYHASH, then the common tail. SERVERIP is the buddy's
            // `GetIP()` in_addr DWORD (first octet in the low byte), consumed
            // verbatim by `ipstr`/`IsFiltered` on the downloader side.
            tags.push(Tag::new_short(
                tag_name::SOURCETYPE,
                TagValue::U8(emule_buddy_source_type(file_size)),
            ));
            tags.push(Tag::new_short(
                tag_name::SERVERIP,
                TagValue::UInt(u64::from(u32::from_le_bytes(buddy_ip.octets()))),
            ));
            tags.push(Tag::new_short(
                tag_name::SERVERPORT,
                TagValue::UInt(u64::from(buddy_kad_port)),
            ));
            tags.push(Tag::new_short(
                tag_name::BUDDYHASH,
                TagValue::String(buddy_publish_hash_hex(own_kad_id)),
            ));
        }
    }
    tags.push(Tag::new_short(
        tag_name::SOURCEPORT,
        TagValue::UInt(u64::from(source_publish_settings.tcp_port)),
    ));
    // C2 disposition: advertise the intern Kad UDP port unconditionally
    // (stock's `!GetUseExternKadPort()` gate holds for us).
    tags.push(Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(kad_udp_port),
    ));
    tags.push(Tag::filesize(file_size));
    tags.push(Tag::new_short(
        tag_name::ENCRYPTION,
        TagValue::U8(connect_options),
    ));
    tags
}
