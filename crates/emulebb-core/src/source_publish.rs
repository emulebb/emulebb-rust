//! Kad source-publish tag builders.
//!
//! Pure helpers that build the KADEMLIA2_PUBLISH source tag set (`SOURCETYPE`,
//! `SOURCEPORT`, `SOURCEIP`, `SOURCEUPORT`, filesize, `ENCRYPTION`) and the
//! supporting eMule conventions: the large-file source type, the byte-swapped
//! Kad chunk order used to derive the publisher client hash, and the source
//! encryption-options byte. Moved verbatim out of `lib.rs` during the
//! maintainability restructuring; they carry no behavior beyond what they had
//! inline. Re-exported `pub(crate)` from the crate root so the publish loop and
//! the test module reach them by their bare names.

use std::net::SocketAddr;

use emulebb_ed2k::ed2k_tcp::emule_connect_options;
use emulebb_kad_proto::{NodeId, Tag, TagValue, tag_name};

use crate::EMULE_LARGE_FILE_SIZE_THRESHOLD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourcePublishSettings {
    pub(crate) tcp_port: u16,
    pub(crate) obfuscation_enabled: bool,
}

pub(crate) fn emule_high_id_source_type(file_size: u64) -> u32 {
    if file_size > EMULE_LARGE_FILE_SIZE_THRESHOLD {
        4
    } else {
        1
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

pub(crate) fn build_source_publish_tags(
    bind_addr: SocketAddr,
    source_publish_settings: SourcePublishSettings,
    file_size: u64,
) -> Vec<Tag> {
    let mut tags = vec![
        Tag::new_short(
            tag_name::SOURCETYPE,
            TagValue::UInt(u64::from(emule_high_id_source_type(file_size))),
        ),
        Tag::new_short(
            tag_name::SOURCEPORT,
            TagValue::UInt(u64::from(source_publish_settings.tcp_port)),
        ),
    ];
    if let SocketAddr::V4(addr) = bind_addr {
        tags.push(Tag::new_short(
            tag_name::SOURCEIP,
            TagValue::U32(u32::from_be_bytes(addr.ip().octets())),
        ));
    }
    tags.push(Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(bind_addr.port()),
    ));
    tags.push(Tag::filesize(file_size));
    tags.push(Tag::new_short(
        tag_name::ENCRYPTION,
        TagValue::U8(emule_source_encryption_options(
            source_publish_settings.obfuscation_enabled,
        )),
    ));
    tags
}
