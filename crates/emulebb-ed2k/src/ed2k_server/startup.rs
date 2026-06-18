use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    time::Instant,
};

use anyhow::Result;
use tracing::debug;

use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::Ed2kHelloIdentity,
    ed2k_transfer::{Ed2kSharedCatalog, Ed2kSharedEntry},
};

use super::tag_codec::{
    push_short_string_tag, push_short_u8_tag, push_short_u32_tag, push_string_tag, push_u32_tag,
};
use super::{
    CT_EMULE_VERSION, CT_NAME, CT_SERVER_FLAGS, CT_VERSION, ED2K_FILETYPE_ARCHIVE,
    ED2K_FILETYPE_AUDIO, ED2K_FILETYPE_DOCUMENT, ED2K_FILETYPE_PROGRAM, ED2K_FILETYPE_VIDEO,
    EDONKEY_VERSION, EMULE_VERSION_MAJOR, EMULE_VERSION_MINOR, EMULE_VERSION_UPDATE, FT_FILENAME,
    FT_FILESIZE, FT_FILESIZE_HI, FT_FILETYPE, HELLO_NICKNAME,
    OFFER_FILE_COMPLETE_SENTINEL_CLIENT_ID, OFFER_FILE_COMPLETE_SENTINEL_CLIENT_PORT,
    OFFER_FILE_SAMPLE_HASH, OFFER_FILE_SAMPLE_NAME, OFFER_FILE_SAMPLE_SIZE,
    OFFER_FILE_SEARCH_SETTLE_DELAY, OP_GETSERVERLIST, OP_GETSOURCES, OP_GETSOURCES_OBFU,
    OP_GLOBGETSOURCES, OP_GLOBGETSOURCES2, OP_OFFERFILES, ResolvedServerEntry,
    SERVER_TCP_FLAG_COMPRESSION, SERVER_TCP_FLAG_TCPOBFUSCATION, SERVER_UDP_FLAG_EXT_GETSOURCES,
    SERVER_UDP_FLAG_EXT_GETSOURCES2, SRVCAP_LARGEFILES, SRVCAP_NEWTAGS, SRVCAP_REQUESTCRYPT,
    SRVCAP_REQUIRECRYPT, SRVCAP_SUPPORTCRYPT, SRVCAP_UNICODE, SRVCAP_ZLIB, ServerSession,
    ServerSessionPhase, dump_ed2k_server_meta, is_low_id,
};

pub(super) fn encode_login_request(identity: Ed2kHelloIdentity) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(&identity.user_hash);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&identity.tcp_port.to_le_bytes());
    payload.extend_from_slice(&4u32.to_le_bytes());
    push_string_tag(&mut payload, CT_NAME, HELLO_NICKNAME);
    push_u32_tag(&mut payload, CT_VERSION, EDONKEY_VERSION);
    push_u32_tag(
        &mut payload,
        CT_SERVER_FLAGS,
        server_capabilities(identity.connect_options),
    );
    push_u32_tag(&mut payload, CT_EMULE_VERSION, emule_version_tag());
    payload
}

pub(super) fn login_identity_for_server_transport(
    identity: Ed2kHelloIdentity,
    use_server_obfuscation: bool,
) -> Ed2kHelloIdentity {
    let _ = use_server_obfuscation;
    identity
}

pub(super) fn encode_offer_files_payload(
    shared_catalog: &[Ed2kSharedEntry],
    client_id: Option<u32>,
    bind_ip: Ipv4Addr,
    tcp_port: u16,
    server_flags: Option<u32>,
) -> Vec<u8> {
    let (advertised_client_id, advertised_client_port) =
        advertised_client_endpoint_for_offer_file(client_id, bind_ip, tcp_port, server_flags);
    let offered_files = offered_files_catalog(shared_catalog);
    let mut payload = Vec::with_capacity(80 * offered_files.len());
    payload.extend_from_slice(
        &u32::try_from(offered_files.len())
            .expect("offered file count fits in u32")
            .to_le_bytes(),
    );
    for (file_hash, file_name, file_size, file_type) in offered_files {
        let lower_file_size = file_size as u32;
        let upper_file_size = u32::try_from(file_size >> 32).unwrap_or(u32::MAX);
        let tag_count = if upper_file_size == 0 { 3u32 } else { 4u32 };
        payload.extend_from_slice(&file_hash);
        payload.extend_from_slice(&advertised_client_id.to_le_bytes());
        payload.extend_from_slice(&advertised_client_port.to_le_bytes());
        payload.extend_from_slice(&tag_count.to_le_bytes());
        push_short_string_tag(&mut payload, FT_FILENAME, &file_name);
        push_short_u32_tag(&mut payload, FT_FILESIZE, lower_file_size);
        if upper_file_size != 0 {
            push_short_u32_tag(&mut payload, FT_FILESIZE_HI, upper_file_size);
        }
        push_short_u8_tag(&mut payload, FT_FILETYPE, file_type);
    }
    payload
}

fn advertised_client_endpoint_for_offer_file(
    client_id: Option<u32>,
    bind_ip: Ipv4Addr,
    tcp_port: u16,
    server_flags: Option<u32>,
) -> (u32, u16) {
    if server_flags.unwrap_or_default() & SERVER_TCP_FLAG_COMPRESSION != 0 {
        return (
            OFFER_FILE_COMPLETE_SENTINEL_CLIENT_ID,
            OFFER_FILE_COMPLETE_SENTINEL_CLIENT_PORT,
        );
    }
    let bind_client_id = u32::from_le_bytes(bind_ip.octets());
    match client_id {
        Some(client_id) if !is_low_id(client_id) => (bind_client_id, tcp_port),
        _ => (0, 0),
    }
}

/// Encode the ED2K local-server source request payload.
///
/// Modern eMule sends the file hash plus file size in the TCP local-server
/// source-request path. Large files use the `0` sentinel followed by a `u64`.
/// When the caller does not yet know the file size, fall back to the legacy
/// hash-only payload so hash-only live probes can still acquire sources.
pub(super) fn encode_source_request(file_hash: Ed2kHash, file_size: u64) -> Vec<u8> {
    if file_size == 0 {
        return file_hash.0.to_vec();
    }
    let mut payload = Vec::with_capacity(28);
    payload.extend_from_slice(&file_hash.0);
    if file_size > u64::from(u32::MAX) {
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&file_size.to_le_bytes());
    } else {
        payload.extend_from_slice(&(file_size as u32).to_le_bytes());
    }
    payload
}

pub(super) fn encode_udp_source_request(
    server: &ResolvedServerEntry,
    file_hash: Ed2kHash,
    file_size: u64,
) -> (u8, Vec<u8>) {
    if server.entry.udp_flags & SERVER_UDP_FLAG_EXT_GETSOURCES2 != 0 {
        (
            OP_GLOBGETSOURCES2,
            encode_source_request(file_hash, file_size),
        )
    } else {
        let _supports_legacy_getsources =
            server.entry.udp_flags & SERVER_UDP_FLAG_EXT_GETSOURCES != 0;
        (OP_GLOBGETSOURCES, file_hash.0.to_vec())
    }
}

pub(super) fn source_request_opcode(connect_options: u8, server_flags: Option<u32>) -> u8 {
    // A source-search session may still need the obfuscated reply family even
    // when the TCP session itself stayed plaintext because the configured
    // server entry lacked an obfuscation port. Once OP_IDCHANGE confirms the
    // server supports TCP obfuscation, prefer the obfuscated found-sources
    // shape so peer user-hash metadata is preserved.
    if connect_options != 0
        && server_flags.unwrap_or_default() & SERVER_TCP_FLAG_TCPOBFUSCATION != 0
    {
        OP_GETSOURCES_OBFU
    } else {
        OP_GETSOURCES
    }
}

fn offered_files_catalog(shared_catalog: &[Ed2kSharedEntry]) -> Vec<([u8; 16], String, u64, u8)> {
    let mut offered_files = shared_catalog
        .iter()
        .filter_map(popular_hash_offer_file)
        .take(200)
        .collect::<Vec<_>>();
    if offered_files.is_empty() {
        offered_files.push((
            OFFER_FILE_SAMPLE_HASH,
            OFFER_FILE_SAMPLE_NAME.to_string(),
            u64::from(OFFER_FILE_SAMPLE_SIZE),
            ED2K_FILETYPE_PROGRAM,
        ));
    }
    offered_files
}

pub(super) fn offer_files_catalog_fingerprint(shared_catalog: &[Ed2kSharedEntry]) -> u64 {
    let mut hasher = DefaultHasher::new();
    offered_files_catalog(shared_catalog).hash(&mut hasher);
    hasher.finish()
}

fn popular_hash_offer_file(hash: &Ed2kSharedEntry) -> Option<([u8; 16], String, u64, u8)> {
    let file_hash = hash.parsed_hash().ok()?;
    Some((
        file_hash.0,
        hash.canonical_name.clone(),
        hash.file_size,
        ed2k_offer_file_type(&hash.canonical_name),
    ))
}

fn ed2k_offer_file_type(file_name: &str) -> u8 {
    match file_name
        .rsplit('.')
        .next()
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("avi" | "mp4" | "mkv" | "mov" | "wmv" | "mpeg" | "mpg") => ED2K_FILETYPE_VIDEO,
        Some("mp3" | "flac" | "ogg" | "wav" | "aac" | "m4a") => ED2K_FILETYPE_AUDIO,
        Some("zip" | "rar" | "7z" | "tar" | "gz" | "bz2") => ED2K_FILETYPE_ARCHIVE,
        Some("pdf" | "doc" | "docx" | "txt" | "rtf" | "epub") => ED2K_FILETYPE_DOCUMENT,
        _ => ED2K_FILETYPE_PROGRAM,
    }
}

pub(super) fn server_capabilities(connect_options: u8) -> u32 {
    let mut flags = SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_LARGEFILES | SRVCAP_UNICODE;
    if connect_options & 0x01 != 0 {
        flags |= SRVCAP_SUPPORTCRYPT;
    }
    if connect_options & 0x02 != 0 {
        flags |= SRVCAP_REQUESTCRYPT;
    }
    if connect_options & 0x04 != 0 {
        flags |= SRVCAP_REQUIRECRYPT;
    }
    flags
}

fn emule_version_tag() -> u32 {
    (EMULE_VERSION_MAJOR << 17) | (EMULE_VERSION_MINOR << 10) | (EMULE_VERSION_UPDATE << 7)
}

pub(super) async fn send_offer_files_advertisement(
    session: &mut ServerSession,
    shared_catalog: &Ed2kSharedCatalog,
    bind_ip: Ipv4Addr,
    tcp_port: u16,
) -> Result<()> {
    let shared_catalog = shared_catalog.read().await.clone();
    let catalog_fingerprint = offer_files_catalog_fingerprint(&shared_catalog);
    if session.offer_files_sent
        && session.offer_files_catalog_fingerprint == Some(catalog_fingerprint)
    {
        return Ok(());
    }
    let payload = encode_offer_files_payload(
        &shared_catalog,
        session.assigned_client_id,
        bind_ip,
        tcp_port,
        session.server_flags,
    );
    let was_sent = session.offer_files_sent;
    session.send_packet(OP_OFFERFILES, &payload).await?;
    session.offer_files_sent = true;
    session.offer_files_sent_at = Some(Instant::now());
    session.offer_files_catalog_fingerprint = Some(catalog_fingerprint);
    session.set_phase(
        ServerSessionPhase::OfferFilesSent,
        format!(
            "{} offer-files advertisement entries={}",
            if was_sent { "refreshed" } else { "sent" },
            offered_files_catalog(&shared_catalog).len()
        ),
    );
    debug!(
        "{} ED2K offer-files advertisement to {}",
        if was_sent { "refreshed" } else { "sent" },
        session.endpoint
    );
    Ok(())
}

pub(super) async fn send_connected_server_startup(
    session: &mut ServerSession,
    shared_catalog: &Ed2kSharedCatalog,
    bind_ip: Ipv4Addr,
    tcp_port: u16,
) -> Result<()> {
    session.set_phase(
        ServerSessionPhase::Connected,
        "server session accepted after OP_IDCHANGE",
    );
    send_offer_files_advertisement(session, shared_catalog, bind_ip, tcp_port).await?;
    send_server_list_request(session).await?;
    Ok(())
}

async fn send_server_list_request(session: &mut ServerSession) -> Result<()> {
    if session.server_list_requested {
        return Ok(());
    }
    session.send_packet(OP_GETSERVERLIST, &[]).await?;
    session.server_list_requested = true;
    dump_ed2k_server_meta(session, "requested server list after connected transition");
    Ok(())
}

pub(super) async fn wait_for_offer_files_settle(session: &ServerSession) {
    let Some(sent_at) = session.offer_files_sent_at else {
        return;
    };
    let elapsed = sent_at.elapsed();
    if elapsed < OFFER_FILE_SEARCH_SETTLE_DELAY {
        tokio::time::sleep(OFFER_FILE_SEARCH_SETTLE_DELAY - elapsed).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::tag_codec::{DecodedTagValue, decode_tag_value};
    use crate::ed2k_transfer::Ed2kSharedEntry;

    use super::*;

    fn one_entry() -> Ed2kSharedEntry {
        Ed2kSharedEntry {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            canonical_name: "lan-bind-source.bin".to_string(),
            file_size: 1234,
            verified_complete: true,
            verified_ranges: Vec::new(),
            compatibility_hint: false,
            source_count_hint: None,
            aich_root: None,
            complete_parts: Vec::new(),
        }
    }

    #[test]
    fn offer_files_uses_bind_ip_for_dialable_same_host_lan_sources() {
        let bind_ip = Ipv4Addr::new(192, 168, 1, 210);
        let synthetic_duplicate_high_id = u32::from_le_bytes([1, 0, 0, 1]);
        let payload = encode_offer_files_payload(
            &[one_entry()],
            Some(synthetic_duplicate_high_id),
            bind_ip,
            4662,
            None,
        );

        assert_eq!(u32::from_le_bytes(payload[0..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(payload[20..24].try_into().unwrap()),
            u32::from_le_bytes(bind_ip.octets())
        );
        assert_eq!(
            u16::from_le_bytes(payload[24..26].try_into().unwrap()),
            4662
        );
    }

    #[test]
    fn offer_files_preserves_complete_sentinel_for_compression_servers() {
        let bind_ip = Ipv4Addr::new(192, 168, 1, 210);
        let payload = encode_offer_files_payload(
            &[one_entry()],
            Some(u32::from_le_bytes([192, 168, 1, 210])),
            bind_ip,
            4662,
            Some(SERVER_TCP_FLAG_COMPRESSION),
        );

        assert_eq!(
            u32::from_le_bytes(payload[20..24].try_into().unwrap()),
            OFFER_FILE_COMPLETE_SENTINEL_CLIENT_ID
        );
        assert_eq!(
            u16::from_le_bytes(payload[24..26].try_into().unwrap()),
            OFFER_FILE_COMPLETE_SENTINEL_CLIENT_PORT
        );
    }

    #[test]
    fn offer_files_preserves_unicode_filename_tag() {
        let mut entry = one_entry();
        entry.canonical_name = "unicode-\u{00e9}-\u{6f22}.bin".to_string();
        let payload = encode_offer_files_payload(
            &[entry],
            Some(u32::from_le_bytes([192, 168, 1, 210])),
            Ipv4Addr::new(192, 168, 1, 210),
            4662,
            None,
        );

        let tag_count_offset = 26;
        assert_eq!(
            u32::from_le_bytes(
                payload[tag_count_offset..tag_count_offset + 4]
                    .try_into()
                    .unwrap()
            ),
            3
        );
        let (tag_name, tag_value, _rest) =
            decode_tag_value(&payload[tag_count_offset + 4..]).unwrap();

        assert_eq!(tag_name, Some(FT_FILENAME));
        assert_eq!(
            tag_value,
            Some(DecodedTagValue::String(
                "unicode-\u{00e9}-\u{6f22}.bin".to_string()
            ))
        );
    }
}
