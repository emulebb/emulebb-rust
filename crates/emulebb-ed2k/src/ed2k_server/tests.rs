use super::{
    BackgroundServerSearchRequest, CT_EMULE_VERSION, CT_NAME, CT_SERVER_FLAGS, CT_VERSION,
    ConfiguredServerEntry, EDONKEY_VERSION, EMULE_ENCRYPTION_METHOD_OBFUSCATION,
    EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC,
    EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT, EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER, EMULE_VERSION_MAJOR,
    EMULE_VERSION_MINOR, EMULE_VERSION_UPDATE, Ed2kFoundSource, Ed2kHash, Ed2kSearchFile,
    Ed2kServerState, FT_FILENAME, FT_FILESIZE, FT_FILESIZE_HI, FT_FILETYPE, FT_SOURCES,
    HELLO_NICKNAME, OFFER_FILE_SAMPLE_HASH, OFFER_FILE_SAMPLE_NAME, OFFER_FILE_SAMPLE_SIZE,
    OP_EDONKEYPROT, OP_EMULEPROT, OP_GETSERVERLIST, OP_GETSOURCES, OP_GETSOURCES_OBFU,
    OP_GLOBFOUNDSOURCES, OP_GLOBGETSOURCES2, OP_GLOBSEARCHREQ, OP_GLOBSEARCHREQ2,
    OP_GLOBSEARCHREQ3, OP_GLOBSERVSTATRES, OP_IDCHANGE, OP_LOGINREQUEST, OP_OFFERFILES,
    OP_PACKEDPROT, PendingBackgroundServerSearch, ResolvedServerEntry,
    SERVER_OBFUSCATION_PRIME_BYTES, SERVER_OBFUSCATION_PUBLIC_KEY_LEN, SERVER_TCP_FLAG_COMPRESSION,
    SERVER_TCP_FLAG_LARGEFILES, SERVER_TCP_FLAG_TCPOBFUSCATION, SERVER_UDP_FLAG_EXT_GETFILES,
    SERVER_UDP_FLAG_EXT_GETSOURCES2, SERVER_UDP_FLAG_LARGEFILES, SERVER_UDP_FLAG_UDPOBFUSCATION,
    SOURCE_OBFUSCATION_USER_HASH_PRESENT, ST_DESCRIPTION, ST_SERVERNAME, ServerSession,
    ServerUdpPacket, TAG_SHORT_NAME_MASK, TAGTYPE_STR1, TAGTYPE_UINT32, TAGTYPE_UINT64,
    biguint_to_fixed_be, decode_callback_request, decode_found_sources, decode_id_change_payload,
    decode_search_result_page, decode_search_results, decode_server_ident, decode_server_payload,
    decode_server_udp_datagram, derive_server_cipher, derive_server_udp_cipher,
    ed2k_string_tag_type, encode_login_request, encode_offer_files_payload, encode_packet,
    encode_search_request, encode_server_udp_datagram, encode_source_request,
    encode_udp_search_request, format_server_flags, handle_background_udp_packet,
    ipv4_from_client_id, login_identity_for_server_transport, new_ed2k_server_search_channel,
    offer_files_catalog_fingerprint, search_keyword_via_background_session,
    search_source_via_background_session, server_capabilities, server_udp_endpoint,
    should_use_server_obfuscation, source_request_opcode, validate_found_sources,
};
use crate::{
    ed2k_tcp::{Ed2kHelloIdentity, emule_connect_options},
    ed2k_transfer::Ed2kSharedEntry,
};
use flate2::{Compression, write::ZlibEncoder};
use hex::decode;
use num_bigint::BigUint;
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::RwLock,
};
use tokio_util::sync::CancellationToken;

fn test_server(obfuscation_port_tcp: u16, udp_flags: u32) -> ResolvedServerEntry {
    ResolvedServerEntry {
        entry: ConfiguredServerEntry {
            host: "127.0.0.1".to_string(),
            port: 4661,
            name: Some("test".to_string()),
            description: None,
            udp_flags,
            udp_key: 0,
            udp_key_ip: 0,
            obfuscation_port_tcp,
            obfuscation_port_udp: 0,
        },
        ip: Ipv4Addr::LOCALHOST,
    }
}

fn test_udp_obfuscated_server() -> ResolvedServerEntry {
    ResolvedServerEntry {
        entry: ConfiguredServerEntry {
            host: "127.0.0.1".to_string(),
            port: 4661,
            name: Some("test".to_string()),
            description: None,
            udp_flags: SERVER_UDP_FLAG_UDPOBFUSCATION | SERVER_UDP_FLAG_EXT_GETSOURCES2,
            udp_key: 0x1122_3344,
            udp_key_ip: 0x5566_7788,
            obfuscation_port_tcp: 4661,
            obfuscation_port_udp: 4675,
        },
        ip: Ipv4Addr::LOCALHOST,
    }
}

#[test]
fn callback_request_only_trusts_crypt_profile_with_user_hash() {
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&u32::from_le_bytes([127, 0, 0, 1]).to_le_bytes());
    truncated.extend_from_slice(&4662u16.to_le_bytes());
    truncated.push(emule_connect_options(true));

    let callback = decode_callback_request(&truncated)
        .unwrap()
        .expect("callback");

    assert_eq!(callback.peer_addr, "127.0.0.1:4662".parse().unwrap());
    assert_eq!(callback.connect_options, None);
    assert_eq!(callback.user_hash, None);

    let mut full = truncated;
    full.extend_from_slice(&[0x11; 16]);
    let callback = decode_callback_request(&full).unwrap().expect("callback");

    assert_eq!(callback.connect_options, Some(emule_connect_options(true)));
    assert_eq!(callback.user_hash, Some([0x11; 16]));
}

#[test]
fn id_change_decoder_preserves_zero_client_id_as_unaccepted_login() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&SERVER_TCP_FLAG_TCPOBFUSCATION.to_le_bytes());
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(&u32::from_le_bytes([127, 0, 0, 1]).to_le_bytes());

    let id_change = decode_id_change_payload(&payload).unwrap();

    assert_eq!(id_change.client_id, 0);
    assert_eq!(id_change.server_flags, Some(SERVER_TCP_FLAG_TCPOBFUSCATION));
    assert_eq!(
        id_change.reported_client_ip,
        Some("127.0.0.1".parse().unwrap())
    );
}

mod background;
mod decoders;
mod protocol;
