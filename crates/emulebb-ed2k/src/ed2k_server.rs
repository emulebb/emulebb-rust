//! Minimal eD2k server session support used to obtain oracle-style HighID/LowID
//! feedback and keep the Rust client visible on the ED2K side of the network.
//!
//! This intentionally does not implement the full server feature set yet. The
//! current scope mirrors the parts of the oracle's `ServerConnect` and
//! `ServerSocket` flow that matter for parity today:
//! - connect from the VPN-bound interface to one configured ED2K server
//! - send an oracle-shaped `OP_LOGINREQUEST`
//! - advertise a minimal oracle-shaped shared-file catalog during the connected
//!   transition so the server sees a credible `OP_OFFERFILES`
//! - process `OP_IDCHANGE`, `OP_SERVERSTATUS`, and a few informational replies
//! - execute keyword searches with oracle-style query trees and `More` paging
//! - execute server source searches through the same long-lived TCP session
//! - keep the TCP session alive with empty `OP_OFFERFILES` packets

use std::time::Duration;

#[cfg(test)]
use emulebb_kad_proto::Ed2kHash;

mod active_callback;
mod active_keyword;
mod active_source;
mod background;
mod diagnostics;
mod flags;
mod loop_runtime;
mod obfuscation;
mod packet_codec;
mod packet_handler;
mod result_decoder;
mod search_expr;
mod server_entry;
mod server_events;
mod server_met;
mod server_status;
mod session;
mod session_driver;
mod source_utils;
mod startup;
mod tag_codec;
mod types;
mod udp;
mod udp_runtime;
pub use active_callback::{Ed2kCallbackRequestOptions, request_callback_on_server};
pub use active_keyword::{Ed2kKeywordSearchOptions, search_keyword_servers};
pub use active_source::{
    Ed2kSourceSearchOptions, Ed2kUdpSourceSearchOptions, search_source_servers,
    search_source_udp_servers,
};
use background::{
    BackgroundServerSearchContext, BackgroundServerSearchRequest, PendingBackgroundServerSearch,
    fail_background_search_request, fail_pending_background_search, handle_background_udp_packet,
    log_search_result_page, start_background_server_search,
};
pub use background::{
    Ed2kServerSearchHandle, Ed2kServerSearchInbox, new_ed2k_server_search_channel,
    publish_shared_catalog_via_background_session, request_callback_via_background_session,
    search_keyword_via_background_session, search_source_via_background_session,
};
use diagnostics::{dump_ed2k_server_meta, dump_ed2k_server_packet};
use flags::{format_connect_options, format_server_flags, is_low_id};
pub use loop_runtime::run_ed2k_server_loop;
use server_events::decode_server_list;
pub use server_events::{
    Ed2kServerListEvent, Ed2kServerListEventReceiver, Ed2kServerListEventSender,
    MAX_SERVERS_FROM_ONE_LIST, ed2k_server_list_event_channel,
};
pub use server_met::{ParsedServerMetEntry, parse_server_met};
use obfuscation::{
    Rc4KeyStream, biguint_to_fixed_be, derive_server_cipher, random_non_protocol_marker,
    random_nonzero_biguint, should_use_server_obfuscation,
};
use packet_codec::{decode_server_payload, encode_packet};
use packet_handler::handle_server_packet;
#[cfg(test)]
use packet_handler::{decode_callback_request, decode_id_change_payload, decode_server_ident};
#[cfg(test)]
use result_decoder::decode_search_results;
use result_decoder::{
    decode_found_sources, decode_search_result_page, decode_udp_found_source_sets,
    decode_udp_search_result_pages,
};
use search_expr::encode_search_request;
#[cfg(test)]
use server_entry::ConfiguredServerEntry;
use server_entry::{
    ResolvedServerEntry, configured_server_entries, resolve_callback_server_entry,
    resolve_server_entry,
};
use session::{Ed2kPacket, ServerSession, ServerSessionPhase};
use session_driver::{clear_server_connection_state, run_one_server_session};
use source_utils::{
    annotate_found_sources_server, ipv4_from_client_id, merge_found_sources, validate_found_sources,
};
use startup::{
    encode_login_request, encode_source_request, encode_udp_search_request,
    encode_udp_source_request, login_identity_for_server_transport, send_connected_server_startup,
    send_offer_files_advertisement, source_request_opcode, wait_for_offer_files_settle,
};
#[cfg(test)]
use startup::{encode_offer_files_payload, offer_files_catalog_fingerprint, server_capabilities};
#[cfg(test)]
use tag_codec::ed2k_string_tag_type;
use tag_codec::{decode_ed2k_string, decode_tag};
use types::ServerUdpPacket;
pub use types::{Ed2kFoundSource, Ed2kSearchFile, Ed2kServerLoopOptions, Ed2kServerState};
#[cfg(test)]
use udp::derive_server_udp_cipher;
use udp::{decode_server_udp_datagram, encode_server_udp_datagram, server_udp_endpoint};
use udp_runtime::{read_server_udp_packet, send_udp_keyword_search, send_udp_source_search};

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_LOGINREQUEST: u8 = 0x01;
const OP_REJECT: u8 = 0x05;
const OP_GETSERVERLIST: u8 = 0x14;
const OP_OFFERFILES: u8 = 0x15;
const OP_SEARCHREQUEST: u8 = 0x16;
const OP_GETSOURCES: u8 = 0x19;
const OP_CALLBACKREQUEST: u8 = 0x1C;
const OP_GETSOURCES_OBFU: u8 = 0x23;
const OP_QUERY_MORE_RESULT: u8 = 0x21;
const OP_GLOBSEARCHREQ3: u8 = 0x90;
const OP_GLOBSEARCHREQ2: u8 = 0x92;
const OP_GLOBGETSOURCES2: u8 = 0x94;
const OP_GLOBSERVSTATREQ: u8 = 0x96;
const OP_GLOBSERVSTATRES: u8 = 0x97;
const OP_GLOBSEARCHREQ: u8 = 0x98;
const OP_GLOBSEARCHRES: u8 = 0x99;
const OP_GLOBGETSOURCES: u8 = 0x9A;
const OP_GLOBFOUNDSOURCES: u8 = 0x9B;
const OP_SERVERLIST: u8 = 0x32;
const OP_SEARCHRESULT: u8 = 0x33;
const OP_SERVERSTATUS: u8 = 0x34;
const OP_CALLBACKREQUESTED: u8 = 0x35;
const OP_CALLBACK_FAIL: u8 = 0x36;
const OP_SERVERMESSAGE: u8 = 0x38;
const OP_IDCHANGE: u8 = 0x40;
const OP_SERVERIDENT: u8 = 0x41;
const OP_FOUNDSOURCES: u8 = 0x42;
const OP_FOUNDSOURCES_OBFU: u8 = 0x44;
const OP_PACKEDPROT: u8 = 0xD4;
const TCP_PACKET_HEADER_LEN: usize = 6;
const MAX_SERVER_DECOMPRESSED_PACKET_LEN: usize = 250_000;

const EDONKEY_VERSION: u32 = 0x3C;
const EMULE_VERSION_MAJOR: u32 = 0;
const EMULE_VERSION_MINOR: u32 = 72;
const EMULE_VERSION_UPDATE: u32 = 0;
// Stock eMule reads the nick from preferences. Until the Rust client grows an
// operator-configurable nick surface, keep a neutral stock-like default
// instead of the earlier project URL identity.
const HELLO_NICKNAME: &str = "eMule";

const TAGTYPE_HASH: u8 = 0x01;
const TAGTYPE_STRING: u8 = 0x02;
const TAGTYPE_UINT32: u8 = 0x03;
const TAGTYPE_FLOAT32: u8 = 0x04;
const TAGTYPE_BOOL: u8 = 0x05;
const TAGTYPE_BOOLARRAY: u8 = 0x06;
const TAGTYPE_BLOB: u8 = 0x07;
const TAGTYPE_UINT16: u8 = 0x08;
const TAGTYPE_UINT8: u8 = 0x09;
const TAGTYPE_UINT64: u8 = 0x0B;
const TAGTYPE_STR1: u8 = 0x11;
const TAG_SHORT_NAME_MASK: u8 = 0x80;

const CT_NAME: u8 = 0x01;
const CT_SERVER_UDPSEARCH_FLAGS: u8 = 0x0E;
const CT_VERSION: u8 = 0x11;
const CT_SERVER_FLAGS: u8 = 0x20;
const CT_EMULE_VERSION: u8 = 0xFB;

const SRVCAP_ZLIB: u32 = 0x0001;
const SRVCAP_NEWTAGS: u32 = 0x0008;
const SRVCAP_UNICODE: u32 = 0x0010;
const SRVCAP_LARGEFILES: u32 = 0x0100;
const SRVCAP_SUPPORTCRYPT: u32 = 0x0200;
const SRVCAP_REQUESTCRYPT: u32 = 0x0400;
const SRVCAP_REQUIRECRYPT: u32 = 0x0800;
const SOURCE_OBFUSCATION_USER_HASH_PRESENT: u8 = 0x80;
const SRVCAP_UDP_NEWTAGS_LARGEFILES: u32 = 0x0001;

const SERVER_TCP_FLAG_COMPRESSION: u32 = 0x0000_0001;
const SERVER_TCP_FLAG_NEWTAGS: u32 = 0x0000_0008;
const SERVER_TCP_FLAG_UNICODE: u32 = 0x0000_0010;
const SERVER_TCP_FLAG_RELATEDSEARCH: u32 = 0x0000_0040;
const SERVER_TCP_FLAG_TYPETAGINTEGER: u32 = 0x0000_0080;
const SERVER_TCP_FLAG_LARGEFILES: u32 = 0x0000_0100;
const SERVER_TCP_FLAG_TCPOBFUSCATION: u32 = 0x0000_0400;
const SERVER_UDP_FLAG_EXT_GETSOURCES: u32 = 0x0000_0001;
const SERVER_UDP_FLAG_EXT_GETFILES: u32 = 0x0000_0002;
const SERVER_UDP_FLAG_EXT_GETSOURCES2: u32 = 0x0000_0020;
const SERVER_UDP_FLAG_LARGEFILES: u32 = 0x0000_0100;
const SERVER_UDP_FLAG_UDPOBFUSCATION: u32 = 0x0000_0200;
const SERVER_UDP_FLAG_TCPOBFUSCATION: u32 = 0x0000_0400;

const ST_SERVERNAME: u8 = 0x01;
const ST_DESCRIPTION: u8 = 0x0B;
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILETYPE: u8 = 0x03;
const FT_SOURCES: u8 = 0x15;
const FT_FILESIZE_HI: u8 = 0x3A;
const ED2K_FILETYPE_PROGRAM: u8 = 0x04;
const ED2K_FILETYPE_DOCUMENT: u8 = 0x05;
const ED2K_FILETYPE_ARCHIVE: u8 = 0x06;
const ED2K_FILETYPE_AUDIO: u8 = 0x07;
const ED2K_FILETYPE_VIDEO: u8 = 0x08;

const OFFER_FILE_COMPLETE_SENTINEL_CLIENT_ID: u32 = 0xFBFB_FBFB;
const OFFER_FILE_COMPLETE_SENTINEL_CLIENT_PORT: u16 = 0xFBFB;
const OFFER_FILE_SAMPLE_HASH: [u8; 16] = [
    0x9F, 0x3C, 0x23, 0xDB, 0x76, 0x51, 0xEF, 0xBA, 0xC9, 0xA8, 0x37, 0xA8, 0xA0, 0xAE, 0x3E, 0xD9,
];
const OFFER_FILE_SAMPLE_NAME: &str = "ubuntu-linux-oracle-sample.iso";
const OFFER_FILE_SAMPLE_SIZE: u32 = 0x0020_0000;
const OFFER_FILE_SEARCH_SETTLE_DELAY: Duration = Duration::from_millis(80);
const EMULE_TCP_CRYPT_MAGIC_REQUESTER: u8 = 34;
const EMULE_TCP_CRYPT_MAGIC_SERVER: u8 = 203;
const EMULE_TCP_CRYPT_MAGIC_SYNC: u32 = 0x835E_6FC4;
const EMULE_TCP_CRYPT_DISCARD_LEN: usize = 1024;
const EMULE_ENCRYPTION_METHOD_OBFUSCATION: u8 = 0x00;
const EMULE_UDP_CRYPT_HEADER_LEN: usize = 8;
const EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER: u32 = 0x13EF_24D5;
const EMULE_UDP_CRYPT_MAGIC_CLIENT_SERVER: u8 = 0x6B;
const EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT: u8 = 0xA5;
const SERVER_OBFUSCATION_PUBLIC_KEY_LEN: usize = 96;
const SERVER_OBFUSCATION_RANDOM_EXPONENT_LEN: usize = 16;
const SERVER_OBFUSCATION_MAX_PADDING_LEN: usize = 15;
const SERVER_OBFUSCATION_PRIME_BYTES: [u8; SERVER_OBFUSCATION_PUBLIC_KEY_LEN] = [
    0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36, 0xE8, 0x86, 0xEB, 0x3C,
    0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D, 0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7,
    0x21, 0xFC, 0x28, 0x63, 0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
    0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4, 0x5A, 0xD5, 0xE0, 0x74,
    0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34, 0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91,
    0x42, 0xFB, 0x42, 0x68, 0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
];

#[cfg(test)]
mod tests;
