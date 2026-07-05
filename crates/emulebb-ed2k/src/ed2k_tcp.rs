//! Minimal eD2k TCP support required for Kad firewall verification and TCP hello parity.
//!
//! The full eD2k peer protocol is still out of scope for the current Rust client, but
//! the Kad oracle exposes a real eD2k TCP surface during startup instead of a
//! one-packet firewall helper stub. To stay wire-compatible with that bootstrap
//! path, this module now implements a small stateful subset:
//! - outbound `OP_HELLO` followed by `OP_FWCHECKUDPREQ` for UDP firewall checks
//! - inbound basic eMule TCP obfuscation handshake
//! - inbound `OP_HELLO` / `OP_HELLOANSWER` framing
//! - inbound `OP_EMULEINFO` / `OP_EMULEINFOANSWER` framing
//! - inbound `OP_FWCHECKUDPREQ`
//!
//! The listener intentionally does not claim full eD2k file-transfer support,
//! but it now serves the verified upload subset that peers expect once they
//! choose us as a source:
//! - filename, file-status, and hashset answers for known files
//! - upload-intent acknowledgement
//! - range serving with eMule-style part fragmentation and optional compression

use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::{Mutex, RwLock};

use crate::ed2k_server::Ed2kServerState;
#[cfg(test)]
use crate::ed2k_transfer::ED2K_EMBLOCK_SIZE;
use crate::ed2k_transfer::{
    Ed2kAichHashset, Ed2kResumeManifest, Ed2kSharedEntry, decode_aich_hash_hex,
};
use crate::kad_firewall::KadFirewallState;
use emulebb_kad_proto::Ed2kHash;

mod aich_salvage;
mod buddy_link;
mod codec;
mod diag_event;
mod download;
mod dump;
mod firewall_helper;
mod hello;
mod hello_buddy;
mod hello_gpl;
mod hello_miscoptions;
mod identity;
mod listener;
mod obfuscation;
mod transport;
pub(in crate::ed2k_tcp) use codec::{
    PeerSourceExchangeRequest, SourceExchangePeer, decode_aich_file_hash_answer,
    decode_aich_recovery_answer_payload, decode_aich_recovery_request_payload,
    decode_answer_sources_payload, decode_answer_sources2_payload,
    decode_chat_captcha_request_payload, decode_chat_captcha_result_payload,
    decode_client_id_change_payload, decode_client_message_payload,
    decode_compressed_part_fragment, decode_edonkey_queue_rank_payload,
    decode_emule_queue_ranking_payload, decode_exact_file_hash_payload,
    decode_file_description_payload, decode_file_status_availability,
    decode_file_status_body_availability, decode_hashset_answer, decode_hashset_answer2,
    decode_kad_callback_payload, decode_optional_file_hash_payload, decode_peer_payload,
    decode_preview_answer_payload, decode_preview_request_payload, decode_public_ip_answer_payload,
    decode_reask_callback_tcp_payload, decode_request_filename_answer,
    decode_request_filename_answer_body, decode_sending_part_payload,
    decode_shared_dirs_answer_payload, decode_shared_files_answer_payload,
    decode_shared_files_dir_answer_payload, decode_shared_files_dir_request_payload,
    encode_aich_file_hash_request, encode_aich_recovery_answer,
    encode_aich_recovery_failure_answer, encode_aich_recovery_request,
    encode_empty_shared_files_answer, encode_hashset_request, encode_hashset_request2,
    encode_multipacket_ext2_request, encode_multipacket_request, encode_packet,
    encode_port_test_answer, encode_public_ip_answer, encode_request_filename,
    encode_request_parts_batch, encode_request_sources2, encode_set_req_file_id,
    encode_shared_browse_denied_answer, encode_start_upload_req, inflate_compressed_part_fragment,
    validate_file_status_part_count,
};
// Re-exported only for codec unit tests; the production decode path uses the
// availability-returning variants above.
pub(in crate::ed2k_tcp) use aich_salvage::handle_aich_recovery_answer;
pub use buddy_link::{OutboundBuddyLinkOptions, run_outbound_buddy_link};
#[cfg(test)]
pub(in crate::ed2k_tcp) use codec::decode_file_status_payload;
#[cfg(test)]
#[allow(unused_imports)]
use codec::{
    build_upload_part_packets, decode_file_hash_payload, decode_hashset_request2,
    decode_request_parts_payload, decode_request_sources_payload, encode_accept_upload_req,
    encode_aich_file_hash_answer, encode_answer_sources, encode_answer_sources2,
    encode_compressed_part_fragment, encode_file_req_ans_nofil, encode_file_status,
    encode_hashset_answer, encode_hashset_answer2, encode_multipacket_answer,
    encode_multipacket_ext2_answer, encode_packed_packet, encode_queue_ranking,
    encode_request_filename_answer, encode_request_sources, encode_request_sources2_subpayload,
    encode_sending_part, skip_request_filename_ext_info,
};
pub(in crate::ed2k_tcp) use download::PendingCompressedPart;
#[cfg(test)]
pub(in crate::ed2k_tcp) use download::{DownloadSessionOptions, drive_download_session};
#[cfg(test)]
use download::{DownloadWindowLimits, next_download_read_timeout, select_download_window_limits};
pub use download::{Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome, download_file_from_peer};
pub(crate) use dump::dump_ed2k_tcp_download_meta;
pub(in crate::ed2k_tcp) use dump::{dump_ed2k_tcp_download_recv, dump_ed2k_tcp_download_send};
pub use firewall_helper::connect_callback_peer;
pub use firewall_helper::emule_connect_options;
pub(crate) use firewall_helper::is_connection_shutdown_error;
pub use firewall_helper::request_udp_firewall_check;
pub use firewall_helper::send_kad_firewall_tcp_ack;
pub use hello::set_publish_rust_identity;
pub(in crate::ed2k_tcp) use hello::{
    DecodedEmuleInfoProfile, build_hello_responses, decode_emule_info_profile,
    decode_hello_answer_profile, decode_hello_profile, encode_emule_info_answer,
    encode_hello_request,
};
#[cfg(test)]
#[allow(unused_imports)]
use hello::{DecodedHelloIdentity, encode_hello_answer, is_mule_hello};
#[cfg(test)]
use hello::{
    emule_misc_options1, emule_misc_options2, emule_version_tag, encode_emule_info_request,
};
pub use hello_buddy::{HelloBuddySnapshot, set_hello_buddy_snapshot};
pub use identity::Ed2kSecureIdent;
pub(in crate::ed2k_tcp) use identity::{
    Ed2kPeerSecureIdentState, begin_secure_ident_probe, decode_public_key_payload,
    decode_secident_state, decode_signature_payload, encode_secident_state, random_nonzero_u32,
    try_send_secure_ident_signature, verify_peer_secure_ident_signature,
};
pub(crate) use listener::reply_with_firewall_udp;
#[cfg(test)]
use listener::{Ed2kConnectionContext, handle_connection};
pub use listener::{Ed2kListenerOptions, run_ed2k_listener};
use obfuscation::{
    Rc4KeyStream, accept_incoming_obfuscation_handshake, is_plain_ed2k_protocol_marker,
    negotiate_outgoing_obfuscation_handshake, should_enable_outgoing_obfuscation,
};
#[cfg(test)]
use obfuscation::{
    decode_incoming_obfuscation_header, derive_obfuscation_key,
    encode_incoming_obfuscation_response,
};
pub use transport::EmuleTcpPacket;
pub(in crate::ed2k_tcp) use transport::{Ed2kTransport, Ed2kTransportMode};

const OP_EMULEPROT: u8 = 0xC5;
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_PACKEDPROT: u8 = 0xD4;
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const OP_COMPRESSEDPART: u8 = 0x40;
const OP_SENDINGPART: u8 = 0x46;
const OP_REQUESTPARTS: u8 = 0x47;
const OP_FILEREQANSNOFIL: u8 = 0x48;
const OP_END_OF_DOWNLOAD: u8 = 0x49;
const OP_ASKSHAREDFILES: u8 = 0x4A;
const OP_ASKSHAREDFILESANSWER: u8 = 0x4B;
const OP_CHANGE_CLIENT_ID: u8 = 0x4D;
const OP_MESSAGE: u8 = 0x4E;
const OP_SETREQFILEID: u8 = 0x4F;
const OP_FILESTATUS: u8 = 0x50;
const OP_HASHSETREQUEST: u8 = 0x51;
const OP_HASHSETANSWER: u8 = 0x52;
const OP_STARTUPLOADREQ: u8 = 0x54;
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
const OP_CANCELTRANSFER: u8 = 0x56;
const OP_OUTOFPARTREQS: u8 = 0x57;
const OP_REQUESTFILENAME: u8 = 0x58;
const OP_REQFILENAMEANSWER: u8 = 0x59;
const OP_CHANGE_SLOT: u8 = 0x5B;
const OP_QUEUERANK: u8 = 0x5C;
const OP_ASKSHAREDDIRS: u8 = 0x5D;
const OP_ASKSHAREDFILESDIR: u8 = 0x5E;
const OP_ASKSHAREDDIRSANS: u8 = 0x5F;
const OP_ASKSHAREDFILESDIRANS: u8 = 0x60;
const OP_ASKSHAREDDENIEDANS: u8 = 0x61;
const OP_QUEUERANKING: u8 = 0x60;
const OP_FILEDESC: u8 = 0x61;
const OP_REQUESTSOURCES: u8 = 0x81;
const OP_ANSWERSOURCES: u8 = 0x82;
const OP_REQUESTSOURCES2: u8 = 0x83;
const OP_ANSWERSOURCES2: u8 = 0x84;
const OP_REQUESTPREVIEW: u8 = 0x90;
const OP_PREVIEWANSWER: u8 = 0x91;
const OP_MULTIPACKET: u8 = 0x92;
const OP_MULTIPACKETANSWER: u8 = 0x93;
const OP_PUBLICIP_REQ: u8 = 0x97;
const OP_PUBLICIP_ANSWER: u8 = 0x98;
const OP_CALLBACK: u8 = 0x99;
const OP_REASKCALLBACKTCP: u8 = 0x9A;
const OP_AICHREQUEST: u8 = 0x9B;
const OP_AICHANSWER: u8 = 0x9C;
const OP_AICHFILEHASHANS: u8 = 0x9D;
const OP_AICHFILEHASHREQ: u8 = 0x9E;
const OP_BUDDYPING: u8 = 0x9F;
const OP_BUDDYPONG: u8 = 0xA0;
const OP_COMPRESSEDPART_I64: u8 = 0xA1;
const OP_SENDINGPART_I64: u8 = 0xA2;
const OP_REQUESTPARTS_I64: u8 = 0xA3;
const OP_MULTIPACKET_EXT: u8 = 0xA4;
const OP_CHATCAPTCHAREQ: u8 = 0xA5;
const OP_CHATCAPTCHARES: u8 = 0xA6;
const OP_KAD_FWTCPCHECK_ACK: u8 = 0xA8;
const OP_MULTIPACKET_EXT2: u8 = 0xA9;
const OP_MULTIPACKETANSWER_EXT2: u8 = 0xB0;
const OP_HASHSETREQUEST2: u8 = 0xB1;
const OP_HASHSETANSWER2: u8 = 0xB2;
const OP_PORTTEST: u8 = 0xFE;
const OP_EMULEINFO: u8 = 0x01;
const OP_EMULEINFOANSWER: u8 = 0x02;
const OP_PUBLICKEY: u8 = 0x85;
const OP_SIGNATURE: u8 = 0x86;
const OP_SECIDENTSTATE: u8 = 0x87;
const OP_FWCHECKUDPREQ: u8 = 0xA7;
const TCP_PACKET_HEADER_LEN: usize = 6;
/// Hard cap on the raw (on-wire) eD2k packet length, mirroring the master
/// client's `sizeof GlobalReadBuffer` (`EMSocket.cpp`: `static char
/// GlobalReadBuffer[2000000];`). A peer declaring a larger length is dropped
/// with `ERR_TOOBIG` before any payload buffer is allocated, preventing an
/// out-of-memory denial of service from a hostile `packet_length`.
pub(crate) const MAX_ED2K_PACKET_LEN: usize = 2_000_000;
const MAX_PEER_DECOMPRESSED_PACKET_LEN: usize = 50_000;
const ED2K_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const ED2K_UPLOAD_QUEUE_POLL_INTERVAL: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(test)]
const ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL: Duration = Duration::from_millis(200);
const FIREWALL_HELPER_POST_REQUEST_KEEPALIVE_SECS: u64 = 10;
const ED2K_UPLOAD_PACKET_SPLIT_THRESHOLD: usize = 13_000;
const ED2K_UPLOAD_PACKET_FRAGMENT_LEN: usize = 10_240;

const EMULE_PROTOCOL_VERSION: u8 = 0x01;
const EDONKEY_VERSION: u32 = 0x3C;
const EMULE_VERSION_MAJOR: u32 = 0;
const EMULE_VERSION_MINOR: u32 = 72;
const EMULE_VERSION_UPDATE: u32 = 0;
// eMule `m_uCurVersionShort` (OP_EMULEINFO leading byte): the product minor
// version formatted as decimal digits then re-parsed as hex — `Format("0x%lu")`
// then `scanf("0x%x")` (Emule.cpp) — i.e. a BCD-style byte. For 0.72 this is
// 0x72, NOT 0x48 (=72). Peers read it as `m_byEmuleVersion` in
// ProcessMuleInfoPacket; 0x48 would misidentify us as an ancient "0.48" client.
const EMULE_VERSION_SHORT: u8 =
    (((EMULE_VERSION_MINOR / 10) << 4) | (EMULE_VERSION_MINOR % 10)) as u8;
const EMULE_SECURE_IDENT_VERSION: u32 = 3;
const EMULE_INFO_FEATURES: u32 = 3;
const EMULE_ADVERTISED_KAD_VERSION: u32 = 10;
const ED2K_SOURCE_EXCHANGE2_VERSION: u8 = 4;

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
const CT_VERSION: u8 = 0x11;
/// eMule hello mod-version string tag (eMule `CT_MOD_VERSION`). Mods/forks set it
/// to their name; we use it to advertise as "eMule Community" (or, when the
/// operator opts in, the real "emule-rust" identity).
const CT_MOD_VERSION: u8 = 0x55;
const CT_EMULE_UDPPORTS: u8 = 0xF9;
const CT_EMULE_MISCOPTIONS1: u8 = 0xFA;
const CT_EMULE_VERSION: u8 = 0xFB;
/// Buddy IP advertised by a firewalled client that holds a buddy (`opcodes.h`).
const CT_EMULE_BUDDYIP: u8 = 0xFC;
/// Buddy UDP port (low 16 bits) advertised alongside `CT_EMULE_BUDDYIP`.
const CT_EMULE_BUDDYUDP: u8 = 0xFD;
const CT_EMULE_MISCOPTIONS2: u8 = 0xFE;

const ET_COMPRESSION: u8 = 0x20;
const ET_UDPPORT: u8 = 0x21;
const ET_UDPVER: u8 = 0x22;
const ET_SOURCEEXCHANGE: u8 = 0x23;
const ET_COMMENTS: u8 = 0x24;
const ET_EXTENDEDREQUEST: u8 = 0x25;
const ET_FEATURES: u8 = 0x27;

const EMULE_CRYPT_SUPPORTS: u8 = 0x01;
const EMULE_CRYPT_REQUESTS: u8 = 0x02;
const EMULE_CRYPT_REQUIRES: u8 = 0x04;
const EMULE_ENCRYPTION_METHOD_OBFUSCATION: u8 = 0x00;
const EMULE_TCP_CRYPT_MAGIC_REQUESTER: u8 = 34;
const EMULE_TCP_CRYPT_MAGIC_SERVER: u8 = 203;
const EMULE_TCP_CRYPT_MAGIC_SYNC: u32 = 0x835E_6FC4;
const EMULE_TCP_CRYPT_DISCARD_LEN: usize = 1024;
const ED2K_SECURE_IDENT_KEY_BITS: usize = 384;
const ED2K_SECURE_IDENT_SIGNATURE_NEEDED: u8 = 1;
const ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED: u8 = 2;

// Stock eMule reads the nick from preferences. Until the Rust client grows an
// operator-configurable nick surface, keep a neutral stock-like default
// instead of the earlier project URL identity.
const HELLO_NICKNAME: &str = "eMule";

/// Payload of `OP_FWCHECKUDPREQ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallCheckUdpRequest {
    /// UDP port the requester is listening on locally.
    pub internal_udp_port: u16,
    /// UDP port observed/mapped externally for the requester.
    pub external_udp_port: u16,
    /// Per-helper Kad UDP verify key used to obfuscate the helper's reply.
    pub sender_udp_key: u32,
}

impl FirewallCheckUdpRequest {
    fn encode(self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..2].copy_from_slice(&self.internal_udp_port.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.external_udp_port.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.sender_udp_key.to_le_bytes());
        bytes
    }

    fn decode(payload: &[u8]) -> Result<Self> {
        if payload.len() < 8 {
            anyhow::bail!("short OP_FWCHECKUDPREQ payload {}", payload.len());
        }
        Ok(Self {
            internal_udp_port: u16::from_le_bytes([payload[0], payload[1]]),
            external_udp_port: u16::from_le_bytes([payload[2], payload[3]]),
            sender_udp_key: u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]),
        })
    }
}

/// Minimal identity announced during the helper TCP hello handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kHelloIdentity {
    /// Stable 16-byte user hash / client hash.
    pub user_hash: [u8; 16],
    /// Server-assigned HighID or LowID when known.
    pub client_id: u32,
    /// TCP port advertised in the hello packet.
    pub tcp_port: u16,
    /// UDP port advertised in the hello packet.
    pub udp_port: u16,
    /// Current ED2K server IPv4 address in the oracle hello trailer format.
    pub server_ip: u32,
    /// Current ED2K server TCP port in the oracle hello trailer format.
    pub server_port: u16,
    /// Local eD2k connect-option bits mirrored from the oracle hello path.
    pub connect_options: u8,
    /// Whether the node currently advertises direct UDP callback support.
    pub direct_udp_callback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed2kFileIdentifier {
    file_hash: Ed2kHash,
    file_size: Option<u64>,
    aich_root: Option<[u8; 20]>,
}

impl Ed2kFileIdentifier {
    const INCLUDE_MD4: u8 = 1 << 0;
    const INCLUDE_SIZE: u8 = 1 << 1;
    const INCLUDE_AICH: u8 = 1 << 2;
    const RESERVED_BITS: u8 = 0xF8;

    fn from_manifest(manifest: &Ed2kResumeManifest) -> Result<Self> {
        Ok(Self {
            file_hash: Ed2kHash::from_str(&manifest.file_hash)
                .with_context(|| format!("invalid manifest file hash {}", manifest.file_hash))?,
            file_size: Some(manifest.file_size).filter(|file_size| *file_size != 0),
            aich_root: manifest
                .aich_root
                .as_deref()
                .map(decode_aich_hash_hex)
                .transpose()?,
        })
    }

    fn from_shared_entry(shared: &Ed2kSharedEntry) -> Result<Self> {
        Ok(Self {
            file_hash: shared.parsed_hash()?,
            file_size: Some(shared.file_size).filter(|file_size| *file_size != 0),
            aich_root: shared
                .aich_root
                .as_deref()
                .map(decode_aich_hash_hex)
                .transpose()?,
        })
    }

    fn encode_into(&self, payload: &mut Vec<u8>) {
        let mut descriptor = Self::INCLUDE_MD4;
        if self.file_size.is_some() {
            descriptor |= Self::INCLUDE_SIZE;
        }
        if self.aich_root.is_some() {
            descriptor |= Self::INCLUDE_AICH;
        }
        payload.push(descriptor);
        payload.extend_from_slice(&self.file_hash.0);
        if let Some(file_size) = self.file_size {
            payload.extend_from_slice(&file_size.to_le_bytes());
        }
        if let Some(aich_root) = self.aich_root {
            payload.extend_from_slice(&aich_root);
        }
    }

    fn decode(payload: &[u8]) -> Result<(Self, &[u8])> {
        let Some((&descriptor, mut rest)) = payload.split_first() else {
            anyhow::bail!("short ED2K FileIdentifier descriptor");
        };
        if descriptor & Self::RESERVED_BITS != 0 {
            anyhow::bail!("unsupported ED2K FileIdentifier descriptor 0x{descriptor:02X}");
        }
        if descriptor & Self::INCLUDE_MD4 == 0 {
            anyhow::bail!("ED2K FileIdentifier missing mandatory MD4 hash");
        }
        if rest.len() < 16 {
            anyhow::bail!("short ED2K FileIdentifier MD4 hash");
        }
        let file_hash = Ed2kHash::from_bytes(rest[..16].try_into().unwrap());
        rest = &rest[16..];

        let file_size = if descriptor & Self::INCLUDE_SIZE != 0 {
            if rest.len() < 8 {
                anyhow::bail!("short ED2K FileIdentifier size");
            }
            let value = u64::from_le_bytes(rest[..8].try_into().unwrap());
            rest = &rest[8..];
            Some(value).filter(|file_size| *file_size != 0)
        } else {
            None
        };

        let aich_root = if descriptor & Self::INCLUDE_AICH != 0 {
            if rest.len() < 20 {
                anyhow::bail!("short ED2K FileIdentifier AICH root");
            }
            let mut root = [0u8; 20];
            root.copy_from_slice(&rest[..20]);
            rest = &rest[20..];
            Some(root)
        } else {
            None
        };

        Ok((
            Self {
                file_hash,
                file_size,
                aich_root,
            },
            rest,
        ))
    }

    fn matches_relaxed(&self, other: &Self) -> bool {
        self.file_hash == other.file_hash
            && match (self.file_size, other.file_size) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
            && match (self.aich_root, other.aich_root) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ed2kHashsetRequestOptions {
    request_md4: bool,
    request_aich: bool,
}

impl Ed2kHashsetRequestOptions {
    const REQUEST_MD4: u8 = 1 << 0;
    const REQUEST_AICH: u8 = 1 << 1;

    fn encode(self) -> u8 {
        (if self.request_md4 {
            Self::REQUEST_MD4
        } else {
            0
        }) | (if self.request_aich {
            Self::REQUEST_AICH
        } else {
            0
        })
    }

    const fn decode(options: u8) -> Self {
        Self {
            request_md4: options & Self::REQUEST_MD4 != 0,
            request_aich: options & Self::REQUEST_AICH != 0,
        }
    }

    const fn has_known_request(self) -> bool {
        self.request_md4 || self.request_aich
    }
}

type Ed2kMd4Hashset = Vec<[u8; 16]>;
type Ed2kMd4HashsetDecode<'a> = (Ed2kHash, Ed2kMd4Hashset, &'a [u8]);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed2kHashsetAnswer2 {
    file_identifier: Ed2kFileIdentifier,
    md4_hashset: Option<Ed2kMd4Hashset>,
    aich_hashset: Option<Ed2kAichHashset>,
}

struct EncodedUploadPartPacket {
    phase: &'static str,
    packet: Vec<u8>,
}

/// Result of the Rust client's active eD2k peer connect path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kPeerConnectMode {
    /// A plaintext eD2k TCP session was opened.
    Plaintext,
    /// An obfuscated eD2k TCP session was opened.
    Obfuscated,
}

impl Ed2kPeerConnectMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Obfuscated => "obfuscated",
        }
    }
}

/// Encode an `OP_CALLBACK` relay frame for a buddy to push down its held TCP
/// connection to the firewalled client (oracle `Process_KADEMLIA_CALLBACK_REQ`).
///
/// `check` is the 16-byte check id from the inbound `KADEMLIA_CALLBACK_REQ`
/// (the firewalled node's `kadID XOR allones`), relayed verbatim; `file_hash`
/// is the requested file; `requester_ip` / `requester_tcp_port` are the callback
/// requester's TCP endpoint (its UDP source IP + advertised TCP port).
#[must_use]
pub fn encode_kad_callback_relay_frame(
    check: [u8; 16],
    file_hash: &Ed2kHash,
    requester_ip: std::net::Ipv4Addr,
    requester_tcp_port: u16,
) -> Vec<u8> {
    codec::encode_kad_callback_relay(check, file_hash, requester_ip, requester_tcp_port)
}

pub(crate) fn apply_server_state(
    mut identity: Ed2kHelloIdentity,
    state: &Ed2kServerState,
) -> Ed2kHelloIdentity {
    if let Some(client_id) = state.client_id {
        identity.client_id = client_id;
    }
    if state.connected
        && let Some(SocketAddr::V4(endpoint)) = state.endpoint
    {
        identity.server_ip = u32::from_le_bytes(endpoint.ip().octets());
        identity.server_port = endpoint.port();
    }
    identity
}

/// Apply the current ED2K server and Kad firewall runtime state to an
/// outbound or listener hello identity.
pub async fn enrich_hello_identity(
    identity: Ed2kHelloIdentity,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> Ed2kHelloIdentity {
    let mut identity = {
        let state = server_state.read().await;
        apply_server_state(identity, &state)
    };
    let firewall = kad_firewall.lock().await;
    identity.direct_udp_callback = identity.client_id != 0
        && identity.client_id < 0x0100_0000
        && firewall.udp_verified
        && firewall.udp_open;
    identity
}

#[cfg(test)]
mod tests;
