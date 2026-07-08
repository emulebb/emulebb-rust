/// Protocol header byte for all Kad2 packets.
pub const OP_KADEMLIAHEADER: u8 = 0xE4;

/// Protocol header byte for zlib-compressed Kad2 packets.
pub const OP_KADEMLIAPACKEDPROT: u8 = 0xE5;

/// Our announced Kad version.
///
/// Live oracle captures from the local eMule debug build advertise `0x0A` in
/// Kad HELLO packets, matching upstream `KADEMLIA_VERSION`.
pub const KAD_VERSION: u8 = 10;
/// Minimum Kad version that accepts the keyword-publish AICH tag.
pub const KAD_VERSION_AICH_KEYWORD_PUBLISH: u8 = 9;
/// Lowest accepted Kad2 contact version (`KADEMLIA_VERSION2_47a`); Kad1 nodes
/// (version < 2) are ignored.
pub const KADEMLIA_VERSION2_47A: u8 = 2;
/// Highest pre-obfuscation Kad version (`KADEMLIA_VERSION5_48a`); a contact on
/// UDP port 53 is only accepted above this ("No DNS Port without encryption").
pub const KADEMLIA_VERSION5_48A: u8 = 5;
/// First Kad version that carries `TAG_KADMISCOPTIONS` and completes the
/// `KADEMLIA2_HELLO_RES_ACK` three-way handshake (`KADEMLIA_VERSION8_49b`).
/// `SendMyDetails` only writes the misc-options tag toward a contact at or
/// above this version; older contacts are IP-verified via PING / legacy
/// challenge instead.
pub const KADEMLIA_VERSION8_49B: u8 = 8;

/// K — k-bucket size.
pub const K: usize = 10;

/// Alpha — parallel lookup queries.
pub const ALPHA: usize = 3;

/// KBASE — zone splitting base exponent.
pub const KBASE: usize = 4;

/// KK — peer selection parameter.
pub const KK: usize = 5;

pub const SEARCH_TIMEOUT_SECS: u64 = 45;
pub const STORE_KEYWORD_TIMEOUT_SECS: u64 = 140;
pub const STORE_SOURCE_TIMEOUT_SECS: u64 = 140;
pub const STORE_NOTES_TIMEOUT_SECS: u64 = 100;
/// Backward-compatible source/keyword store lifetime alias.
pub const STORE_TIMEOUT_SECS: u64 = STORE_SOURCE_TIMEOUT_SECS;
/// MFC stops STORE searches in the final 20 seconds so late responses can land.
pub const STORE_STOP_GRACE_SECS: u64 = 20;
/// Target store answers for STOREKEYWORD/STOREFILE/STORENOTES searches.
///
/// Mirrors MFC `SEARCHSTORE*_TOTAL`; this is distinct from active store caps.
pub const STORE_PUBLISH_TARGET_CONTACTS: usize = 10;
/// FINDBUDDY search lifetime in seconds (MFC `SEARCHFINDBUDDY_LIFETIME`,
/// `Defines.h:58`). Like the STORE searches, the manager stops the search 20
/// seconds early so late replies can still land (`SearchManager.cpp:322-325`).
pub const SEARCHFINDBUDDY_LIFETIME_SECS: u64 = 100;
/// FINDBUDDY answer target (MFC `SEARCHFINDBUDDY_TOTAL`, `Defines.h:67`).
///
/// Each `KADEMLIA_FINDBUDDY_REQ` sent counts as one answer
/// (`Search.cpp:892` `++m_uAnswers`); the manager stops the search once the
/// target is reached (`SearchManager.cpp:324`).
pub const SEARCHFINDBUDDY_TOTAL: usize = 10;
pub const REPUBLISH_INTERVAL_SECS: u64 = 18_000;

/// Contacts to request in Req for value lookups (Keyword/Source/Notes/File).
pub const KADEMLIA_FIND_VALUE: u8 = 0x02;
/// Contacts to request in Req for node lookups.
pub const KADEMLIA_FIND_NODE: u8 = 0x0B;
/// Contacts to request when re-asking the closest responded contact for MORE
/// close nodes after a stalled value lookup (eMule `CSearch::JumpStart`
/// `SendFindValue(.., true)`; `KADEMLIA_FIND_VALUE_MORE == KADEMLIA_FIND_NODE`).
pub const KADEMLIA_FIND_VALUE_MORE: u8 = KADEMLIA_FIND_NODE;
/// Contacts to request in Req for store operations.
pub const KADEMLIA_STORE: u8 = 0x04;
/// Max XOR distance high-32-bits for sending search packets to a node.
pub const SEARCHTOLERANCE: u32 = 0x0100_0000;

/// Kad2 packet opcodes.
pub mod opcode {
    pub const BOOTSTRAP_REQ: u8 = 0x01;
    pub const BOOTSTRAP_RES: u8 = 0x09;
    /// Legacy pre-Kad2 hello request; named for diagnostics only.
    pub const HELLO_REQ_DEPRECATED: u8 = 0x10;
    pub const HELLO_REQ: u8 = 0x11;
    /// Legacy pre-Kad2 hello response; named for diagnostics only.
    pub const HELLO_RES_DEPRECATED: u8 = 0x18;
    pub const HELLO_RES: u8 = 0x19;
    pub const HELLO_RES_ACK: u8 = 0x22;
    pub const REQ: u8 = 0x21;
    pub const RES: u8 = 0x29;
    pub const SEARCH_KEY_REQ: u8 = 0x33;
    pub const SEARCH_SOURCE_REQ: u8 = 0x34;
    pub const SEARCH_NOTES_REQ: u8 = 0x35;
    /// Legacy (pre-Kad2) notes-search request (oracle `KADEMLIA_SEARCH_NOTES_REQ`,
    /// 0x32). Out-tracked alongside the Kad2 variant so a legacy notes response is
    /// not dropped as unrequested (oracle `IsTrackedOutListRequestPacket`).
    pub const SEARCH_NOTES_REQ_LEGACY: u8 = 0x32;
    pub const SEARCH_RES: u8 = 0x3B;
    pub const PUBLISH_KEY_REQ: u8 = 0x43;
    pub const PUBLISH_SOURCE_REQ: u8 = 0x44;
    pub const PUBLISH_NOTES_REQ: u8 = 0x45;
    pub const PUBLISH_RES: u8 = 0x4B;
    pub const PUBLISH_RES_ACK: u8 = 0x4C;
    pub const FIREWALLED_REQ: u8 = 0x50;
    pub const FIREWALLED2_REQ: u8 = 0x53;
    pub const FIREWALLED_RES: u8 = 0x58;
    pub const FIREWALLED_ACK_RES: u8 = 0x59;
    pub const FIREWALLUDP: u8 = 0x62;
    /// Buddy-discovery request used by firewalled Kad clients.
    pub const FINDBUDDY_REQ: u8 = 0x51;
    /// Buddy-callback request sent to the chosen relay node.
    ///
    /// Driven end-to-end by the runtime: the LowID buddy / firewalled-callback
    /// state machine acquires a buddy (`FINDBUDDY_REQ`/`RES`), holds the relay
    /// TCP link, and relays `CALLBACK_REQ` to the served buddy.
    pub const CALLBACK_REQ: u8 = 0x52;
    /// Buddy-discovery response returned by an accepted relay node.
    pub const FINDBUDDY_RES: u8 = 0x5A;
    pub const PING: u8 = 0x60;
    pub const PONG: u8 = 0x61;
}

/// Short tag name constants (1-byte eMule FT_* codes).
pub mod tag_name {
    pub const FILENAME: u8 = 0x01;
    pub const FILESIZE: u8 = 0x02;
    pub const FILETYPE: u8 = 0x03;
    pub const FILEFORMAT: u8 = 0x04;
    pub const DESCRIPTION: u8 = 0x0B;
    pub const SOURCES: u8 = 0x15;
    pub const PUBLISHINFO: u8 = 0x33;
    pub const KADAICHHASHPUB: u8 = 0x36;
    pub const KADAICHHASHRESULT: u8 = 0x37;
    pub const FILESIZE_HI: u8 = 0x3A;
    pub const MEDIA_ARTIST: u8 = 0xD0;
    pub const MEDIA_ALBUM: u8 = 0xD1;
    pub const MEDIA_TITLE: u8 = 0xD2;
    pub const MEDIA_LENGTH: u8 = 0xD3;
    pub const MEDIA_BITRATE: u8 = 0xD4;
    pub const MEDIA_CODEC: u8 = 0xD5;
    /// Kad hello/firewall capability bits.
    pub const KADMISCOPTIONS: u8 = 0xF2;
    pub const ENCRYPTION: u8 = 0xF3;
    pub const FILERATING: u8 = 0xF7;
    /// Buddy id (firewalled Kad source's buddy Kad-id) as a 32-char hex string.
    pub const BUDDYHASH: u8 = 0xF8;
    /// Buddy (relay) UDP port for a firewalled Kad source.
    pub const SERVERPORT: u8 = 0xFA;
    pub const SERVERIP: u8 = 0xFB;
    pub const SOURCEUPORT: u8 = 0xFC;
    pub const SOURCEPORT: u8 = 0xFD;
    pub const SOURCEIP: u8 = 0xFE;
    pub const SOURCETYPE: u8 = 0xFF;
}

#[cfg(test)]
mod tests {
    use super::{KAD_VERSION, opcode};

    #[test]
    fn kad_version_matches_local_oracle_build() {
        assert_eq!(KAD_VERSION, 10);
    }

    #[test]
    fn kad2_opcode_constants_match_emule_oracle() {
        let oracle = [
            ("BOOTSTRAP_REQ", opcode::BOOTSTRAP_REQ, 0x01),
            ("BOOTSTRAP_RES", opcode::BOOTSTRAP_RES, 0x09),
            ("HELLO_REQ_DEPRECATED", opcode::HELLO_REQ_DEPRECATED, 0x10),
            ("HELLO_REQ", opcode::HELLO_REQ, 0x11),
            ("HELLO_RES_DEPRECATED", opcode::HELLO_RES_DEPRECATED, 0x18),
            ("HELLO_RES", opcode::HELLO_RES, 0x19),
            ("REQ", opcode::REQ, 0x21),
            ("HELLO_RES_ACK", opcode::HELLO_RES_ACK, 0x22),
            ("RES", opcode::RES, 0x29),
            ("SEARCH_KEY_REQ", opcode::SEARCH_KEY_REQ, 0x33),
            ("SEARCH_SOURCE_REQ", opcode::SEARCH_SOURCE_REQ, 0x34),
            ("SEARCH_NOTES_REQ", opcode::SEARCH_NOTES_REQ, 0x35),
            ("SEARCH_RES", opcode::SEARCH_RES, 0x3B),
            ("PUBLISH_KEY_REQ", opcode::PUBLISH_KEY_REQ, 0x43),
            ("PUBLISH_SOURCE_REQ", opcode::PUBLISH_SOURCE_REQ, 0x44),
            ("PUBLISH_NOTES_REQ", opcode::PUBLISH_NOTES_REQ, 0x45),
            ("PUBLISH_RES", opcode::PUBLISH_RES, 0x4B),
            ("PUBLISH_RES_ACK", opcode::PUBLISH_RES_ACK, 0x4C),
            ("FIREWALLED_REQ", opcode::FIREWALLED_REQ, 0x50),
            ("FINDBUDDY_REQ", opcode::FINDBUDDY_REQ, 0x51),
            ("CALLBACK_REQ", opcode::CALLBACK_REQ, 0x52),
            ("FIREWALLED2_REQ", opcode::FIREWALLED2_REQ, 0x53),
            ("FIREWALLED_RES", opcode::FIREWALLED_RES, 0x58),
            ("FIREWALLED_ACK_RES", opcode::FIREWALLED_ACK_RES, 0x59),
            ("FINDBUDDY_RES", opcode::FINDBUDDY_RES, 0x5A),
            ("PING", opcode::PING, 0x60),
            ("PONG", opcode::PONG, 0x61),
            ("FIREWALLUDP", opcode::FIREWALLUDP, 0x62),
        ];

        for (name, actual, expected) in oracle {
            assert_eq!(actual, expected, "{name}");
        }
    }
}
