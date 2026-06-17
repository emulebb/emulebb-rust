//! eD2k client-to-client UDP obfuscation — the userhash-key path of eMule's
//! `CEncryptedDatagramSocket::EncryptSendClient` / `DecryptReceivedClient`
//! (`srchybrid/EncryptedDatagramSocket.cpp`).
//!
//! This is the missing obfuscation primitive for the UDP source-reask transport
//! ([[udp-source-reask-foundation]]): the crate already has eD2k TCP obfuscation
//! (`ed2k_tcp::obfuscation`), eD2k server-UDP obfuscation (`ed2k_server::obfuscation`)
//! and Kad-UDP obfuscation lives in `emulebb-kad-net`, but client-to-client eD2k
//! UDP packets (OP_REASKFILEPING and friends) are keyed off the *destination
//! client's user hash* + our public IP, which none of those cover.
//!
//! Pure and transport-free: encode/decode of the on-wire crypt frame only. The
//! Kad key paths (NodeID / ReceiverVerifyKey) of the same eMule function are
//! intentionally out of scope here — those belong to the Kad obfuscation layer.
//!
//! Kept off the build's dead-code radar until the reask transport wires it in,
//! mirroring `ed2k_client_udp`.
#![allow(dead_code)]

use md5::compute as md5_compute;

/// `MAGICVALUE_UDP` — the key-material marker byte
/// (`EncryptedDatagramSocket.cpp` `#define MAGICVALUE_UDP 91`).
const MAGICVALUE_UDP: u8 = 91;

/// `MAGICVALUE_UDP_SYNC_CLIENT` — the obfuscation sync magic that, once the first
/// four encrypted bytes decrypt to it, confirms the packet is an eD2k
/// client-to-client obfuscated datagram.
const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F_2EC1;

/// eD2k client UDP crypt-header size with padding disabled (the eMule default,
/// `CRYPT_HEADER_PADDING == 0`) and without the Kad-only verify keys:
/// `byProtocol(1) + wRandomKeyPart(2) + dwMagic(4) + byPadding[0](1)`.
const CRYPT_HEADER_SIZE: usize = 8;

/// Bytes transmitted in clear before the encrypted region begins:
/// `byProtocol(1) + wRandomKeyPart(2)`. eMule's `RC4Crypt(&crypt.dwMagic,
/// nBufLen - 3, ...)` starts encrypting at `dwMagic`.
const CRYPT_HEADER_CLEAR_PREFIX: usize = 3;

// Protocol marker bytes that must never appear as the semi-random first byte:
// the receiver treats them as "definitely not an encrypted packet" and passes
// them through plain (`DecryptReceivedClient` early `switch`).
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_PACKEDPROT: u8 = 0xD4;
const OP_EMULEPROT: u8 = 0xC5;
const OP_KADEMLIAHEADER: u8 = 0xE4;
const OP_KADEMLIAPACKEDPROT: u8 = 0xE5;
const OP_UDPRESERVEDPROT1: u8 = 0xA3;
const OP_UDPRESERVEDPROT2: u8 = 0xB2;

/// The ed2k marker bit eMule sets on the semi-random first byte of client
/// packets (`bySemiRandomNotProtocolMarker |= 1`).
const ED2K_MARKER_BIT: u8 = 0x01;

/// Returns whether `marker` is a reserved protocol byte that the receiver would
/// treat as plaintext, so it must not be used as the obfuscation marker.
fn is_reserved_protocol_marker(marker: u8) -> bool {
    matches!(
        marker,
        OP_EMULEPROT
            | OP_KADEMLIAPACKEDPROT
            | OP_KADEMLIAHEADER
            | OP_UDPRESERVEDPROT1
            | OP_UDPRESERVEDPROT2
            | OP_PACKEDPROT
    )
}

/// Coerce a candidate marker into a valid eD2k client marker: the ed2k bit set
/// and not a reserved protocol byte (matching eMule's `|= 1` + re-roll). The
/// deterministic fallback (`OP_EDONKEYPROT | 1 == 0xE3`) is itself a valid,
/// non-reserved odd byte.
fn sanitize_ed2k_marker(candidate: u8) -> u8 {
    let marker = candidate | ED2K_MARKER_BIT;
    if is_reserved_protocol_marker(marker) {
        OP_EDONKEYPROT | ED2K_MARKER_BIT
    } else {
        marker
    }
}

/// Triage decision for an inbound UDP datagram on the shared eD2k/Kad socket,
/// from its first protocol byte — the `emulebb-ed2k`-owned slice of eMule's
/// `DecryptReceivedClient` key-try heuristic (`EncryptedDatagramSocket.cpp`
/// lines 181-188). Tells the (gated) demux whether to attempt eD2k
/// client-to-client deobfuscation first; the Kad NodeID-vs-ReceiverKey ordering
/// behind `TryKadFirst` is `emulebb-kad-net`'s concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundUdpDecision {
    /// First byte is a reserved protocol marker — the packet is plaintext and
    /// must never be fed to deobfuscation (eMule's early `switch` pass-through).
    Plaintext,
    /// Try eD2k client-to-client deobfuscation first: the ed2k marker bit is set,
    /// or Kad is not running so the eD2k key is the only one worth trying.
    TryEd2kClientFirst,
    /// Kad is running and the ed2k bit is clear, so the packet is more likely a
    /// Kad packet; the eD2k client key remains a later fallback (eMule rotates
    /// through all key types regardless).
    TryKadFirst,
}

/// Classify an inbound shared-socket UDP datagram by its first byte.
///
/// `kad_active` mirrors eMule's `Kademlia::CKademlia::GetPrefs() != NULL`: when
/// Kad never started there is no point trying Kad keys, so eD2k is forced first.
pub fn classify_inbound_client_udp(first_byte: u8, kad_active: bool) -> InboundUdpDecision {
    if is_reserved_protocol_marker(first_byte) {
        return InboundUdpDecision::Plaintext;
    }
    if !kad_active || (first_byte & ED2K_MARKER_BIT) != 0 {
        InboundUdpDecision::TryEd2kClientFirst
    } else {
        InboundUdpDecision::TryKadFirst
    }
}

/// Minimal RC4 keystream, no key-drop — eD2k UDP keys are created with
/// `RC4CreateKey(..., /*bSkipDiscard=*/true)`, i.e. the 1024-byte discard that
/// the TCP handshake performs is skipped (`OtherFunctions.cpp` `RC4CreateKey`).
struct Rc4 {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (index, value) in s.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut j = 0usize;
        for i in 0..256usize {
            j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xFF;
            s.swap(i, j);
        }
        // No discard: eD2k UDP uses bSkipDiscard == true.
        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            self.i = (self.i + 1) & 0xFF;
            self.j = (self.j + self.s[self.i] as usize) & 0xFF;
            self.s.swap(self.i, self.j);
            *byte ^= self.s[(self.s[self.i] as usize + self.s[self.j] as usize) & 0xFF];
        }
    }
}

/// Build the RC4 keystream for an eD2k client UDP packet.
///
/// Key material (`EncryptedDatagramSocket.cpp`, eD2k case): `userHash[16] ||
/// ip[4] || MAGICVALUE_UDP || randomKeyPart[2 LE]`, hashed with MD5. `ip` is the
/// four IPv4 octets in network order (`a.b.c.d`), matching eMule's
/// `PokeUInt32(&achKeyData[16], dwIP)` where `dwIP` already holds the raw wire
/// bytes — taking the octets directly avoids host/network endianness ambiguity.
///
/// The same derivation is symmetric: the sender keys on the *destination*
/// client's hash + the *sender's* public IP; the receiver keys on its *own* hash
/// + the *sender's* IP (which equal the sender's chosen hash/IP).
fn client_udp_keystream(user_hash: &[u8; 16], ip_octets: [u8; 4], random_key_part: u16) -> Rc4 {
    let mut key_material = [0u8; 23];
    key_material[..16].copy_from_slice(user_hash);
    key_material[16..20].copy_from_slice(&ip_octets);
    key_material[20] = MAGICVALUE_UDP;
    key_material[21..23].copy_from_slice(&random_key_part.to_le_bytes());
    Rc4::new(&md5_compute(key_material).0)
}

/// Obfuscate an eD2k client-to-client UDP datagram with caller-supplied
/// `random_key_part` and marker (deterministic; for tests and reproducibility).
///
/// - `dest_user_hash`: the destination client's 16-byte user hash.
/// - `our_public_ip`: our public IPv4 octets (`a.b.c.d`), eMule's
///   `theApp.GetPublicIP()`.
/// - `plaintext`: the cleartext eD2k client packet (e.g. an OP_EMULEPROT frame).
pub fn obfuscate_client_udp_with(
    dest_user_hash: &[u8; 16],
    our_public_ip: [u8; 4],
    plaintext: &[u8],
    random_key_part: u16,
    marker: u8,
) -> Vec<u8> {
    let marker = sanitize_ed2k_marker(marker);
    let mut keystream = client_udp_keystream(dest_user_hash, our_public_ip, random_key_part);

    let mut out = Vec::with_capacity(CRYPT_HEADER_SIZE + plaintext.len());
    out.push(marker); // byProtocol — clear
    out.extend_from_slice(&random_key_part.to_le_bytes()); // wRandomKeyPart — clear
    out.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes()); // dwMagic — encrypted
    out.push(0u8); // byPadding[0] = 0 (padding disabled) — encrypted
    out.extend_from_slice(plaintext); // payload — encrypted

    // Encrypt one continuous RC4 run from dwMagic to the end (nBufLen - 3).
    keystream.apply(&mut out[CRYPT_HEADER_CLEAR_PREFIX..]);
    out
}

/// Obfuscate an eD2k client-to-client UDP datagram, generating the random key
/// part and a fresh non-reserved marker (the production entry point).
pub fn obfuscate_client_udp(
    dest_user_hash: &[u8; 16],
    our_public_ip: [u8; 4],
    plaintext: &[u8],
) -> Vec<u8> {
    let random_key_part: u16 = rand::random();
    let marker = sanitize_ed2k_marker(rand::random::<u8>());
    obfuscate_client_udp_with(
        dest_user_hash,
        our_public_ip,
        plaintext,
        random_key_part,
        marker,
    )
}

/// Try to deobfuscate an inbound datagram as an eD2k client-to-client UDP packet.
///
/// Returns `Some(plaintext)` when the packet decrypts to the eD2k sync magic
/// under our user hash + the sender's IP, else `None` (not an eD2k-obfuscated
/// packet addressed to us, or junk — the caller should then try the Kad key
/// paths or treat it as plaintext, exactly like eMule's multi-try `DecryptReceivedClient`).
///
/// - `our_user_hash`: our own 16-byte user hash (`thePrefs.GetUserHash()`).
/// - `sender_ip`: the sender's IPv4 octets (`a.b.c.d`) from `recvfrom`.
pub fn deobfuscate_client_udp(
    our_user_hash: &[u8; 16],
    sender_ip: [u8; 4],
    datagram: &[u8],
) -> Option<Vec<u8>> {
    // Too short to carry the crypt header => not an encrypted packet.
    if datagram.len() <= CRYPT_HEADER_SIZE {
        return None;
    }
    // A reserved protocol byte means "definitely plaintext" — don't try to decrypt.
    if is_reserved_protocol_marker(datagram[0]) {
        return None;
    }

    let random_key_part = u16::from_le_bytes([datagram[1], datagram[2]]);
    let mut keystream = client_udp_keystream(our_user_hash, sender_ip, random_key_part);

    // Decrypt dwMagic (4 bytes) and check the sync value.
    let mut magic = [datagram[3], datagram[4], datagram[5], datagram[6]];
    keystream.apply(&mut magic);
    if u32::from_le_bytes(magic) != MAGICVALUE_UDP_SYNC_CLIENT {
        return None;
    }

    // Decrypt the padding-length byte; only the low nibble is the length.
    let mut padding = [datagram[7]];
    keystream.apply(&mut padding);
    let padding_len = (padding[0] & 0x0F) as usize;

    // nResult tracks the remaining cleartext, mirroring eMule's accounting.
    let mut remaining = datagram.len() - CRYPT_HEADER_SIZE;
    if remaining <= padding_len {
        return None; // padding larger than the packet => junk
    }
    if padding_len > 0 {
        // Advance the keystream past the padding bytes (they are discarded).
        let mut skip = vec![0u8; padding_len];
        keystream.apply(&mut skip);
        remaining -= padding_len;
    }

    // The payload is the trailing `remaining` bytes; decrypt in place.
    let start = datagram.len() - remaining;
    let mut payload = datagram[start..].to_vec();
    keystream.apply(&mut payload);
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_HASH: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    const SENDER_IP: [u8; 4] = [203, 0, 113, 7];

    #[test]
    fn roundtrip_recovers_plaintext() {
        let plaintext = b"\xC5\x90reask-file-ping-payload";
        // Sender keys on the destination hash + its own (sender) IP; the receiver
        // keys on its own hash (== destination hash) + the sender's IP.
        let datagram = obfuscate_client_udp_with(&DEST_HASH, SENDER_IP, plaintext, 0xBEEF, 0x42);
        let recovered = deobfuscate_client_udp(&DEST_HASH, SENDER_IP, &datagram)
            .expect("packet should decrypt under the shared key");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn obfuscated_header_keeps_marker_and_random_part_in_clear() {
        let datagram = obfuscate_client_udp_with(&DEST_HASH, SENDER_IP, b"payload", 0x1234, 0x40);
        // byProtocol carries the ed2k marker bit and is not a reserved byte.
        assert_eq!(datagram[0] & ED2K_MARKER_BIT, ED2K_MARKER_BIT);
        assert!(!is_reserved_protocol_marker(datagram[0]));
        // wRandomKeyPart is sent in clear, little-endian.
        assert_eq!(u16::from_le_bytes([datagram[1], datagram[2]]), 0x1234);
        // The sync magic is encrypted, so it must NOT appear verbatim on the wire.
        assert_ne!(
            u32::from_le_bytes([datagram[3], datagram[4], datagram[5], datagram[6]]),
            MAGICVALUE_UDP_SYNC_CLIENT
        );
        assert_eq!(datagram.len(), CRYPT_HEADER_SIZE + "payload".len());
    }

    #[test]
    fn wrong_hash_does_not_decrypt() {
        let datagram = obfuscate_client_udp_with(&DEST_HASH, SENDER_IP, b"secret", 0x7777, 0x44);
        let mut other_hash = DEST_HASH;
        other_hash[0] ^= 0xFF;
        assert!(deobfuscate_client_udp(&other_hash, SENDER_IP, &datagram).is_none());
    }

    #[test]
    fn wrong_sender_ip_does_not_decrypt() {
        let datagram = obfuscate_client_udp_with(&DEST_HASH, SENDER_IP, b"secret", 0x7777, 0x44);
        assert!(deobfuscate_client_udp(&DEST_HASH, [198, 51, 100, 9], &datagram).is_none());
    }

    #[test]
    fn reserved_protocol_marker_is_passed_through() {
        // A datagram whose first byte is a reserved protocol marker is plaintext;
        // never attempt to decrypt it.
        let mut datagram = vec![OP_EMULEPROT, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7];
        assert!(deobfuscate_client_udp(&DEST_HASH, SENDER_IP, &datagram).is_none());
        datagram[0] = OP_KADEMLIAHEADER;
        assert!(deobfuscate_client_udp(&DEST_HASH, SENDER_IP, &datagram).is_none());
    }

    #[test]
    fn short_datagram_is_not_treated_as_encrypted() {
        let datagram = [0x01u8; CRYPT_HEADER_SIZE]; // exactly header-sized => no payload
        assert!(deobfuscate_client_udp(&DEST_HASH, SENDER_IP, &datagram).is_none());
    }

    #[test]
    fn sanitize_marker_sets_ed2k_bit_and_avoids_reserved() {
        // Even input gains the ed2k bit.
        assert_eq!(
            sanitize_ed2k_marker(0x40) & ED2K_MARKER_BIT,
            ED2K_MARKER_BIT
        );
        // Reserved-after-bit values fall back to a valid non-reserved marker.
        for reserved in [
            OP_EMULEPROT,
            OP_KADEMLIAPACKEDPROT,
            OP_KADEMLIAHEADER,
            OP_UDPRESERVEDPROT1,
            OP_UDPRESERVEDPROT2,
            OP_PACKEDPROT,
        ] {
            let marker = sanitize_ed2k_marker(reserved);
            assert!(!is_reserved_protocol_marker(marker));
            assert_eq!(marker & ED2K_MARKER_BIT, ED2K_MARKER_BIT);
        }
    }

    #[test]
    fn classify_reserved_markers_are_plaintext() {
        for reserved in [
            OP_EMULEPROT,
            OP_KADEMLIAPACKEDPROT,
            OP_KADEMLIAHEADER,
            OP_UDPRESERVEDPROT1,
            OP_UDPRESERVEDPROT2,
            OP_PACKEDPROT,
        ] {
            assert_eq!(
                classify_inbound_client_udp(reserved, true),
                InboundUdpDecision::Plaintext
            );
        }
        // OP_EDONKEYPROT (0xE3) is NOT in the plaintext switch, so it is treated
        // as a deobfuscation candidate (and it is odd => ed2k bit set).
        assert_eq!(
            classify_inbound_client_udp(OP_EDONKEYPROT, true),
            InboundUdpDecision::TryEd2kClientFirst
        );
    }

    #[test]
    fn classify_ed2k_bit_prefers_ed2k_when_kad_active() {
        // ed2k marker bit set => eD2k key first even with Kad running.
        assert_eq!(
            classify_inbound_client_udp(0x43, true),
            InboundUdpDecision::TryEd2kClientFirst
        );
        // ed2k bit clear + Kad active => Kad first.
        assert_eq!(
            classify_inbound_client_udp(0x42, true),
            InboundUdpDecision::TryKadFirst
        );
    }

    #[test]
    fn classify_forces_ed2k_when_kad_inactive() {
        // Kad never ran => only the eD2k key is worth trying, regardless of bits.
        assert_eq!(
            classify_inbound_client_udp(0x42, false),
            InboundUdpDecision::TryEd2kClientFirst
        );
        assert_eq!(
            classify_inbound_client_udp(0x43, false),
            InboundUdpDecision::TryEd2kClientFirst
        );
        // A reserved marker is still plaintext even when Kad is inactive.
        assert_eq!(
            classify_inbound_client_udp(OP_EMULEPROT, false),
            InboundUdpDecision::Plaintext
        );
    }

    #[test]
    fn marker_and_random_part_do_not_affect_payload_recovery() {
        // Different markers / key parts still round-trip (marker is cleartext;
        // the key part is mixed into the MD5 key on both ends).
        let plaintext = b"another-reask-ack";
        for (rkp, marker) in [(0x0000u16, 0x00u8), (0xFFFF, 0xFE), (0x8001, 0x80)] {
            let datagram = obfuscate_client_udp_with(&DEST_HASH, SENDER_IP, plaintext, rkp, marker);
            let recovered =
                deobfuscate_client_udp(&DEST_HASH, SENDER_IP, &datagram).expect("round-trip");
            assert_eq!(recovered, plaintext);
        }
    }

    /// Full pure pipeline the gated reask transport will run, end to end:
    /// encode an OP_REASKFILEPING body -> wrap as an OP_EMULEPROT client UDP frame
    /// -> obfuscate -> classify the inbound first byte -> deobfuscate -> decode.
    /// Guards that the independently-built pieces compose losslessly.
    #[test]
    fn full_reask_obfuscation_pipeline_round_trips() {
        use crate::ed2k_client_udp::{
            OP_REASKFILEPING, decode_reask_file_ping, encode_reask_file_ping,
        };
        use emulebb_kad_proto::Ed2kHash;

        let file_hash = Ed2kHash::from_bytes([
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);
        let parts = [true, false, true, true, false];
        let udp_version = 4;

        // Downloader builds the OP_EMULEPROT client-UDP frame: [0xC5][opcode][body].
        let body = encode_reask_file_ping(&file_hash, Some(&parts), 3, udp_version);
        let mut frame = vec![OP_EMULEPROT, OP_REASKFILEPING];
        frame.extend_from_slice(&body);

        // Obfuscate toward the destination, keyed on its hash + our IP.
        let datagram = obfuscate_client_udp_with(&DEST_HASH, SENDER_IP, &frame, 0x1357, 0x40);

        // The receiver triages the first byte before any decrypt: with the ed2k
        // marker bit set it tries the eD2k client key first.
        assert_eq!(
            classify_inbound_client_udp(datagram[0], true),
            InboundUdpDecision::TryEd2kClientFirst
        );

        // Deobfuscate (receiver keys on its own hash == DEST_HASH + sender IP).
        let recovered_frame = deobfuscate_client_udp(&DEST_HASH, SENDER_IP, &datagram)
            .expect("pipeline should decrypt");
        assert_eq!(recovered_frame, frame);

        // Strip the 2-byte OP_EMULEPROT header and decode the reask ping back.
        assert_eq!(recovered_frame[0], OP_EMULEPROT);
        assert_eq!(recovered_frame[1], OP_REASKFILEPING);
        let decoded = decode_reask_file_ping(&recovered_frame[2..], udp_version).unwrap();
        assert_eq!(decoded.file_hash, file_hash);
        assert_eq!(decoded.part_status.unwrap(), parts);
        assert_eq!(decoded.complete_source_count, Some(3));
    }
}
