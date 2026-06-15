//! UDP global server-status (`OP_GLOBSERVSTATREQ`/`OP_GLOBSERVSTATRES`) challenge
//! handling, mirroring stock eMule's `CServerList::Process` /
//! `CUDPSocket::ProcessPacket` (`ServerList.cpp` / `UDPSocket.cpp`).
//!
//! eMule sends a 4-byte challenge (`0x55AA0000 | rand16`) in the status request,
//! stores it on the pinged server, and the response echoes the challenge in its
//! first 4 bytes; a mismatching (or stale) challenge is discarded as an
//! unsolicited reply. The user/file counters therefore live at offset 4/8, not
//! 0/4, and the server's live UDP capability flags trail at offset 24.

/// Build a stock global-server-status challenge: `0x55AA0000 | rand16`
/// (`ServerList.cpp`: `uChallenge = 0x55AA0000 + GetRandomUInt16()`).
pub(super) fn server_status_challenge() -> u32 {
    0x55AA_0000 | u32::from(rand::random::<u16>())
}

/// Decoded `OP_GLOBSERVSTATRES` body once its echoed challenge has matched the
/// outstanding request challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ServerStatusResponse {
    pub(super) users: u32,
    pub(super) files: u32,
    /// Live UDP capability flags (offset 24), when the server included them.
    pub(super) udp_flags: Option<u32>,
}

fn read_u32_le(payload: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ])
}

/// Validate and decode an `OP_GLOBSERVSTATRES` payload against the challenge we
/// issued. Returns `None` when the payload is too short or the echoed challenge
/// does not match (an unsolicited/stale reply, which eMule discards).
///
/// Layout (`UDPSocket.cpp`): `[challenge@0][users@4][files@8][maxusers@12]`
/// `[softfiles@16][hardfiles@20][udpflags@24]...`. eMule requires `size >= 12`
/// (challenge + users + files); the trailing fields are optional.
pub(super) fn decode_server_status_response(
    payload: &[u8],
    expected_challenge: u32,
) -> Option<ServerStatusResponse> {
    if payload.len() < 12 {
        return None;
    }
    let challenge = read_u32_le(payload, 0);
    if challenge != expected_challenge {
        return None;
    }
    let users = read_u32_le(payload, 4);
    let files = read_u32_le(payload, 8);
    let udp_flags = (payload.len() >= 28).then(|| read_u32_le(payload, 24));
    Some(ServerStatusResponse {
        users,
        files,
        udp_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(challenge: u32, users: u32, files: u32, trailer: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&challenge.to_le_bytes());
        payload.extend_from_slice(&users.to_le_bytes());
        payload.extend_from_slice(&files.to_le_bytes());
        payload.extend_from_slice(trailer);
        payload
    }

    #[test]
    fn challenge_uses_stock_prefix() {
        for _ in 0..64 {
            let challenge = server_status_challenge();
            assert_eq!(challenge & 0xFFFF_0000, 0x55AA_0000);
        }
    }

    #[test]
    fn decode_reads_users_and_files_at_stock_offsets() {
        let challenge = 0x55AA_1234;
        let payload = body(challenge, 5000, 90000, &[]);
        let decoded = decode_server_status_response(&payload, challenge).expect("matching challenge");
        assert_eq!(decoded.users, 5000);
        assert_eq!(decoded.files, 90000);
        assert_eq!(decoded.udp_flags, None);
    }

    #[test]
    fn decode_harvests_udp_flags_at_offset_24() {
        let challenge = 0x55AA_ABCD;
        // maxusers@12, softfiles@16, hardfiles@20, udpflags@24
        let trailer = {
            let mut t = Vec::new();
            t.extend_from_slice(&7000u32.to_le_bytes()); // maxusers
            t.extend_from_slice(&1u32.to_le_bytes()); // softfiles
            t.extend_from_slice(&2u32.to_le_bytes()); // hardfiles
            t.extend_from_slice(&0x0000_0321u32.to_le_bytes()); // udpflags
            t
        };
        let payload = body(challenge, 100, 200, &trailer);
        let decoded = decode_server_status_response(&payload, challenge).expect("matching challenge");
        assert_eq!(decoded.users, 100);
        assert_eq!(decoded.files, 200);
        assert_eq!(decoded.udp_flags, Some(0x0000_0321));
    }

    #[test]
    fn decode_rejects_mismatched_challenge() {
        let payload = body(0x55AA_0001, 1, 2, &[]);
        assert!(decode_server_status_response(&payload, 0x55AA_0002).is_none());
    }

    #[test]
    fn decode_rejects_short_payload() {
        let payload = body(0x55AA_0001, 1, 2, &[]);
        assert!(decode_server_status_response(&payload[..11], 0x55AA_0001).is_none());
    }
}
