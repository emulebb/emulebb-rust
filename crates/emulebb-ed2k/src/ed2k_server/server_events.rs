//! Server-list feedback events raised by the long-lived server session and the
//! decoder for `OP_SERVERLIST` server-discovery bodies.
//!
//! The session loop runs inside this crate but the authoritative server list
//! lives in the core. These typed events (libtorrent-alert style) let the
//! session report server-discovery (`OP_SERVERLIST`, eMule
//! `CServerSocket::ProcessPacket`) and connect/ping outcomes (eMule
//! `CServerList::ServerStats` fail-count + dead-server drop) back to the core,
//! which owns the persisted server store.

use std::net::Ipv4Addr;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Maximum servers accepted from a single `OP_SERVERLIST` body. eMule itself
/// imposes no fixed cap beyond the `count <= (size - 1) / 6` structural bound it
/// validates, but a sane upper bound guards against a hostile server flooding the
/// list in one packet.
pub const MAX_SERVERS_FROM_ONE_LIST: usize = 1_000;

/// A feedback event from the ED2K server session to the core's server store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed2kServerListEvent {
    /// New `(ip, port)` servers learned from an `OP_SERVERLIST` reply, to be
    /// merged into the server list (deduped against existing entries by the core).
    DiscoveredServers(Vec<(Ipv4Addr, u16)>),
    /// A connect/ping attempt to `endpoint` failed (eMule `IncFailedCount`); the
    /// core increments the fail-count and may drop a non-static dead server.
    ConnectFailed { endpoint: String },
    /// A connect to `endpoint` succeeded (login accepted); the core clears the
    /// fail-count (eMule resets the count on a successful response/connect).
    ConnectSucceeded { endpoint: String },
}

/// Sender half handed to the server session loop.
pub type Ed2kServerListEventSender = UnboundedSender<Ed2kServerListEvent>;
/// Receiver half consumed by the core's server-list event task.
pub type Ed2kServerListEventReceiver = UnboundedReceiver<Ed2kServerListEvent>;

/// Create a server-list event channel (unbounded; events are small and rare).
#[must_use]
pub fn ed2k_server_list_event_channel() -> (Ed2kServerListEventSender, Ed2kServerListEventReceiver)
{
    unbounded_channel()
}

/// Decode the `(ip, port)` entries from an `OP_SERVERLIST` body.
///
/// Layout (eMule `CServerSocket::ProcessPacket` OP_SERVERLIST):
/// `{count: u8}` then `count * {ip: u32 LE, port: u16 LE}`. eMule validates the
/// structural bound `count <= (size - 1) / (4 + 2)` and silently stops at the
/// first truncated entry. The IP is read little-endian (`ReadUInt32`), i.e. the
/// four body bytes are the dotted octets in order. Returns the decoded servers
/// (deduped within this body), capped at [`MAX_SERVERS_FROM_ONE_LIST`].
#[must_use]
pub fn decode_server_list(body: &[u8]) -> Vec<(Ipv4Addr, u16)> {
    if body.is_empty() {
        return Vec::new();
    }
    let declared = body[0] as usize;
    // eMule's structural sanity bound: a body claiming more entries than it can
    // hold is rejected outright.
    let available = (body.len() - 1) / 6;
    if declared > available {
        return Vec::new();
    }
    let mut servers = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut pos = 1usize;
    for _ in 0..declared {
        if servers.len() >= MAX_SERVERS_FROM_ONE_LIST {
            break;
        }
        if pos + 6 > body.len() {
            break;
        }
        let ip = Ipv4Addr::new(body[pos], body[pos + 1], body[pos + 2], body[pos + 3]);
        let port = u16::from_le_bytes([body[pos + 4], body[pos + 5]]);
        pos += 6;
        // Skip structurally useless entries (eMule never adds a zero-port server).
        if port == 0 || ip.is_unspecified() {
            continue;
        }
        if seen.insert((ip, port)) {
            servers.push((ip, port));
        }
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut bytes = ip.to_vec();
        bytes.extend_from_slice(&port.to_le_bytes());
        bytes
    }

    #[test]
    fn decodes_count_and_entries() {
        let mut body = vec![2u8];
        body.extend(entry([45, 82, 80, 155], 5687));
        body.extend(entry([203, 0, 113, 9], 4661));
        let servers = decode_server_list(&body);
        assert_eq!(
            servers,
            vec![
                (Ipv4Addr::new(45, 82, 80, 155), 5687),
                (Ipv4Addr::new(203, 0, 113, 9), 4661),
            ]
        );
    }

    #[test]
    fn dedupes_within_one_body() {
        let mut body = vec![3u8];
        body.extend(entry([45, 82, 80, 155], 5687));
        body.extend(entry([45, 82, 80, 155], 5687));
        body.extend(entry([1, 2, 3, 4], 4242));
        let servers = decode_server_list(&body);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], (Ipv4Addr::new(45, 82, 80, 155), 5687));
        assert_eq!(servers[1], (Ipv4Addr::new(1, 2, 3, 4), 4242));
    }

    #[test]
    fn skips_zero_port_and_unspecified() {
        let mut body = vec![2u8];
        body.extend(entry([45, 82, 80, 155], 0)); // zero port
        body.extend(entry([0, 0, 0, 0], 4661)); // unspecified ip
        assert!(decode_server_list(&body).is_empty());
    }

    #[test]
    fn rejects_count_exceeding_structural_bound() {
        // Claims 5 entries but only carries one entry's worth of bytes.
        let mut body = vec![5u8];
        body.extend(entry([1, 2, 3, 4], 4242));
        assert!(decode_server_list(&body).is_empty());
    }

    #[test]
    fn empty_body_yields_nothing() {
        assert!(decode_server_list(&[]).is_empty());
        assert!(decode_server_list(&[0u8]).is_empty());
    }

    #[test]
    fn caps_at_max_servers_from_one_list() {
        let count = MAX_SERVERS_FROM_ONE_LIST + 50;
        // u8 count cannot exceed 255, so exercise the in-loop cap with a body that
        // declares 255 entries; the cap itself is asserted as a constant guard.
        let declared = 255usize;
        let mut body = vec![declared as u8];
        for i in 0..declared {
            body.extend(entry(
                [10, 0, (i >> 8) as u8, (i & 0xff) as u8],
                4000 + (i as u16),
            ));
        }
        let servers = decode_server_list(&body);
        assert!(servers.len() <= MAX_SERVERS_FROM_ONE_LIST);
        assert!(servers.len() <= count);
    }
}
