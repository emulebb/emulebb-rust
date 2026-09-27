//! Legacy ED2K server-UDP packet bodies which remain useful for old-server
//! interoperability.

use std::net::Ipv4Addr;

use super::{OP_SERVER_LIST_REQ, OP_SERVER_LIST_REQ2};

/// Which historical UDP server-list request body to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServerListRequest {
    /// Server-to-server announcement/request: `<server-ip:4><server-port:2>`.
    LegacyPeer {
        server_ip: Ipv4Addr,
        server_port: u16,
    },
    /// Client request (`ServerGiveUDPList`): an empty body.
    Client,
}

/// Encode `OP_GLOBCALLBACKREQ`:
/// `<requester-ip:4><requester-tcp-port:2><target-low-id:4>`.
pub(super) fn encode_global_callback_request(
    requester_ip: Ipv4Addr,
    requester_tcp_port: u16,
    target_client_id: u32,
) -> [u8; 10] {
    let mut body = [0u8; 10];
    body[..4].copy_from_slice(&requester_ip.octets());
    body[4..6].copy_from_slice(&requester_tcp_port.to_le_bytes());
    body[6..10].copy_from_slice(&target_client_id.to_le_bytes());
    body
}

/// Encode either UDP server-list request variant.
pub(super) fn encode_server_list_request(request: ServerListRequest) -> (u8, Vec<u8>) {
    match request {
        ServerListRequest::LegacyPeer {
            server_ip,
            server_port,
        } => {
            let mut body = Vec::with_capacity(6);
            body.extend_from_slice(&server_ip.octets());
            body.extend_from_slice(&server_port.to_le_bytes());
            (OP_SERVER_LIST_REQ, body)
        }
        ServerListRequest::Client => (OP_SERVER_LIST_REQ2, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_callback_matches_stock_layout() {
        assert_eq!(
            encode_global_callback_request(Ipv4Addr::new(203, 0, 113, 9), 46_662, 0x1234_5678),
            [203, 0, 113, 9, 0x46, 0xB6, 0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn server_list_request_variants_match_stock_layouts() {
        assert_eq!(
            encode_server_list_request(ServerListRequest::LegacyPeer {
                server_ip: Ipv4Addr::new(198, 51, 100, 7),
                server_port: 4661,
            }),
            (OP_SERVER_LIST_REQ, vec![198, 51, 100, 7, 0x35, 0x12])
        );
        assert_eq!(
            encode_server_list_request(ServerListRequest::Client),
            (OP_SERVER_LIST_REQ2, Vec::new())
        );
    }
}
