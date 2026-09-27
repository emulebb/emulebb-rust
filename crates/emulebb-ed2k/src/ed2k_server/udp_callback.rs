//! Cross-server LowID callback over the legacy ED2K server-UDP lane.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Result, ensure};

use crate::config::Ed2kRuntimeConfig;

use super::{
    OP_GLOBCALLBACKREQ, bind_server_udp_socket, encode_global_callback_request, is_low_id,
    resolve_callback_server_entry, udp_runtime::send_server_udp_packet,
};

/// Inputs for one `OP_GLOBCALLBACKREQ` datagram.
pub struct Ed2kUdpCallbackRequestOptions<'a> {
    /// VPN-bound local IPv4 used for the datagram's actual egress.
    pub bind_ip: Ipv4Addr,
    /// Effective server list, including persisted UDP obfuscation metadata.
    pub config: &'a Ed2kRuntimeConfig,
    /// Public IPv4 learned from HighID/STUN. The server anti-spoof check compares
    /// this body field with the datagram's observed source address.
    pub requester_public_ip: Ipv4Addr,
    /// Externally reachable TCP port to which the LowID target should connect.
    pub requester_tcp_port: u16,
    /// TCP endpoint of the server which reported/owns the target LowID client.
    pub server_endpoint: SocketAddr,
    /// Target LowID client identifier.
    pub target_client_id: u32,
}

/// Ask a remote ED2K server to relay a callback to one of its LowID clients.
///
/// This is the old cross-server counterpart to TCP `OP_CALLBACKREQUEST`. It is
/// fire-and-forget: the server either relays a normal `OP_CALLBACKREQUESTED` to
/// the target or silently drops an unknown/rate-limited identifier.
pub async fn request_callback_via_udp_server(
    options: Ed2kUdpCallbackRequestOptions<'_>,
) -> Result<()> {
    ensure!(
        !options.requester_public_ip.is_unspecified(),
        "ED2K global callback requires a known public IPv4"
    );
    ensure!(
        options.requester_tcp_port != 0,
        "ED2K global callback requires a non-zero requester TCP port"
    );
    ensure!(
        options.target_client_id != 0,
        "ED2K global callback requires a non-zero target client ID"
    );
    ensure!(
        is_low_id(options.target_client_id),
        "ED2K global callback target must be a LowID client"
    );

    let mut server = resolve_callback_server_entry(options.config, options.server_endpoint).await?;
    if !server
        .entry
        .udp_key_is_valid_for(Some(options.requester_public_ip))
    {
        // Server UDP keys are bound to the public IPv4 which acquired them.
        // Falling back to the ordinary UDP endpoint is safer than encrypting
        // this one-shot callback with stale persisted key material.
        server.entry.udp_key = 0;
    }
    let body = encode_global_callback_request(
        options.requester_public_ip,
        options.requester_tcp_port,
        options.target_client_id,
    );
    let socket = bind_server_udp_socket(options.bind_ip).await?;
    send_server_udp_packet(&socket, &server, OP_GLOBCALLBACKREQ, &body).await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::*;
    use crate::ed2k_server::OP_EDONKEYPROT;

    #[tokio::test]
    async fn global_callback_sends_exact_plaintext_datagram_to_server_udp_port() {
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_udp_port = server_socket.local_addr().unwrap().port();
        assert!(server_udp_port >= 4);
        let server_tcp_port = server_udp_port - 4;
        let config = Ed2kRuntimeConfig {
            server_endpoints: vec![format!("127.0.0.1:{server_tcp_port}")],
            ..Ed2kRuntimeConfig::default()
        };

        request_callback_via_udp_server(Ed2kUdpCallbackRequestOptions {
            bind_ip: Ipv4Addr::LOCALHOST,
            config: &config,
            requester_public_ip: Ipv4Addr::LOCALHOST,
            requester_tcp_port: 4662,
            server_endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, server_tcp_port)),
            target_client_id: 0x0012_3456,
        })
        .await
        .unwrap();

        let mut buffer = [0u8; 32];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), server_socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            &buffer[..len],
            &[
                OP_EDONKEYPROT,
                OP_GLOBCALLBACKREQ,
                127,
                0,
                0,
                1,
                0x36,
                0x12,
                0x56,
                0x34,
                0x12,
                0x00,
            ]
        );
    }

    #[tokio::test]
    async fn global_callback_rejects_a_high_id_target_before_network_io() {
        let config = Ed2kRuntimeConfig::default();
        let error = request_callback_via_udp_server(Ed2kUdpCallbackRequestOptions {
            bind_ip: Ipv4Addr::LOCALHOST,
            config: &config,
            requester_public_ip: Ipv4Addr::LOCALHOST,
            requester_tcp_port: 4662,
            server_endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, 4661)),
            target_client_id: u32::from_le_bytes([203, 0, 113, 9]),
        })
        .await
        .unwrap_err();

        assert!(error.to_string().contains("must be a LowID"));
    }
}
