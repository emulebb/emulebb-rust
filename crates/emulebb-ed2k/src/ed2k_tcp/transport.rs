use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};

use super::{
    MAX_ED2K_PACKET_LEN, OP_EDONKEYPROT, OP_EMULEPROT, OP_PACKEDPROT, Rc4KeyStream,
    TCP_PACKET_HEADER_LEN, accept_incoming_obfuscation_handshake, decode_peer_payload,
    is_plain_ed2k_protocol_marker, negotiate_outgoing_obfuscation_handshake,
    should_enable_outgoing_obfuscation,
};

/// One decoded eD2k TCP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuleTcpPacket {
    /// Protocol marker byte.
    pub protocol: u8,
    /// Packet opcode.
    pub opcode: u8,
    /// Packet payload without the framing header.
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct Ed2kTransport {
    pub(super) stream: TcpStream,
    pub(super) prefetched: VecDeque<u8>,
    pub(super) receive_cipher: Option<Rc4KeyStream>,
    pub(super) send_cipher: Option<Rc4KeyStream>,
    pub(super) mode: Ed2kTransportMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kTransportMode {
    Plaintext,
    Obfuscated,
}

impl Ed2kTransportMode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Obfuscated => "obfuscated",
        }
    }

    /// Whether the session is obfuscated — a proxy for the peer supporting crypt,
    /// used to decide whether UDP reasks to it should be obfuscated.
    pub(crate) const fn is_obfuscated(self) -> bool {
        matches!(self, Self::Obfuscated)
    }
}

impl Ed2kTransport {
    pub(super) async fn connect_outgoing(
        bind_ip: Ipv4Addr,
        peer_addr: SocketAddr,
        local_connect_options: u8,
        peer_user_hash: Option<[u8; 16]>,
        peer_connect_options: Option<u8>,
        timeout: Duration,
    ) -> Result<Self> {
        let socket = match peer_addr {
            SocketAddr::V4(_) => {
                TcpSocket::new_v4().context("failed to create outgoing eD2k TCP socket")?
            }
            SocketAddr::V6(_) => {
                anyhow::bail!("IPv6 callback peer connections are not supported yet: {peer_addr}")
            }
        };
        let bind_if_index = crate::networking::require_bind_if_index(bind_ip, "eD2k TCP")?;
        socket
            .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
            .with_context(|| format!("failed to bind outgoing eD2k socket to {bind_ip}"))?;
        // Pin egress to the VPN tunnel interface (IP_UNICAST_IF) before connect so
        // the SYN + payload leave via the tunnel, not just bound by source IP —
        // solid VPN binding (eMule ApplyConfiguredIpv4UnicastInterface).
        emulebb_kad_dht::socket_opts::pin_egress_to_interface(
            socket2::SockRef::from(&socket),
            Some(bind_if_index),
        )
        .with_context(|| {
            format!("failed to pin eD2k egress to the bind interface for {bind_ip}")
        })?;
        let mut stream = tokio::time::timeout(timeout, socket.connect(peer_addr))
            .await
            .with_context(|| format!("timed out connecting to eD2k peer {peer_addr}"))??;
        stream
            .set_nodelay(true)
            .with_context(|| format!("failed to enable TCP_NODELAY for peer {peer_addr}"))?;

        if should_enable_outgoing_obfuscation(
            local_connect_options,
            peer_user_hash,
            peer_connect_options,
        )? {
            let peer_user_hash = peer_user_hash.expect("validated above");
            let (receive_cipher, send_cipher) = tokio::time::timeout(
                timeout,
                negotiate_outgoing_obfuscation_handshake(&mut stream, peer_user_hash),
            )
            .await
            .with_context(|| {
                format!("timed out negotiating eD2k obfuscation with peer {peer_addr}")
            })??;
            return Ok(Self {
                stream,
                prefetched: VecDeque::new(),
                receive_cipher: Some(receive_cipher),
                send_cipher: Some(send_cipher),
                mode: Ed2kTransportMode::Obfuscated,
            });
        }

        Ok(Self {
            stream,
            prefetched: VecDeque::new(),
            receive_cipher: None,
            send_cipher: None,
            mode: Ed2kTransportMode::Plaintext,
        })
    }

    pub(super) async fn accept(mut stream: TcpStream, local_user_hash: [u8; 16]) -> Result<Self> {
        let mut first_byte = [0u8; 1];
        match stream.read_exact(&mut first_byte).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(Self {
                    stream,
                    prefetched: VecDeque::new(),
                    receive_cipher: None,
                    send_cipher: None,
                    mode: Ed2kTransportMode::Plaintext,
                });
            }
            Err(error) => return Err(error.into()),
        }

        if is_plain_ed2k_protocol_marker(first_byte[0]) {
            let mut prefetched = VecDeque::with_capacity(1);
            prefetched.push_back(first_byte[0]);
            return Ok(Self {
                stream,
                prefetched,
                receive_cipher: None,
                send_cipher: None,
                mode: Ed2kTransportMode::Plaintext,
            });
        }

        let (receive_cipher, send_cipher) =
            accept_incoming_obfuscation_handshake(&mut stream, local_user_hash, first_byte[0])
                .await?;
        Ok(Self {
            stream,
            prefetched: VecDeque::new(),
            receive_cipher: Some(receive_cipher),
            send_cipher: Some(send_cipher),
            mode: Ed2kTransportMode::Obfuscated,
        })
    }

    pub(super) async fn read_packet(&mut self) -> Result<Option<EmuleTcpPacket>> {
        let Some(protocol) = self.read_u8().await? else {
            return Ok(None);
        };

        let mut header_rest = [0u8; TCP_PACKET_HEADER_LEN - 1];
        self.read_exact(&mut header_rest).await?;
        let packet_length = u32::from_le_bytes([
            header_rest[0],
            header_rest[1],
            header_rest[2],
            header_rest[3],
        ]);
        let opcode = header_rest[4];
        if !matches!(protocol, OP_EDONKEYPROT | OP_PACKEDPROT | OP_EMULEPROT) {
            anyhow::bail!("invalid eD2k peer protocol header 0x{protocol:02X}");
        }
        if packet_length == 0 {
            anyhow::bail!("invalid eD2k packet length 0");
        }

        let payload_len = usize::try_from(packet_length - 1).context("packet length overflow")?;
        if payload_len > MAX_ED2K_PACKET_LEN {
            anyhow::bail!(
                "oversized eD2k peer packet length {payload_len} exceeds {MAX_ED2K_PACKET_LEN}"
            );
        }
        let mut payload = vec![0u8; payload_len];
        self.read_exact(&mut payload).await?;
        let (protocol, payload) = decode_peer_payload(protocol, payload)?;
        Ok(Some(EmuleTcpPacket {
            protocol,
            opcode,
            payload,
        }))
    }

    pub(super) async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(cipher) = self.send_cipher.as_mut() {
            let mut encrypted = bytes.to_vec();
            cipher.apply(&mut encrypted);
            self.stream.write_all(&encrypted).await?;
        } else {
            self.stream.write_all(bytes).await?;
        }
        Ok(())
    }

    async fn read_u8(&mut self) -> Result<Option<u8>> {
        if let Some(byte) = self.prefetched.pop_front() {
            return Ok(Some(byte));
        }
        let mut byte = [0u8; 1];
        match self.stream.read_exact(&mut byte).await {
            Ok(_) => {
                if let Some(cipher) = self.receive_cipher.as_mut() {
                    cipher.apply(&mut byte);
                }
                Ok(Some(byte[0]))
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            if let Some(byte) = self.prefetched.pop_front() {
                bytes[offset] = byte;
                offset += 1;
            } else {
                break;
            }
        }
        if offset < bytes.len() {
            self.stream.read_exact(&mut bytes[offset..]).await?;
            if let Some(cipher) = self.receive_cipher.as_mut() {
                cipher.apply(&mut bytes[offset..]);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::OP_HELLO;
    use super::*;
    use tokio::net::TcpListener;

    /// Build a plaintext transport whose `read_packet` consumes only the
    /// `prefetched` bytes (the cap/header validation happens before any payload
    /// read). The TcpStream is a parked loopback connection used purely to
    /// satisfy the struct field; its contents are never read in these cases.
    async fn transport_with_prefetched(prefetched: Vec<u8>) -> (Ed2kTransport, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let stream = connect.await.unwrap();
        (
            Ed2kTransport {
                stream,
                prefetched: prefetched.into(),
                receive_cipher: None,
                send_cipher: None,
                mode: Ed2kTransportMode::Plaintext,
            },
            // Returned so the caller controls the peer side (e.g. drop it to
            // force EOF on a payload read).
            server,
        )
    }

    fn header(protocol: u8, packet_length: u32, opcode: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN);
        bytes.push(protocol);
        bytes.extend_from_slice(&packet_length.to_le_bytes());
        bytes.push(opcode);
        bytes
    }

    #[tokio::test]
    async fn rejects_oversized_declared_packet_length_without_allocating() {
        // A hostile peer declares packet_length = 0xFFFFFFFF (~4GB). The cap
        // must reject it before the payload buffer is allocated.
        let (mut transport, _server) =
            transport_with_prefetched(header(OP_EDONKEYPROT, u32::MAX, OP_HELLO)).await;
        let err = transport
            .read_packet()
            .await
            .expect_err("oversized declared length must be rejected");
        assert!(
            err.to_string()
                .contains("oversized eD2k peer packet length"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn accepts_declared_length_at_the_cap_boundary() {
        // packet_length = MAX_ED2K_PACKET_LEN + 1 -> payload_len == cap, allowed
        // by the bound (it only rejects payload_len > cap). The payload read
        // then fails on the closed parked stream, proving we got past the cap.
        let packet_length = u32::try_from(MAX_ED2K_PACKET_LEN + 1).unwrap();
        let (mut transport, server) =
            transport_with_prefetched(header(OP_EDONKEYPROT, packet_length, OP_HELLO)).await;
        // Close the peer side so the (allowed) payload read fails with EOF
        // instead of blocking forever.
        drop(server);
        let err = transport
            .read_packet()
            .await
            .expect_err("payload read should fail on the closed peer");
        // The failure must come from the payload read, NOT the oversized cap.
        assert!(
            !err.to_string()
                .contains("oversized eD2k peer packet length"),
            "boundary length must not trip the cap: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_unknown_protocol_header() {
        // Protocol byte not in {0xE3, 0xD4, 0xC5} -> drop (ERR_WRONGHEADER).
        let (mut transport, _server) = transport_with_prefetched(header(0x12, 5, OP_HELLO)).await;
        let err = transport
            .read_packet()
            .await
            .expect_err("bad protocol header must be rejected");
        assert!(
            err.to_string()
                .contains("invalid eD2k peer protocol header"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_zero_packet_length() {
        let (mut transport, _server) =
            transport_with_prefetched(header(OP_EDONKEYPROT, 0, OP_HELLO)).await;
        let err = transport
            .read_packet()
            .await
            .expect_err("zero packet length must be rejected");
        assert!(
            err.to_string().contains("invalid eD2k packet length 0"),
            "unexpected error: {err}"
        );
    }
}
