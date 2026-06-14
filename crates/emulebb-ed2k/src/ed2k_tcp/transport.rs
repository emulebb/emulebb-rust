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
    Rc4KeyStream, TCP_PACKET_HEADER_LEN, accept_incoming_obfuscation_handshake,
    decode_peer_payload, is_plain_ed2k_protocol_marker, negotiate_outgoing_obfuscation_handshake,
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
        socket
            .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
            .with_context(|| format!("failed to bind outgoing eD2k socket to {bind_ip}"))?;
        // Pin egress to the VPN tunnel interface (IP_UNICAST_IF) before connect so
        // the SYN + payload leave via the tunnel, not just bound by source IP —
        // solid VPN binding (eMule ApplyConfiguredIpv4UnicastInterface). No-op when
        // bind_ip resolves to no interface (e.g. unspecified bind).
        emulebb_kad_dht::socket_opts::pin_egress_to_interface(
            socket2::SockRef::from(&socket),
            crate::networking::resolve_bind_if_index(bind_ip),
        )
        .with_context(|| format!("failed to pin eD2k egress to the bind interface for {bind_ip}"))?;
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
        if packet_length == 0 {
            anyhow::bail!("invalid eD2k packet length 0");
        }

        let payload_len = usize::try_from(packet_length - 1).context("packet length overflow")?;
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
