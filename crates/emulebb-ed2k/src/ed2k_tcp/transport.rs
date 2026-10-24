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

#[cfg(feature = "packet-diagnostics")]
#[derive(Debug, Default)]
struct Ed2kTcpReadCapture {
    raw: Vec<u8>,
    clear_frame: Vec<u8>,
}

/// One socket-read granularity for the buffered receive path. Headers are 6
/// bytes and control packets tens of bytes, so one recv typically batches many
/// packets (plus a data packet's tail); the old unbuffered path paid two
/// syscalls per packet for the 1-byte marker + 5-byte header alone.
const READ_BUFFER_CHUNK: usize = 32 * 1024;

#[derive(Debug)]
pub(super) struct Ed2kTransport {
    pub(super) stream: TcpStream,
    pub(super) prefetched: VecDeque<u8>,
    pub(super) receive_cipher: Option<Rc4KeyStream>,
    pub(super) send_cipher: Option<Rc4KeyStream>,
    pub(super) mode: Ed2kTransportMode,
    /// Buffered inbound bytes, already decrypted (RC4 is a stream cipher, so
    /// the keystream is applied once, in arrival order, at fill time).
    /// `read_pos` marks how far the buffer has been consumed.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Exact socket bytes aligned with `read_buf`. The protocol reader decrypts
    /// `read_buf` in place, so diagnostics retain this parallel copy while the
    /// packet-diagnostics feature is enabled.
    #[cfg(feature = "packet-diagnostics")]
    read_wire_buf: Vec<u8>,
    #[cfg(feature = "packet-diagnostics")]
    read_capture: Option<Ed2kTcpReadCapture>,
    /// Reusable ciphertext scratch for obfuscated sends, so every write does
    /// not allocate a fresh copy of the packet.
    write_buf: Vec<u8>,
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
    pub(super) fn from_parts(
        stream: TcpStream,
        prefetched: VecDeque<u8>,
        receive_cipher: Option<Rc4KeyStream>,
        send_cipher: Option<Rc4KeyStream>,
        mode: Ed2kTransportMode,
    ) -> Self {
        Self {
            stream,
            prefetched,
            receive_cipher,
            send_cipher,
            mode,
            read_buf: Vec::new(),
            read_pos: 0,
            #[cfg(feature = "packet-diagnostics")]
            read_wire_buf: Vec::new(),
            #[cfg(feature = "packet-diagnostics")]
            read_capture: None,
            write_buf: Vec::new(),
        }
    }

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
            return Ok(Self::from_parts(
                stream,
                VecDeque::new(),
                Some(receive_cipher),
                Some(send_cipher),
                Ed2kTransportMode::Obfuscated,
            ));
        }

        Ok(Self::from_parts(
            stream,
            VecDeque::new(),
            None,
            None,
            Ed2kTransportMode::Plaintext,
        ))
    }

    pub(super) async fn accept(mut stream: TcpStream, local_user_hash: [u8; 16]) -> Result<Self> {
        let mut first_byte = [0u8; 1];
        match stream.read_exact(&mut first_byte).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(Self::from_parts(
                    stream,
                    VecDeque::new(),
                    None,
                    None,
                    Ed2kTransportMode::Plaintext,
                ));
            }
            Err(error) => return Err(error.into()),
        }

        if is_plain_ed2k_protocol_marker(first_byte[0]) {
            let mut prefetched = VecDeque::with_capacity(1);
            prefetched.push_back(first_byte[0]);
            return Ok(Self::from_parts(
                stream,
                prefetched,
                None,
                None,
                Ed2kTransportMode::Plaintext,
            ));
        }

        let (receive_cipher, send_cipher) =
            accept_incoming_obfuscation_handshake(&mut stream, local_user_hash, first_byte[0])
                .await?;
        Ok(Self::from_parts(
            stream,
            VecDeque::new(),
            Some(receive_cipher),
            Some(send_cipher),
            Ed2kTransportMode::Obfuscated,
        ))
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

    #[cfg(feature = "packet-diagnostics")]
    pub(super) async fn read_packet_diagnostic(
        &mut self,
        flow: &'static str,
        remote_addr: SocketAddr,
        phase: &str,
    ) -> Result<Option<EmuleTcpPacket>> {
        self.read_capture = Some(Ed2kTcpReadCapture::default());
        let result = self.read_packet().await;
        let capture = self
            .read_capture
            .take()
            .expect("diagnostic read capture must remain active");
        if let Ok(Some(packet)) = result.as_ref() {
            super::dump::dump_ed2k_tcp_recv_capture(
                flow,
                remote_addr,
                self.mode,
                phase,
                packet,
                &capture.raw,
                &capture.clear_frame,
            );
        } else if let Err(error) = result.as_ref() {
            super::dump::dump_ed2k_tcp_recv_failure(
                flow,
                remote_addr,
                self.mode,
                phase,
                &capture.raw,
                &capture.clear_frame,
                format!("{error:#}"),
            );
        }
        result
    }

    #[cfg(not(feature = "packet-diagnostics"))]
    pub(super) async fn read_packet_diagnostic(
        &mut self,
        _flow: &'static str,
        _remote_addr: SocketAddr,
        _phase: &str,
    ) -> Result<Option<EmuleTcpPacket>> {
        self.read_packet().await
    }

    pub(super) async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(cipher) = self.send_cipher.as_mut() {
            self.write_buf.clear();
            self.write_buf.extend_from_slice(bytes);
            cipher.apply(&mut self.write_buf);
            self.stream.write_all(&self.write_buf).await?;
        } else {
            self.stream.write_all(bytes).await?;
        }
        Ok(())
    }

    #[cfg(feature = "packet-diagnostics")]
    pub(super) async fn write_all_diagnostic(
        &mut self,
        flow: &'static str,
        remote_addr: SocketAddr,
        phase: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let obfuscated = self.send_cipher.is_some();
        if let Some(cipher) = self.send_cipher.as_mut() {
            self.write_buf.clear();
            self.write_buf.extend_from_slice(bytes);
            cipher.apply(&mut self.write_buf);
        }
        let wire_bytes = if obfuscated {
            self.write_buf.as_slice()
        } else {
            bytes
        };
        let (written_len, result) = write_with_progress(&mut self.stream, wire_bytes).await;
        let outcome = if result.is_ok() {
            "send_succeeded"
        } else {
            "send_failed"
        };
        let detail = result.as_ref().err().map(ToString::to_string);
        super::dump::dump_ed2k_tcp_send_capture(
            flow,
            remote_addr,
            self.mode,
            phase,
            bytes,
            &wire_bytes[..written_len],
            wire_bytes.len(),
            outcome,
            detail,
        );
        result.map_err(Into::into)
    }

    #[cfg(not(feature = "packet-diagnostics"))]
    pub(super) async fn write_all_diagnostic(
        &mut self,
        _flow: &'static str,
        _remote_addr: SocketAddr,
        _phase: &str,
        bytes: &[u8],
    ) -> Result<()> {
        self.write_all(bytes).await
    }

    /// Pull the next chunk off the socket into the (fully consumed) read
    /// buffer, decrypting it in place. Returns the byte count; 0 means EOF.
    ///
    /// Cancellation-safe: sessions wrap `read_packet` in timeouts and keep
    /// reading the same transport afterwards, so the buffer must never hold
    /// uninitialized "valid" bytes across a cancelled await. `read_buf`
    /// appends into spare capacity and only advances the length when the read
    /// completes; a cancelled fill leaves the (empty) buffer untouched.
    async fn fill_read_buf(&mut self) -> io::Result<usize> {
        debug_assert_eq!(self.read_pos, self.read_buf.len());
        self.read_buf.clear();
        self.read_pos = 0;
        self.read_buf.reserve(READ_BUFFER_CHUNK);
        let received = self.stream.read_buf(&mut self.read_buf).await?;
        #[cfg(feature = "packet-diagnostics")]
        {
            self.read_wire_buf.clear();
            self.read_wire_buf.extend_from_slice(&self.read_buf);
        }
        if received > 0
            && let Some(cipher) = self.receive_cipher.as_mut()
        {
            cipher.apply(&mut self.read_buf);
        }
        Ok(received)
    }

    async fn read_u8(&mut self) -> Result<Option<u8>> {
        if let Some(byte) = self.prefetched.pop_front() {
            #[cfg(feature = "packet-diagnostics")]
            if let Some(capture) = self.read_capture.as_mut() {
                capture.raw.push(byte);
                capture.clear_frame.push(byte);
            }
            return Ok(Some(byte));
        }
        if self.read_pos == self.read_buf.len() {
            match self.fill_read_buf().await {
                // EOF on a packet boundary is a clean close.
                Ok(0) => return Ok(None),
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let byte = self.read_buf[self.read_pos];
        #[cfg(feature = "packet-diagnostics")]
        if let Some(capture) = self.read_capture.as_mut() {
            capture.raw.push(self.read_wire_buf[self.read_pos]);
            capture.clear_frame.push(byte);
        }
        self.read_pos += 1;
        Ok(Some(byte))
    }

    async fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            if let Some(byte) = self.prefetched.pop_front() {
                bytes[offset] = byte;
                #[cfg(feature = "packet-diagnostics")]
                if let Some(capture) = self.read_capture.as_mut() {
                    capture.raw.push(byte);
                    capture.clear_frame.push(byte);
                }
                offset += 1;
            } else {
                break;
            }
        }
        while offset < bytes.len() {
            let buffered = self.read_buf.len() - self.read_pos;
            if buffered == 0 {
                // A large remainder (payload body) skips the copy through the
                // buffer: read it directly and decrypt in place.
                if bytes.len() - offset >= READ_BUFFER_CHUNK {
                    while offset < bytes.len() {
                        let received = self.stream.read(&mut bytes[offset..]).await?;
                        if received == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eD2k stream closed mid-frame",
                            )
                            .into());
                        }
                        #[cfg(feature = "packet-diagnostics")]
                        let raw = self
                            .read_capture
                            .as_ref()
                            .map(|_| bytes[offset..offset + received].to_vec());
                        if let Some(cipher) = self.receive_cipher.as_mut() {
                            cipher.apply(&mut bytes[offset..offset + received]);
                        }
                        #[cfg(feature = "packet-diagnostics")]
                        if let (Some(capture), Some(raw)) = (self.read_capture.as_mut(), raw) {
                            capture.raw.extend_from_slice(&raw);
                            capture
                                .clear_frame
                                .extend_from_slice(&bytes[offset..offset + received]);
                        }
                        offset += received;
                    }
                    return Ok(());
                }
                if self.fill_read_buf().await? == 0 {
                    // Mid-frame EOF: same error shape the unbuffered
                    // `read_exact` produced.
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "eD2k stream closed mid-frame",
                    )
                    .into());
                }
                continue;
            }
            let take = buffered.min(bytes.len() - offset);
            bytes[offset..offset + take]
                .copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
            #[cfg(feature = "packet-diagnostics")]
            if let Some(capture) = self.read_capture.as_mut() {
                capture
                    .raw
                    .extend_from_slice(&self.read_wire_buf[self.read_pos..self.read_pos + take]);
                capture
                    .clear_frame
                    .extend_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
            }
            self.read_pos += take;
            offset += take;
        }
        Ok(())
    }
}

#[cfg(feature = "packet-diagnostics")]
async fn write_with_progress(stream: &mut TcpStream, bytes: &[u8]) -> (usize, io::Result<()>) {
    let mut written = 0usize;
    while written < bytes.len() {
        match stream.write(&bytes[written..]).await {
            Ok(0) => {
                return (
                    written,
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write complete eD2k frame",
                    )),
                );
            }
            Ok(count) => written += count,
            Err(error) => return (written, Err(error)),
        }
    }
    (written, Ok(()))
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
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let stream = connect.await.unwrap();
        (
            Ed2kTransport::from_parts(
                stream,
                prefetched.into(),
                None,
                None,
                Ed2kTransportMode::Plaintext,
            ),
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
    async fn buffered_reads_frame_multiple_packets_from_one_burst() {
        use tokio::io::AsyncWriteExt as _;
        let (mut transport, mut server) = transport_with_prefetched(Vec::new()).await;
        // Two packets sent as one burst: the buffered reader must frame both
        // (the second packet's bytes arrive inside the first fill).
        let mut burst = header(OP_EDONKEYPROT, 4, OP_HELLO);
        burst.extend_from_slice(&[1, 2, 3]);
        burst.extend(header(OP_EMULEPROT, 3, 0x42));
        burst.extend_from_slice(&[9, 8]);
        server.write_all(&burst).await.unwrap();

        let first = transport.read_packet().await.unwrap().unwrap();
        assert_eq!((first.protocol, first.opcode), (OP_EDONKEYPROT, OP_HELLO));
        assert_eq!(first.payload, vec![1, 2, 3]);
        let second = transport.read_packet().await.unwrap().unwrap();
        assert_eq!((second.protocol, second.opcode), (OP_EMULEPROT, 0x42));
        assert_eq!(second.payload, vec![9, 8]);

        // Clean EOF at a packet boundary stays a clean close.
        drop(server);
        assert!(transport.read_packet().await.unwrap().is_none());
    }

    #[cfg(feature = "packet-diagnostics")]
    #[tokio::test]
    async fn diagnostic_capture_preserves_obfuscated_wire_and_clear_frame() {
        use super::super::derive_obfuscation_key;
        use tokio::io::AsyncWriteExt as _;

        let (mut transport, mut server) = transport_with_prefetched(Vec::new()).await;
        let user_hash = [0x31; 16];
        let random_key_part = [0x41, 0x42, 0x43, 0x44];
        let mut sender_cipher = derive_obfuscation_key(user_hash, 0x12, random_key_part);
        transport.receive_cipher = Some(derive_obfuscation_key(user_hash, 0x12, random_key_part));
        transport.mode = Ed2kTransportMode::Obfuscated;

        let mut clear_frame = header(OP_EDONKEYPROT, 4, OP_HELLO);
        clear_frame.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let mut raw = clear_frame.clone();
        sender_cipher.apply(&mut raw);
        server.write_all(&raw).await.unwrap();

        transport.read_capture = Some(Ed2kTcpReadCapture::default());
        let packet = transport.read_packet().await.unwrap().unwrap();
        let capture = transport.read_capture.take().unwrap();

        assert_eq!(packet.payload, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(capture.raw, raw);
        assert_eq!(capture.clear_frame, clear_frame);
        assert_ne!(capture.raw, capture.clear_frame);
    }

    #[cfg(feature = "packet-diagnostics")]
    #[tokio::test]
    async fn diagnostic_capture_preserves_rejected_packed_frame() {
        use tokio::io::AsyncWriteExt as _;

        let (mut transport, mut server) = transport_with_prefetched(Vec::new()).await;
        let mut frame = header(OP_PACKEDPROT, 4, OP_HELLO);
        frame.extend_from_slice(&[0x01, 0x02, 0x03]);
        server.write_all(&frame).await.unwrap();

        transport.read_capture = Some(Ed2kTcpReadCapture::default());
        let error = transport
            .read_packet()
            .await
            .expect_err("invalid packed payload must be rejected");
        let capture = transport.read_capture.take().unwrap();

        assert!(
            error.to_string().contains("zlib"),
            "unexpected error: {error}"
        );
        assert_eq!(capture.raw, frame);
        assert_eq!(capture.clear_frame, frame);
    }

    #[cfg(feature = "packet-diagnostics")]
    #[tokio::test]
    async fn diagnostic_capture_preserves_partial_large_payload_before_eof() {
        use tokio::io::AsyncWriteExt as _;

        let payload_len = READ_BUFFER_CHUNK;
        let packet_length = u32::try_from(payload_len + 1).unwrap();
        let header = header(OP_EDONKEYPROT, packet_length, OP_HELLO);
        let partial_payload = vec![0x5A; 1024];
        let (mut transport, mut server) = transport_with_prefetched(header.clone()).await;
        server.write_all(&partial_payload).await.unwrap();
        drop(server);

        transport.read_capture = Some(Ed2kTcpReadCapture::default());
        let error = transport
            .read_packet()
            .await
            .expect_err("partial large payload must end with EOF");
        let capture = transport.read_capture.take().unwrap();
        let mut expected = header;
        expected.extend_from_slice(&partial_payload);

        assert!(
            error.to_string().contains("closed mid-frame"),
            "unexpected error: {error}"
        );
        assert_eq!(capture.raw, expected);
        assert_eq!(capture.clear_frame, expected);
    }

    #[cfg(feature = "packet-diagnostics")]
    #[tokio::test]
    async fn diagnostic_send_writes_exact_obfuscated_frame() {
        use super::super::derive_obfuscation_key;
        use tokio::io::AsyncReadExt as _;

        let (mut transport, mut server) = transport_with_prefetched(Vec::new()).await;
        let user_hash = [0x51; 16];
        let random_key_part = [0x61, 0x62, 0x63, 0x64];
        let mut expected_cipher = derive_obfuscation_key(user_hash, 0x12, random_key_part);
        transport.send_cipher = Some(derive_obfuscation_key(user_hash, 0x12, random_key_part));
        transport.mode = Ed2kTransportMode::Obfuscated;

        let mut clear_frame = header(OP_EDONKEYPROT, 4, OP_HELLO);
        clear_frame.extend_from_slice(&[0xCA, 0xFE, 0x01]);
        let mut expected_raw = clear_frame.clone();
        expected_cipher.apply(&mut expected_raw);
        let remote_addr = server.local_addr().unwrap();

        transport
            .write_all_diagnostic("test", remote_addr, "send", &clear_frame)
            .await
            .unwrap();
        let mut actual_raw = vec![0u8; expected_raw.len()];
        server.read_exact(&mut actual_raw).await.unwrap();

        assert_eq!(actual_raw, expected_raw);
        assert_ne!(actual_raw, clear_frame);
    }

    #[tokio::test]
    async fn timed_out_idle_read_keeps_the_transport_usable() {
        use tokio::io::AsyncWriteExt as _;
        // Sessions wrap read_packet in timeouts and keep reading afterwards
        // (queue-waiting peers). A cancelled idle wait must not corrupt the
        // read buffer: the next read still frames the next packet exactly.
        let (mut transport, mut server) = transport_with_prefetched(Vec::new()).await;
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            transport.read_packet(),
        )
        .await;
        assert!(timed_out.is_err(), "idle read must time out");

        let mut packet = header(OP_EDONKEYPROT, 2, OP_HELLO);
        packet.push(0x7F);
        server.write_all(&packet).await.unwrap();
        let read = transport.read_packet().await.unwrap().unwrap();
        assert_eq!((read.protocol, read.opcode), (OP_EDONKEYPROT, OP_HELLO));
        assert_eq!(read.payload, vec![0x7F]);
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
