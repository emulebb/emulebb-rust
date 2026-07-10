use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use num_bigint::BigUint;
use rand::{Rng, RngCore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::RwLock,
};
use tracing::debug;

use crate::ed2k_tcp::MAX_ED2K_PACKET_LEN;

use super::{
    EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_TCP_CRYPT_MAGIC_REQUESTER,
    EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC, Ed2kServerState, OP_EDONKEYPROT,
    OP_PACKEDPROT, Rc4KeyStream, SERVER_OBFUSCATION_MAX_PADDING_LEN,
    SERVER_OBFUSCATION_PRIME_BYTES, SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
    SERVER_OBFUSCATION_RANDOM_EXPONENT_LEN, SERVER_TCP_FLAG_COMPRESSION, TCP_PACKET_HEADER_LEN,
    biguint_to_fixed_be, decode_server_payload, derive_server_cipher, dump_ed2k_server_meta,
    dump_ed2k_server_packet, encode_packet, random_non_protocol_marker, random_nonzero_biguint,
    server_opcode_allows_compression,
};

static NEXT_SERVER_SESSION_TRACE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(super) struct Ed2kPacket {
    pub(super) opcode: u8,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServerSessionPhase {
    Connecting,
    AwaitingIdChange,
    Connected,
    OfferFilesSent,
    SearchActive,
    AwaitingMore,
    Completed,
}

impl ServerSessionPhase {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::AwaitingIdChange => "awaiting_idchange",
            Self::Connected => "connected",
            Self::OfferFilesSent => "offer_files_sent",
            Self::SearchActive => "search_active",
            Self::AwaitingMore => "awaiting_more",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug)]
pub(super) struct ServerSession {
    stream: TcpStream,
    pub(super) endpoint: SocketAddr,
    pub(super) state: Arc<RwLock<Ed2kServerState>>,
    pub(super) trace_id: u64,
    pub(super) trace_role: &'static str,
    pub(super) last_tx: Instant,
    pub(super) receive_cipher: Option<Rc4KeyStream>,
    pub(super) send_cipher: Option<Rc4KeyStream>,
    pub(super) login_accepted: bool,
    pub(super) probe_search_sent: bool,
    pub(super) offer_files_sent: bool,
    pub(super) offer_files_sent_at: Option<Instant>,
    pub(super) offer_files_catalog_fingerprint: Option<u64>,
    pub(super) offer_files_catalog_cursor: usize,
    pub(super) offer_files_published_hashes: HashSet<[u8; 16]>,
    pub(super) assigned_client_id: Option<u32>,
    pub(super) server_flags: Option<u32>,
    /// Soft file limit of the connected server (from the resolved entry); 0 when
    /// unknown. Caps the OP_OFFERFILES batch size (see `server_offer_file_limit`).
    pub(super) server_soft_files: u32,
    pub(super) server_list_requested: bool,
    pub(super) phase: ServerSessionPhase,
}

impl ServerSession {
    pub(super) async fn connect(
        bind_ip: Ipv4Addr,
        endpoint: SocketAddr,
        state: Arc<RwLock<Ed2kServerState>>,
        trace_role: &'static str,
        timeout: Duration,
    ) -> Result<Self> {
        {
            let mut guard = state.write().await;
            guard.connecting = true;
            guard.connected = false;
            guard.endpoint = Some(endpoint);
        }
        let stream = match async {
            let socket = TcpSocket::new_v4().context("failed to create ED2K server TCP socket")?;
            socket
                .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
                .with_context(|| format!("failed to bind ED2K server socket to {bind_ip}"))?;
            let bind_if_index =
                crate::networking::require_bind_if_index(bind_ip, "ED2K server TCP")?;
            // Egress-pin to the VPN tunnel interface (IP_UNICAST_IF) before connect
            // so the server session leaves via the tunnel — solid VPN binding.
            emulebb_kad_dht::socket_opts::pin_egress_to_interface(
                socket2::SockRef::from(&socket),
                Some(bind_if_index),
            )
            .with_context(|| format!("failed to pin ED2K server egress for {bind_ip}"))?;
            let stream = tokio::time::timeout(timeout, socket.connect(endpoint))
                .await
                .with_context(|| format!("timed out connecting to ED2K server {endpoint}"))??;
            stream.set_nodelay(true).with_context(|| {
                format!("failed to enable TCP_NODELAY for ED2K server {endpoint}")
            })?;
            Ok::<TcpStream, anyhow::Error>(stream)
        }
        .await
        {
            Ok(stream) => stream,
            Err(error) => {
                let mut guard = state.write().await;
                if guard.connecting && guard.endpoint == Some(endpoint) {
                    guard.connecting = false;
                    guard.endpoint = None;
                }
                return Err(error);
            }
        };
        let trace_id = NEXT_SERVER_SESSION_TRACE_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            stream,
            endpoint,
            state,
            trace_id,
            trace_role,
            last_tx: Instant::now(),
            receive_cipher: None,
            send_cipher: None,
            login_accepted: false,
            probe_search_sent: false,
            offer_files_sent: false,
            offer_files_sent_at: None,
            offer_files_catalog_fingerprint: None,
            offer_files_catalog_cursor: 0,
            offer_files_published_hashes: HashSet::new(),
            assigned_client_id: None,
            server_flags: None,
            server_soft_files: 0,
            server_list_requested: false,
            phase: ServerSessionPhase::Connecting,
        })
    }

    #[cfg(test)]
    pub(super) fn from_stream_for_test(stream: TcpStream, endpoint: SocketAddr) -> Self {
        let trace_id = NEXT_SERVER_SESSION_TRACE_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            stream,
            endpoint,
            state: Arc::new(RwLock::new(Ed2kServerState::default())),
            trace_id,
            trace_role: "test",
            last_tx: Instant::now(),
            receive_cipher: None,
            send_cipher: None,
            login_accepted: false,
            probe_search_sent: false,
            offer_files_sent: false,
            offer_files_sent_at: None,
            offer_files_catalog_fingerprint: None,
            offer_files_catalog_cursor: 0,
            offer_files_published_hashes: HashSet::new(),
            assigned_client_id: None,
            server_flags: None,
            server_soft_files: 0,
            server_list_requested: false,
            phase: ServerSessionPhase::Connecting,
        }
    }

    pub(super) fn set_phase(&mut self, phase: ServerSessionPhase, note: impl Into<String>) {
        self.phase = phase;
        dump_ed2k_server_meta(self, note);
    }

    pub(super) async fn send_packet(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        // Only OP_OFFERFILES is packed on the server-TCP path, and only when the
        // server advertised SRV_TCPFLG_COMPRESSION; every other server-bound opcode
        // (OP_SEARCHREQUEST, OP_GETSOURCES, OP_GETSERVERLIST, OP_QUERY_MORE_RESULT,
        // OP_CALLBACKREQUEST, OP_LOGINREQUEST, keepalive) is sent uncompressed as
        // OP_EDONKEYPROT (0xE3). Matches CSharedFileList::SendListToServer
        // (SharedFileList.cpp:2723-2725), the sole server-bound PackPacket() call.
        let use_compression =
            server_opcode_allows_compression(opcode) && self.server_supports_compression();
        let mut packet = encode_packet(opcode, payload, use_compression)?;
        // The wire may still be OP_EDONKEYPROT even when compression was permitted
        // (keep-if-smaller left the packet raw): report the actual protocol byte.
        let packed = packet[0] == OP_PACKEDPROT;
        debug!(
            "ED2K trace id={} role={} phase={} dir=tx endpoint={} opcode=0x{:02X} payload_len={} wire_len={} compressed={}",
            self.trace_id,
            self.trace_role,
            self.phase.as_str(),
            self.endpoint,
            opcode,
            payload.len(),
            packet.len(),
            packed
        );
        dump_ed2k_server_packet(self, "tx", packet[0], opcode, payload);
        if let Some(cipher) = self.send_cipher.as_mut() {
            cipher.apply(&mut packet);
        }
        self.stream.write_all(&packet).await.with_context(|| {
            format!("failed to send opcode=0x{opcode:02X} to {}", self.endpoint)
        })?;
        self.last_tx = Instant::now();
        Ok(())
    }

    pub(super) async fn send_encoded_packet(
        &mut self,
        packet: &[u8],
        context: impl Into<String>,
    ) -> Result<()> {
        self.stream
            .write_all(packet)
            .await
            .with_context(|| context.into())?;
        self.last_tx = Instant::now();
        Ok(())
    }

    fn server_supports_compression(&self) -> bool {
        self.server_flags.unwrap_or_default() & SERVER_TCP_FLAG_COMPRESSION != 0
    }

    pub(super) async fn negotiate_obfuscation_and_send(
        &mut self,
        first_packet: &[u8],
    ) -> Result<()> {
        let prime = BigUint::from_bytes_be(&SERVER_OBFUSCATION_PRIME_BYTES);
        let generator = BigUint::from(2u8);
        let secret = random_nonzero_biguint(SERVER_OBFUSCATION_RANDOM_EXPONENT_LEN);
        let public = generator.modpow(&secret, &prime);
        let public_bytes = biguint_to_fixed_be(&public, SERVER_OBFUSCATION_PUBLIC_KEY_LEN)?;

        let mut request = Vec::with_capacity(1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 16);
        request.push(random_non_protocol_marker());
        request.extend_from_slice(&public_bytes);
        let initial_padding_len =
            rand::thread_rng().gen_range(0..=SERVER_OBFUSCATION_MAX_PADDING_LEN);
        request.push(u8::try_from(initial_padding_len).expect("padding length fits in u8"));
        let mut initial_padding = vec![0u8; initial_padding_len];
        rand::thread_rng().fill_bytes(&mut initial_padding);
        request.extend_from_slice(&initial_padding);
        self.stream.write_all(&request).await.with_context(|| {
            format!(
                "failed to send ED2K server obfuscation request to {}",
                self.endpoint
            )
        })?;

        let mut remote_public_bytes = [0u8; SERVER_OBFUSCATION_PUBLIC_KEY_LEN];
        self.stream
            .read_exact(&mut remote_public_bytes)
            .await
            .with_context(|| {
                format!(
                    "failed to read ED2K server obfuscation DH answer from {}",
                    self.endpoint
                )
            })?;
        let remote_public = BigUint::from_bytes_be(&remote_public_bytes);
        let shared_secret = remote_public.modpow(&secret, &prime);
        let shared_secret_bytes =
            biguint_to_fixed_be(&shared_secret, SERVER_OBFUSCATION_PUBLIC_KEY_LEN)?;
        let mut send_cipher =
            derive_server_cipher(&shared_secret_bytes, EMULE_TCP_CRYPT_MAGIC_REQUESTER);
        let mut receive_cipher =
            derive_server_cipher(&shared_secret_bytes, EMULE_TCP_CRYPT_MAGIC_SERVER);

        let mut encrypted_header = [0u8; 7];
        self.stream
            .read_exact(&mut encrypted_header)
            .await
            .with_context(|| {
                format!(
                    "failed to read ED2K server obfuscation header from {}",
                    self.endpoint
                )
            })?;
        receive_cipher.apply(&mut encrypted_header);
        let magic = u32::from_le_bytes(encrypted_header[..4].try_into().unwrap());
        if magic != EMULE_TCP_CRYPT_MAGIC_SYNC {
            anyhow::bail!(
                "unexpected ED2K server obfuscation magic 0x{magic:08X} from {}",
                self.endpoint
            );
        }
        let server_preferred = encrypted_header[5];
        if server_preferred != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
            debug!(
                "ED2K server {} preferred unsupported obfuscation method {}",
                self.endpoint, server_preferred
            );
        }
        let server_padding_len = usize::from(encrypted_header[6]);
        if server_padding_len > SERVER_OBFUSCATION_MAX_PADDING_LEN {
            debug!(
                "ED2K server {} sent {} obfuscation padding bytes",
                self.endpoint, server_padding_len
            );
        }
        if server_padding_len > 0 {
            let mut encrypted_padding = vec![0u8; server_padding_len];
            self.stream
                .read_exact(&mut encrypted_padding)
                .await
                .with_context(|| {
                    format!(
                        "failed to read ED2K server obfuscation padding from {}",
                        self.endpoint
                    )
                })?;
            receive_cipher.apply(&mut encrypted_padding);
        }

        // WHY: the obfuscated login path carries the first packet (the
        // OP_LOGINREQUEST) inside the crypt-negotiation response, bypassing
        // send_packet() and therefore its dump hook — live server dumps showed
        // OP_IDCHANGE recvs with no matching login send. Dump it here exactly
        // like the plain path does (plaintext opcode + payload, pre-cipher).
        if first_packet.len() >= TCP_PACKET_HEADER_LEN {
            dump_ed2k_server_packet(
                self,
                "tx",
                first_packet[0],
                first_packet[5],
                &first_packet[TCP_PACKET_HEADER_LEN..],
            );
        }
        let response_padding_len =
            rand::thread_rng().gen_range(0..=SERVER_OBFUSCATION_MAX_PADDING_LEN);
        let mut response = Vec::with_capacity(6 + response_padding_len + first_packet.len());
        response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        response.push(u8::try_from(response_padding_len).expect("padding length fits in u8"));
        let mut response_padding = vec![0u8; response_padding_len];
        rand::thread_rng().fill_bytes(&mut response_padding);
        response.extend_from_slice(&response_padding);
        response.extend_from_slice(first_packet);
        send_cipher.apply(&mut response);
        self.stream.write_all(&response).await.with_context(|| {
            format!(
                "failed to send ED2K server obfuscation response to {}",
                self.endpoint
            )
        })?;

        self.receive_cipher = Some(receive_cipher);
        self.send_cipher = Some(send_cipher);
        self.last_tx = Instant::now();
        dump_ed2k_server_meta(self, "server obfuscation negotiated");
        Ok(())
    }

    pub(super) async fn read_packet(&mut self) -> Result<Option<Ed2kPacket>> {
        let mut header = [0u8; TCP_PACKET_HEADER_LEN];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                debug!(
                    "ED2K trace id={} role={} phase={} dir=rx endpoint={} eof=true",
                    self.trace_id,
                    self.trace_role,
                    self.phase.as_str(),
                    self.endpoint
                );
                dump_ed2k_server_meta(self, "server session drop reason=eof");
                return Ok(None);
            }
            Err(error) => {
                dump_ed2k_server_meta(
                    self,
                    format!("server session drop reason=read_error detail={error}"),
                );
                return Err(error.into());
            }
        }
        if let Some(cipher) = self.receive_cipher.as_mut() {
            cipher.apply(&mut header);
        }

        if !matches!(header[0], OP_EDONKEYPROT | OP_PACKEDPROT) {
            dump_ed2k_server_meta(
                self,
                format!(
                    "server session drop reason=read_error detail=unsupported_protocol_0x{:02X}",
                    header[0]
                ),
            );
            anyhow::bail!(
                "unsupported ED2K server protocol 0x{:02X} from {}",
                header[0],
                self.endpoint
            );
        }

        let packet_length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        if packet_length == 0 {
            dump_ed2k_server_meta(
                self,
                "server session drop reason=read_error detail=invalid_packet_length_0",
            );
            anyhow::bail!("invalid ED2K server packet length 0");
        }
        let payload_len = match usize::try_from(packet_length - 1) {
            Ok(payload_len) => payload_len,
            Err(error) => {
                dump_ed2k_server_meta(
                    self,
                    format!("server session drop reason=read_error detail=length_overflow {error}"),
                );
                anyhow::bail!("server packet length overflow");
            }
        };
        if payload_len > MAX_ED2K_PACKET_LEN {
            dump_ed2k_server_meta(
                self,
                format!(
                    "server session drop reason=read_error detail=oversized_packet payload_len={payload_len} max={MAX_ED2K_PACKET_LEN}"
                ),
            );
            anyhow::bail!(
                "oversized ED2K server packet length {} exceeds {} from {}",
                payload_len,
                MAX_ED2K_PACKET_LEN,
                self.endpoint
            );
        }
        let mut payload = vec![0u8; payload_len];
        if let Err(error) = self.stream.read_exact(&mut payload).await {
            dump_ed2k_server_meta(
                self,
                format!("server session drop reason=read_error detail=payload_read {error}"),
            );
            return Err(error.into());
        }
        if let Some(cipher) = self.receive_cipher.as_mut() {
            cipher.apply(&mut payload);
        }
        let payload = match decode_server_payload(header[0], payload) {
            Ok(payload) => payload,
            Err(error) => {
                dump_ed2k_server_meta(
                    self,
                    format!("server session drop reason=read_error detail=decode {error}"),
                );
                return Err(error).with_context(|| {
                    format!("failed to decode ED2K server packet from {}", self.endpoint)
                });
            }
        };
        debug!(
            "ED2K trace id={} role={} phase={} dir=rx endpoint={} prot=0x{:02X} opcode=0x{:02X} payload_len={}",
            self.trace_id,
            self.trace_role,
            self.phase.as_str(),
            self.endpoint,
            header[0],
            header[5],
            payload.len()
        );
        dump_ed2k_server_packet(self, "rx", header[0], header[5], &payload);
        Ok(Some(Ed2kPacket {
            opcode: header[5],
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A peer that declares an oversized server packet length must be dropped
    /// before the payload buffer is allocated (raw-length cap mirroring
    /// `sizeof GlobalReadBuffer`), preventing an OOM denial of service.
    #[tokio::test]
    async fn server_read_rejects_oversized_declared_length() {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut peer = TcpStream::connect(addr).await.unwrap();
            // OP_EDONKEYPROT header declaring packet_length = 0xFFFFFFFF (~4GB).
            let mut header = vec![OP_EDONKEYPROT];
            header.extend_from_slice(&u32::MAX.to_le_bytes());
            header.push(OP_EDONKEYPROT); // opcode byte (value irrelevant)
            peer.write_all(&header).await.unwrap();
            // Keep the peer alive so the server reads the header, not EOF.
            peer
        });
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let _peer = writer.await.unwrap();
        let mut session = ServerSession::from_stream_for_test(stream, peer_addr);
        let err = session
            .read_packet()
            .await
            .expect_err("oversized server packet length must be rejected");
        assert!(
            err.to_string()
                .contains("oversized ED2K server packet length"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn server_connect_rolls_back_connecting_state_on_setup_failure() {
        let state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4661);

        let err = ServerSession::connect(
            Ipv4Addr::new(203, 0, 113, 200),
            endpoint,
            Arc::clone(&state),
            "test",
            Duration::from_millis(10),
        )
        .await
        .expect_err("non-local bind IP should fail before a session is established");

        let guard = state.read().await;
        assert!(
            !guard.connecting,
            "failed setup left server state connecting after {err}"
        );
        assert!(!guard.connected);
        assert!(guard.endpoint.is_none());
    }

    /// Establish a connected `ServerSession` (from the accepted end of a local
    /// pair) plus the remote peer stream that receives whatever the session sends.
    async fn connected_test_session_with_peer() -> (ServerSession, TcpStream) {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = TcpStream::connect(addr).await.unwrap();
        let (stream, peer_addr) = listener.accept().await.unwrap();
        (ServerSession::from_stream_for_test(stream, peer_addr), peer)
    }

    /// Read just the eD2k packet header (protocol + length + opcode) the session
    /// wrote to the wire.
    async fn read_wire_header(peer: &mut TcpStream) -> [u8; TCP_PACKET_HEADER_LEN] {
        let mut header = [0u8; TCP_PACKET_HEADER_LEN];
        peer.read_exact(&mut header).await.unwrap();
        header
    }

    /// RUST-PAR-019 R19-3: every server-bound opcode except OP_OFFERFILES is sent
    /// uncompressed (OP_EDONKEYPROT / 0xE3) even when the server advertised
    /// SRV_TCPFLG_COMPRESSION — eMule packs only OP_OFFERFILES toward the server
    /// (SharedFileList.cpp:2723-2725). The 512-zero payload is highly compressible,
    /// so a 0xE3 here proves the opcode gate rather than keep-if-smaller.
    #[tokio::test]
    async fn server_bound_non_offer_packets_stay_uncompressed_with_compression_flag() {
        use super::super::{OP_GETSOURCES, OP_SEARCHREQUEST};

        for opcode in [OP_SEARCHREQUEST, OP_GETSOURCES] {
            let (mut session, mut peer) = connected_test_session_with_peer().await;
            session.server_flags = Some(SERVER_TCP_FLAG_COMPRESSION);
            session.send_packet(opcode, &vec![0u8; 512]).await.unwrap();
            let header = read_wire_header(&mut peer).await;
            assert_eq!(
                header[0], OP_EDONKEYPROT,
                "opcode 0x{opcode:02X} must be sent as 0xE3, not packed",
            );
            assert_eq!(header[5], opcode);
        }
    }

    /// RUST-PAR-019 R19-3: OP_OFFERFILES is packed (0xD4) when the server supports
    /// compression and the packed form is strictly smaller (keep-if-smaller,
    /// Packets.cpp:259). A 512-zero payload compresses well below its raw size.
    #[tokio::test]
    async fn offer_files_is_packed_when_smaller_on_compression_server() {
        use super::super::OP_OFFERFILES;

        let (mut session, mut peer) = connected_test_session_with_peer().await;
        session.server_flags = Some(SERVER_TCP_FLAG_COMPRESSION);
        session
            .send_packet(OP_OFFERFILES, &vec![0u8; 512])
            .await
            .unwrap();
        let header = read_wire_header(&mut peer).await;
        assert_eq!(
            header[0], OP_PACKEDPROT,
            "compressible OP_OFFERFILES must pack"
        );
        assert_eq!(header[5], OP_OFFERFILES);
    }

    /// RUST-PAR-019 R19-3: the empty-share OP_OFFERFILES keepalive (a 4-byte
    /// zero-count payload) is NOT emitted as a larger packed packet — zlib expands
    /// it, so keep-if-smaller leaves it as OP_EDONKEYPROT (0xE3).
    #[tokio::test]
    async fn empty_offer_files_keepalive_is_not_packed() {
        use super::super::OP_OFFERFILES;

        let (mut session, mut peer) = connected_test_session_with_peer().await;
        session.server_flags = Some(SERVER_TCP_FLAG_COMPRESSION);
        session
            .send_packet(OP_OFFERFILES, &0u32.to_le_bytes())
            .await
            .unwrap();
        let header = read_wire_header(&mut peer).await;
        assert_eq!(
            header[0], OP_EDONKEYPROT,
            "0-file OP_OFFERFILES keepalive must stay uncompressed",
        );
        assert_eq!(header[5], OP_OFFERFILES);
    }
}
