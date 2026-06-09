use std::net::SocketAddr;

/// Kad transport-layer failures surfaced by `emulebb-kad-net`.
///
/// These errors sit at the UDP/RPC boundary: socket I/O, packet decode,
/// timeout handling, and the oracle-shaped flood tracker.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Raw socket I/O failed while reading or writing a datagram.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The datagram decoded to an invalid Kad wire shape.
    #[error("protocol error: {0}")]
    Proto(#[from] emulebb_kad_proto::ProtoError),
    /// An outbound request expired before the expected response arrived.
    #[error("request timed out after {secs}s to {addr}")]
    Timeout { addr: SocketAddr, secs: u64 },
    /// An internal response or control channel closed unexpectedly.
    #[error("channel closed")]
    ChannelClosed,
    /// The local outbound rate limiter rejected the send attempt.
    #[error("rate limited")]
    RateLimited,
    /// The datagram was too short to be a valid Kad UDP frame.
    #[error("packet too short ({len} bytes)")]
    PacketTooShort { len: usize },
    /// The oracle-style packet tracker rejected this peer as currently flooded.
    #[error("peer {0} is flood-blocked")]
    FloodBlocked(std::net::IpAddr),
}
