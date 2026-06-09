#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid node ID")]
    InvalidNodeId,
    #[error("unknown tag type: {0:#x}")]
    UnknownTagType(u8),
    #[error("unknown opcode: {0:#x}")]
    UnknownOpcode(u8),
    #[error("invalid protocol byte: {0:#x}")]
    InvalidProtocol(u8),
    #[error("binrw error: {0}")]
    BinRw(#[from] binrw::Error),
    #[error("invalid UTF-8 in tag string")]
    InvalidUtf8,
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid packet size for opcode {opcode:#x}: expected {expected}, got {actual}")]
    InvalidPacketSize {
        opcode: u8,
        expected: usize,
        actual: usize,
    },
    #[error("zlib decompression failed")]
    DecompressError,
}
