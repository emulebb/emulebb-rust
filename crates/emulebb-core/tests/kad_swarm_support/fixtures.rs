use emulebb_kad_proto::{Ed2kHash, NodeId};

pub fn node_id(byte: u8) -> NodeId {
    NodeId::from_bytes([byte; 16])
}

pub fn file_hash(byte: u8) -> Ed2kHash {
    Ed2kHash::from_bytes([byte; 16])
}
