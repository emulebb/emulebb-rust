use std::fmt;
use std::str::FromStr;

use binrw::{BinRead, BinWrite};

use crate::error::ProtoError;

/// A 128-bit Kademlia node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BinRead, BinWrite)]
#[brw(little)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    pub const ZERO: NodeId = NodeId([0u8; 16]);

    #[must_use]
    pub fn from_bytes(b: [u8; 16]) -> Self {
        NodeId(b)
    }

    /// Construct a Kad ID from canonical big-endian chunk bytes such as raw
    /// MD4/file-hash bytes or eMule `ToHexString()` output.
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; 16]) -> Self {
        let mut wire = [0u8; 16];
        for chunk_idx in 0..4 {
            let start = chunk_idx * 4;
            wire[start..start + 4].copy_from_slice(&[
                bytes[start + 3],
                bytes[start + 2],
                bytes[start + 1],
                bytes[start],
            ]);
        }
        NodeId(wire)
    }

    /// Decode one eMule `CUInt128` chunk from the raw Kad wire/storage layout.
    #[must_use]
    pub fn chunk_u32(self, index: usize) -> u32 {
        let start = index * 4;
        u32::from_le_bytes([
            self.0[start],
            self.0[start + 1],
            self.0[start + 2],
            self.0[start + 3],
        ])
    }

    /// Convert the raw Kad wire/storage layout back into canonical big-endian
    /// chunk bytes such as MD4/file-hash order.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for chunk_idx in 0..4 {
            let start = chunk_idx * 4;
            bytes[start..start + 4].copy_from_slice(&[
                self.0[start + 3],
                self.0[start + 2],
                self.0[start + 1],
                self.0[start],
            ]);
        }
        bytes
    }

    /// XOR distance between two node IDs.
    #[must_use]
    pub fn distance(&self, other: &Self) -> NodeId {
        let mut result = [0u8; 16];
        for (index, slot) in result.iter_mut().enumerate() {
            *slot = self.0[index] ^ other.0[index];
        }
        NodeId(result)
    }

    /// Index of the highest set bit in the XOR distance (0 = MSB of byte 0).
    /// Returns None if XOR is all zeros (same node).
    #[must_use]
    pub fn distance_exp(&self, other: &Self) -> Option<u32> {
        let xor = self.distance(other);
        for chunk_idx in 0..4 {
            let chunk = xor.chunk_u32(chunk_idx);
            if chunk != 0 {
                return Some(chunk_idx as u32 * 32 + chunk.leading_zeros());
            }
        }
        None
    }

    /// Returns the bit at position `pos` (0 = MSB of byte 0).
    #[must_use]
    pub fn bit(&self, pos: u32) -> bool {
        let chunk_idx = (pos / 32) as usize;
        if chunk_idx >= 4 {
            return false;
        }
        let bit_idx = 31 - (pos % 32);
        (self.chunk_u32(chunk_idx) >> bit_idx) & 1 == 1
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk_idx in 0..4 {
            write!(f, "{:08x}", self.chunk_u32(chunk_idx))?;
        }
        Ok(())
    }
}

impl FromStr for NodeId {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 {
            return Err(ProtoError::InvalidNodeId);
        }
        let mut bytes = [0u8; 16];
        for chunk_idx in 0..4 {
            let start = chunk_idx * 8;
            let chunk = u32::from_str_radix(&s[start..start + 8], 16)
                .map_err(|_| ProtoError::InvalidNodeId)?;
            bytes[chunk_idx * 4..chunk_idx * 4 + 4].copy_from_slice(&chunk.to_be_bytes());
        }
        Ok(NodeId::from_be_bytes(bytes))
    }
}

impl PartialOrd for NodeId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for chunk_idx in 0..4 {
            let ordering = self.chunk_u32(chunk_idx).cmp(&other.chunk_u32(chunk_idx));
            if ordering != std::cmp::Ordering::Equal {
                return ordering;
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(hex: &str) -> NodeId {
        hex.parse().unwrap()
    }

    #[test]
    fn test_zero() {
        assert_eq!(NodeId::ZERO.0, [0u8; 16]);
    }

    #[test]
    fn test_distance_zero() {
        let a = make_id("0102030405060708090a0b0c0d0e0f10");
        let dist = a.distance(&a);
        assert_eq!(dist, NodeId::ZERO);
    }

    #[test]
    fn test_distance_xor() {
        let a = NodeId::from_bytes([0xFF; 16]);
        let b = NodeId::from_bytes([0x0F; 16]);
        let d = a.distance(&b);
        assert_eq!(d.0[0], 0xF0);
    }

    #[test]
    fn test_distance_exp_none_for_equal() {
        let a = make_id("aabbccddeeff00112233445566778899");
        assert_eq!(a.distance_exp(&a), None);
    }

    #[test]
    fn test_distance_exp_msb() {
        // XOR chunk0 = 0x80000000 => highest bit at position 0
        let a = make_id("80000000000000000000000000000000");
        let b = NodeId::ZERO;
        assert_eq!(a.distance_exp(&b), Some(0));
    }

    #[test]
    fn test_distance_exp_second_byte() {
        // XOR chunk0 = 0x00800000 => highest bit at position 8
        let a = make_id("00800000000000000000000000000000");
        let b = NodeId::ZERO;
        assert_eq!(a.distance_exp(&b), Some(8));
    }

    #[test]
    fn test_distance_exp_lsb() {
        // XOR chunk3 = 0x00000001 => bit at position 127
        let a = make_id("00000000000000000000000000000001");
        let b = NodeId::ZERO;
        assert_eq!(a.distance_exp(&b), Some(127));
    }

    #[test]
    fn test_bit() {
        // chunk0 = 0x80000000 => bit 0 = 1, bit 1 = 0
        let a = make_id("80000000000000000000000000000000");
        assert!(a.bit(0));
        assert!(!a.bit(1));
        assert!(!a.bit(8));
    }

    #[test]
    fn test_bit_second_byte() {
        // chunk0 = 0x00010000 => bit 15 = 1
        let a = make_id("00010000000000000000000000000000");
        assert!(!a.bit(8));
        assert!(a.bit(15));
    }

    #[test]
    fn test_display() {
        let a = NodeId::from_bytes([
            0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f,
            0x0e, 0x0d,
        ]);
        assert_eq!(format!("{a}"), "0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn test_from_str_roundtrip() {
        let hex = "0102030405060708090a0b0c0d0e0f10";
        let id: NodeId = hex.parse().unwrap();
        assert_eq!(format!("{id}"), hex);
        assert_eq!(
            id.0,
            [
                0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f,
                0x0e, 0x0d,
            ]
        );
    }

    #[test]
    fn test_from_be_bytes_matches_emule_wire_layout() {
        let id = NodeId::from_be_bytes([
            0x2a, 0x85, 0xd7, 0xa5, 0x6b, 0x40, 0x4d, 0x26, 0x4a, 0x2a, 0x68, 0x2d, 0xd1, 0xb6,
            0x8f, 0xa8,
        ]);
        assert_eq!(
            id.0,
            [
                0xa5, 0xd7, 0x85, 0x2a, 0x26, 0x4d, 0x40, 0x6b, 0x2d, 0x68, 0x2a, 0x4a, 0xa8, 0x8f,
                0xb6, 0xd1,
            ]
        );
        assert_eq!(id.to_string(), "2a85d7a56b404d264a2a682dd1b68fa8");
    }

    #[test]
    fn test_to_be_bytes_roundtrip() {
        let canonical = [
            0x2a, 0x85, 0xd7, 0xa5, 0x6b, 0x40, 0x4d, 0x26, 0x4a, 0x2a, 0x68, 0x2d, 0xd1, 0xb6,
            0x8f, 0xa8,
        ];
        assert_eq!(NodeId::from_be_bytes(canonical).to_be_bytes(), canonical);
    }

    #[test]
    fn test_from_str_invalid() {
        assert!("short".parse::<NodeId>().is_err());
        assert!(
            "gggggggggggggggggggggggggggggggg"
                .parse::<NodeId>()
                .is_err()
        );
    }

    #[test]
    fn test_ord() {
        let a = NodeId::from_bytes([0x00; 16]);
        let b = make_id("00000001000000000000000000000000");
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn test_ord_uses_emule_chunk_order_not_raw_byte_order() {
        let smaller = make_id("00000001000000000000000000000000");
        let larger = make_id("00000100000000000000000000000000");
        assert!(smaller < larger);
    }

    #[test]
    fn test_binrw_roundtrip() {
        use binrw::{BinRead, BinWrite};
        use std::io::Cursor;

        let id = NodeId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let mut buf = Cursor::new(Vec::new());
        id.write_le(&mut buf).unwrap();
        buf.set_position(0);
        let id2 = NodeId::read_le(&mut buf).unwrap();
        assert_eq!(id, id2);
    }
}
