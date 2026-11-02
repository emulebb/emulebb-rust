use std::fmt;
use std::str::FromStr;

use binrw::{BinRead, BinWrite};

use crate::error::ProtoError;

/// A 128-bit eMule eD2K hash in canonical MD4 byte order.
///
/// Kad packets serialize hash-valued `CUInt128` fields in eMule's native
/// four-little-endian-words layout. Use the explicit conversion methods below
/// at that wire boundary; application code always keeps canonical hash bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BinRead, BinWrite)]
#[brw(little)]
pub struct Ed2kHash(pub [u8; 16]);

impl Ed2kHash {
    pub const ZERO: Ed2kHash = Ed2kHash([0u8; 16]);

    #[must_use]
    pub fn from_bytes(b: [u8; 16]) -> Self {
        Ed2kHash(b)
    }

    /// Decode an eMule `CUInt128` hash field from Kad wire order.
    #[must_use]
    pub fn from_kad_uint128_wire_bytes(wire: [u8; 16]) -> Self {
        Self(swap_u32_byte_order(wire))
    }

    /// Encode this canonical hash as an eMule `CUInt128` Kad wire field.
    #[must_use]
    pub fn to_kad_uint128_wire_bytes(self) -> [u8; 16] {
        swap_u32_byte_order(self.0)
    }
}

fn swap_u32_byte_order(bytes: [u8; 16]) -> [u8; 16] {
    let mut swapped = [0u8; 16];
    for chunk in 0..4 {
        let start = chunk * 4;
        swapped[start..start + 4].copy_from_slice(&[
            bytes[start + 3],
            bytes[start + 2],
            bytes[start + 1],
            bytes[start],
        ]);
    }
    swapped
}

impl fmt::Display for Ed2kHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Ed2kHash {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 {
            return Err(ProtoError::InvalidNodeId);
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| ProtoError::InvalidNodeId)?;
        }
        Ok(Ed2kHash(bytes))
    }
}

impl PartialOrd for Ed2kHash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ed2kHash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// Per-sender anti-spoofing key used in Kad2 obfuscated transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BinRead, BinWrite)]
#[brw(little)]
pub struct KadUdpKey(pub u32);

impl KadUdpKey {
    pub const ZERO: KadUdpKey = KadUdpKey(0);

    #[must_use]
    pub fn new(key: u32) -> Self {
        KadUdpKey(key)
    }

    #[must_use]
    pub fn value(&self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::{BinRead, BinWrite};
    use std::io::Cursor;

    #[test]
    fn test_ed2k_zero() {
        assert_eq!(Ed2kHash::ZERO.0, [0u8; 16]);
    }

    #[test]
    fn test_ed2k_display() {
        let h = Ed2kHash::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        assert_eq!(format!("{h}"), "0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn test_ed2k_from_str_roundtrip() {
        let hex = "aabbccddeeff00112233445566778899";
        let h: Ed2kHash = hex.parse().unwrap();
        assert_eq!(format!("{h}"), hex);
    }

    #[test]
    fn test_ed2k_ord() {
        let a = Ed2kHash::ZERO;
        let b = Ed2kHash::from_bytes([0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(a < b);
    }

    #[test]
    fn test_ed2k_binrw_roundtrip() {
        let h = Ed2kHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let mut buf = Cursor::new(Vec::new());
        h.write_le(&mut buf).unwrap();
        buf.set_position(0);
        let h2 = Ed2kHash::read_le(&mut buf).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_kad_uint128_wire_conversion_matches_stock_word_order() {
        let canonical = Ed2kHash::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let wire = [
            0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f,
            0x0e, 0x0d,
        ];

        assert_eq!(canonical.to_kad_uint128_wire_bytes(), wire);
        assert_eq!(Ed2kHash::from_kad_uint128_wire_bytes(wire), canonical);
    }

    #[test]
    fn test_kad_udp_key() {
        let k = KadUdpKey::new(0xDEAD_BEEF);
        assert_eq!(k.value(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_kad_udp_key_binrw_roundtrip() {
        let k = KadUdpKey::new(0x1234_5678);
        let mut buf = Cursor::new(Vec::new());
        k.write_le(&mut buf).unwrap();
        buf.set_position(0);
        let k2 = KadUdpKey::read_le(&mut buf).unwrap();
        assert_eq!(k, k2);
    }
}
