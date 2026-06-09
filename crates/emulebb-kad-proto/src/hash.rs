use std::fmt;
use std::str::FromStr;

use binrw::{BinRead, BinWrite};

use crate::error::ProtoError;

/// A 128-bit eMule Ed2k file hash (MD4-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BinRead, BinWrite)]
#[brw(little)]
pub struct Ed2kHash(pub [u8; 16]);

impl Ed2kHash {
    pub const ZERO: Ed2kHash = Ed2kHash([0u8; 16]);

    #[must_use]
    pub fn from_bytes(b: [u8; 16]) -> Self {
        Ed2kHash(b)
    }
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
