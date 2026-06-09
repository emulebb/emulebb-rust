//! Bootstrap-node parsing and `nodes.dat` persistence helpers.
//!
//! This module is the boundary between the oracle's persisted contact formats
//! and the in-memory DHT runtime. It intentionally preserves the peer UDP key
//! field so restart-time obfuscation context stays aligned with eMule.

use crate::error::DhtError;
use binrw::{BinRead, BinWrite};
use emulebb_kad_proto::{KadUdpKey, NodeId};

/// Basic 25-byte entry: node_id + ip + udp_port + tcp_port + version.
#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(little)]
struct NodesDatEntry {
    node_id: emulebb_kad_proto::NodeId,
    ip: u32,
    udp_port: u16,
    tcp_port: u16,
    version: u8,
}

/// Extended 34-byte entry used by modern eMule/aMule:
/// basic (25) + contact_type (1) + last_seen (4) + udp_key (4).
#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(little)]
struct NodesDatEntryExt {
    node_id: NodeId,
    ip: u32,
    udp_port: u16,
    tcp_port: u16,
    version: u8,
    _contact_type: u8,
    _last_seen: u32,
    udp_key: u32,
}

#[derive(Debug, Clone)]
pub struct BootstrapContact {
    /// Kad node ID loaded from `nodes.dat`, when known.
    pub node_id: NodeId,
    /// IPv4 address of the bootstrap peer.
    pub ip: std::net::Ipv4Addr,
    /// Kad UDP port.
    pub udp_port: u16,
    /// ED2K TCP port advertised by the peer.
    pub tcp_port: u16,
    /// Kad version announced by the peer.
    pub version: u8,
    /// Peer UDP anti-spoofing key persisted from `nodes.dat` or learned at runtime.
    pub udp_key: KadUdpKey,
}

/// Parse a nodes.dat file in any of the known eMule/aMule formats:
///
/// - **Modern** (most common): `[0x00000000][version=2][count]` + 34-byte entries
///   (basic 25 bytes + contact_type + last_seen + udp_key)
/// - **Version 2**: `[version=2][count]` + 25- or 34-byte entries
/// - **Version 3**: `[version=3][bootstrap_edition][count]` + 25- or 34-byte entries
/// - **Old / legacy**: first u32 IS the count (no version header), 25-byte entries
pub fn parse_nodes_dat(data: &[u8]) -> Result<Vec<BootstrapContact>, DhtError> {
    use binrw::BinReaderExt;
    use std::io::Cursor;

    if data.len() < 8 {
        return Err(DhtError::NodesDatParse);
    }

    let mut cursor = Cursor::new(data);
    let first: u32 = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;

    // Detect header format and read the contact count.
    let count: u32 = if first == 0 {
        // Modern eMule format: 0x00000000 magic prefix, then version, then count.
        let version: u32 = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
        match version {
            2 => cursor.read_le().map_err(|_| DhtError::NodesDatParse)?,
            3 => {
                let _edition: u32 = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
                cursor.read_le().map_err(|_| DhtError::NodesDatParse)?
            }
            _ => return Err(DhtError::NodesDatParse),
        }
    } else {
        match first {
            // Versioned without magic prefix.
            2 => cursor.read_le().map_err(|_| DhtError::NodesDatParse)?,
            3 => {
                let _edition: u32 = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
                cursor.read_le().map_err(|_| DhtError::NodesDatParse)?
            }
            // Old format: first u32 IS the count.
            n => n,
        }
    };

    if count == 0 || count > 500_000 {
        return Ok(vec![]);
    }

    // Determine entry size from remaining bytes so we handle both 25- and 34-byte entries.
    let header_end = cursor.position() as usize;
    let remaining = data.len().saturating_sub(header_end);
    let entry_size = remaining / count as usize;
    let extended = entry_size >= 34;

    let mut contacts = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (node_id, ip, udp_port, tcp_port, version, udp_key) = if extended {
            let e: NodesDatEntryExt = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
            (
                e.node_id,
                e.ip,
                e.udp_port,
                e.tcp_port,
                e.version,
                KadUdpKey::new(e.udp_key),
            )
        } else {
            let e: NodesDatEntry = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
            (
                e.node_id,
                e.ip,
                e.udp_port,
                e.tcp_port,
                e.version,
                KadUdpKey::ZERO,
            )
        };

        if ip == 0 || udp_port == 0 {
            continue;
        }

        // IP is stored as a little-endian u32 representing network-byte-order octets.
        // to_be_bytes() recovers the original network-order [A, B, C, D].
        contacts.push(BootstrapContact {
            node_id,
            ip: std::net::Ipv4Addr::from(ip.to_be_bytes()),
            udp_port,
            tcp_port,
            version,
            udp_key,
        });
    }
    Ok(contacts)
}

/// Parse a plain-text node list. Each line: `ip:port` (UDP port).
/// Lines starting with '#' and empty lines are skipped.
pub fn parse_nodes_text(text: &str) -> Vec<BootstrapContact> {
    let mut contacts = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(addr) = line.parse::<std::net::SocketAddr>() {
            let ip = match addr.ip() {
                std::net::IpAddr::V4(ip) => ip,
                _ => continue,
            };
            contacts.push(BootstrapContact {
                node_id: NodeId::ZERO,
                ip,
                udp_port: addr.port(),
                tcp_port: addr.port(),
                version: 9,
                udp_key: KadUdpKey::ZERO,
            });
        }
    }
    contacts
}

/// Hardcoded bootstrap contacts — sourced from a live nodes.dat, used as last resort.
/// KAD1_IGNORED: Only Kad2 nodes (version >= 8) listed here.
pub fn hardcoded_bootstrap() -> Vec<BootstrapContact> {
    macro_rules! bc {
        ($ip:expr, $udp:expr, $tcp:expr, $ver:expr) => {
            BootstrapContact {
                node_id: NodeId::ZERO,
                ip: $ip.parse().unwrap(),
                udp_port: $udp,
                tcp_port: $tcp,
                version: $ver,
                udp_key: KadUdpKey::ZERO,
            }
        };
    }
    vec![
        bc!("37.222.82.145", 46772, 46762, 10),
        bc!("99.105.56.85", 4672, 4662, 8),
        bc!("87.220.164.19", 6763, 35771, 10),
        bc!("81.29.181.79", 4672, 4662, 8),
        bc!("81.57.54.56", 4672, 4662, 8),
        bc!("83.54.4.165", 20000, 10000, 9),
        bc!("93.44.81.49", 17953, 45230, 10),
        bc!("81.41.182.56", 58226, 58226, 10),
        bc!("50.191.141.58", 6802, 6800, 9),
        bc!("37.134.60.141", 13795, 19926, 9),
        bc!("86.63.39.150", 50535, 4662, 8),
        bc!("79.9.95.42", 21000, 21000, 10),
        bc!("83.37.242.162", 63100, 63100, 10),
        bc!("176.107.153.122", 4672, 4662, 8),
        bc!("95.237.210.130", 47533, 47523, 8),
        bc!("37.15.139.100", 4663, 4653, 8),
        bc!("151.60.189.25", 4672, 4662, 10),
        bc!("111.250.66.140", 4672, 4662, 8),
        bc!("85.60.24.134", 4672, 4662, 8),
        bc!("151.242.30.126", 14672, 14662, 8),
        bc!("82.84.74.202", 9126, 9125, 9),
        bc!("5.157.122.191", 4672, 4662, 8),
        bc!("79.116.194.103", 9507, 5329, 10),
        bc!("180.177.59.39", 4672, 4662, 8),
        bc!("81.57.92.93", 46720, 46620, 8),
        bc!("79.117.36.185", 29881, 28887, 8),
        bc!("88.5.100.118", 6011, 5011, 9),
        bc!("213.23.236.199", 4672, 4661, 10),
        bc!("87.13.47.77", 4672, 4662, 8),
        bc!("116.30.129.71", 1030, 5000, 9),
        bc!("109.134.251.8", 54664, 28253, 9),
        bc!("88.25.142.235", 4672, 4662, 8),
        bc!("87.222.156.134", 4292, 45129, 9),
        bc!("185.185.198.46", 4672, 4662, 8),
        bc!("27.147.28.182", 14672, 14662, 9),
        bc!("2.236.249.112", 4672, 4662, 10),
        bc!("118.118.237.130", 4672, 4662, 8),
        bc!("94.166.10.173", 4672, 4662, 8),
        bc!("88.26.10.158", 7523, 46242, 9),
        bc!("62.220.83.189", 4672, 4662, 10),
        bc!("109.117.111.98", 46672, 46662, 8),
        bc!("118.168.40.184", 8181, 8080, 9),
        bc!("128.116.245.196", 4672, 4662, 9),
        bc!("120.36.84.51", 4672, 4662, 8),
        bc!("79.116.189.91", 8882, 8881, 8),
        bc!("79.117.24.252", 26899, 26889, 8),
        bc!("82.84.102.19", 4672, 4662, 8),
        bc!("87.180.171.132", 4672, 4662, 8),
        bc!("88.27.31.76", 4672, 4662, 8),
        bc!("1.36.40.170", 7762, 59235, 10),
    ]
}

/// Serialize contacts into a simple modern nodes.dat payload with the modern
/// 34-byte entry layout.
pub fn encode_nodes_dat(contacts: &[BootstrapContact]) -> Result<Vec<u8>, DhtError> {
    use binrw::BinWriterExt;
    use std::io::Cursor;

    let mut cursor = Cursor::new(Vec::new());
    cursor
        .write_le(&0u32)
        .map_err(|_| DhtError::NodesDatParse)?;
    cursor
        .write_le(&2u32)
        .map_err(|_| DhtError::NodesDatParse)?;
    cursor
        .write_le(&(contacts.len() as u32))
        .map_err(|_| DhtError::NodesDatParse)?;

    for contact in contacts {
        let entry = NodesDatEntryExt {
            node_id: contact.node_id,
            ip: u32::from_be_bytes(contact.ip.octets()),
            udp_port: contact.udp_port,
            tcp_port: contact.tcp_port,
            version: contact.version,
            _contact_type: 2,
            _last_seen: 0,
            udp_key: contact.udp_key.value(),
        };
        cursor
            .write_le(&entry)
            .map_err(|_| DhtError::NodesDatParse)?;
    }

    Ok(cursor.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_basic_entry(ip: [u8; 4], udp: u16, tcp: u16, ver: u8) -> Vec<u8> {
        let mut e = vec![0xABu8; 16]; // node_id
        // IP stored as LE u32 of network-byte-order value: to_le_bytes of the BE u32
        let ip_le = u32::from_be_bytes(ip).to_le_bytes();
        e.extend_from_slice(&ip_le);
        e.extend_from_slice(&udp.to_le_bytes());
        e.extend_from_slice(&tcp.to_le_bytes());
        e.push(ver);
        e // 25 bytes
    }

    fn make_ext_entry(ip: [u8; 4], udp: u16, tcp: u16, ver: u8, udp_key: u32) -> Vec<u8> {
        let mut e = make_basic_entry(ip, udp, tcp, ver);
        e.push(2u8); // contact_type
        e.extend_from_slice(&0u32.to_le_bytes()); // last_seen
        e.extend_from_slice(&udp_key.to_le_bytes());
        e // 34 bytes
    }

    #[test]
    fn test_parse_nodes_dat_modern_magic_prefix() {
        // Format used by real eMule/aMule nodes.dat: [0][2][count] + 34-byte entries
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // magic
        data.extend_from_slice(&2u32.to_le_bytes()); // version
        data.extend_from_slice(&2u32.to_le_bytes()); // count
        data.extend(make_ext_entry([1, 2, 3, 4], 4672, 4662, 9, 0x1122_3344));
        data.extend(make_ext_entry([10, 0, 0, 1], 4673, 4663, 8, 0x5566_7788));

        let contacts = parse_nodes_dat(&data).unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(
            contacts[0].ip,
            "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(contacts[0].udp_port, 4672);
        assert_eq!(contacts[0].version, 9);
        assert_eq!(contacts[0].udp_key, KadUdpKey::new(0x1122_3344));
        assert_eq!(
            contacts[1].ip,
            "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(contacts[1].udp_port, 4673);
        assert_eq!(contacts[1].udp_key, KadUdpKey::new(0x5566_7788));
    }

    #[test]
    fn test_parse_nodes_dat_v2() {
        // Version 2 without magic prefix, 25-byte entries
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // version
        data.extend_from_slice(&2u32.to_le_bytes()); // count
        data.extend(make_basic_entry([192, 168, 1, 1], 4672, 4662, 9));
        data.extend(make_basic_entry([10, 0, 0, 1], 4673, 4663, 8));

        let contacts = parse_nodes_dat(&data).unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(
            contacts[0].ip,
            "192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(contacts[0].udp_port, 4672);
        assert_eq!(contacts[0].version, 9);
        assert_eq!(contacts[0].udp_key, KadUdpKey::ZERO);
        assert_eq!(contacts[1].udp_port, 4673);
        assert_eq!(contacts[1].udp_key, KadUdpKey::ZERO);
    }

    #[test]
    fn test_parse_nodes_dat_v3() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes()); // version 3
        data.extend_from_slice(&1u32.to_le_bytes()); // bootstrap edition
        data.extend_from_slice(&1u32.to_le_bytes()); // count
        data.extend(make_basic_entry([1, 2, 3, 4], 4672, 4662, 9));

        let contacts = parse_nodes_dat(&data).unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].version, 9);
        assert_eq!(contacts[0].udp_key, KadUdpKey::ZERO);
    }

    #[test]
    fn test_parse_nodes_dat_bad_version() {
        // magic=0, unknown version=99
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&99u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_nodes_dat(&data).is_err());
    }

    #[test]
    fn test_parse_nodes_text() {
        let text = "# comment\n\n192.168.1.1:4672\n10.0.0.1:4673\n";
        let contacts = parse_nodes_text(text);
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].udp_port, 4672);
        assert_eq!(contacts[1].udp_port, 4673);
        assert_eq!(contacts[0].udp_key, KadUdpKey::ZERO);
    }

    #[test]
    fn test_parse_nodes_text_invalid_lines_skipped() {
        let text = "not_an_ip:port\n127.0.0.1:4672\n";
        let contacts = parse_nodes_text(text);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].udp_key, KadUdpKey::ZERO);
    }

    #[test]
    fn test_encode_nodes_dat_roundtrips_udp_key() {
        let contact = BootstrapContact {
            node_id: NodeId::from_bytes([0x11; 16]),
            ip: "1.2.3.4".parse().unwrap(),
            udp_port: 4665,
            tcp_port: 4662,
            version: 9,
            udp_key: KadUdpKey::new(0xA1B2_C3D4),
        };

        let data = encode_nodes_dat(std::slice::from_ref(&contact)).unwrap();
        let parsed = parse_nodes_dat(&data).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].node_id, contact.node_id);
        assert_eq!(parsed[0].ip, contact.ip);
        assert_eq!(parsed[0].udp_port, contact.udp_port);
        assert_eq!(parsed[0].tcp_port, contact.tcp_port);
        assert_eq!(parsed[0].version, contact.version);
        assert_eq!(parsed[0].udp_key, contact.udp_key);
    }
}
