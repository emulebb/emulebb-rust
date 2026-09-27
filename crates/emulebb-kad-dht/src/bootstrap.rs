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

/// eMule nodes.dat v2 contact: basic (25) + CKadUDPKey (key and IP,
/// 4 bytes each) + IP-verified flag (1 byte).
#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(little)]
struct NodesDatEntryExt {
    node_id: NodeId,
    ip: u32,
    udp_port: u16,
    tcp_port: u16,
    version: u8,
    udp_key: u32,
    udp_key_ip: u32,
    verified: u8,
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
    /// Public IPv4 address for which `udp_key` is valid. Stock `CKadUDPKey`
    /// exposes the key only while this matches our current public address.
    pub udp_key_ip: Option<std::net::Ipv4Addr>,
    /// Whether the contact completed Kad IP verification before it was saved.
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodesDatLayout {
    /// Version 0: the first u32 is the contact count and the final record byte
    /// is the obsolete contact type, not a Kad protocol version.
    Legacy,
    /// Version 1 and version-3 bootstrap-edition records.
    Basic,
    /// Version 2 and normal version 3 records with key binding + verification.
    Extended,
}

/// Parse a nodes.dat file in each stock eMule format:
///
/// - **Version 0 / legacy**: `[count]` + exact 25-byte entries
/// - **Version 1**: `[0][1][count]` + exact 25-byte entries
/// - **Version 2**: `[0][2][count]` + exact 34-byte entries
/// - **Version 3 normal**: `[0][3][edition=0][count]` + exact 34-byte entries
/// - **Version 3 bootstrap edition**: `[0][3][edition=1][count]` + exact
///   25-byte entries
///
/// A non-zero first word is always a legacy count. This is important for
/// unversioned files containing exactly two or three contacts: treating those
/// counts as version numbers corrupts the framing. Trailing and truncated data
/// are rejected rather than using integer division to infer a record layout.
pub fn parse_nodes_dat(data: &[u8]) -> Result<Vec<BootstrapContact>, DhtError> {
    use binrw::BinReaderExt;
    use std::io::Cursor;

    const BASIC_ENTRY_SIZE: usize = 25;
    const EXTENDED_ENTRY_SIZE: usize = 34;
    const MAX_CONTACTS: u32 = 500_000;

    if data.len() < 4 {
        return Err(DhtError::NodesDatParse);
    }

    let mut cursor = Cursor::new(data);
    let first: u32 = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;

    let (count, layout): (u32, NodesDatLayout) = if first == 0 {
        // A four-byte zero is the valid empty legacy file. Any additional data
        // selects the versioned grammar used by stock RoutingZone.cpp.
        if data.len() == 4 {
            return Ok(Vec::new());
        }
        let file_version: u32 = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
        match file_version {
            1 => (
                cursor.read_le().map_err(|_| DhtError::NodesDatParse)?,
                NodesDatLayout::Basic,
            ),
            2 => (
                cursor.read_le().map_err(|_| DhtError::NodesDatParse)?,
                NodesDatLayout::Extended,
            ),
            3 => {
                let edition: u32 = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
                let count = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
                let layout = match edition {
                    0 => NodesDatLayout::Extended,
                    1 => NodesDatLayout::Basic,
                    _ => return Err(DhtError::NodesDatParse),
                };
                (count, layout)
            }
            _ => return Err(DhtError::NodesDatParse),
        }
    } else {
        (first, NodesDatLayout::Legacy)
    };

    if count > MAX_CONTACTS {
        return Err(DhtError::NodesDatParse);
    }

    let header_end = cursor.position() as usize;
    let entry_size = match layout {
        NodesDatLayout::Legacy | NodesDatLayout::Basic => BASIC_ENTRY_SIZE,
        NodesDatLayout::Extended => EXTENDED_ENTRY_SIZE,
    };
    let expected_len = (count as usize)
        .checked_mul(entry_size)
        .and_then(|entries_len| header_end.checked_add(entries_len))
        .ok_or(DhtError::NodesDatParse)?;
    if data.len() != expected_len {
        return Err(DhtError::NodesDatParse);
    }

    let mut contacts = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (node_id, ip, udp_port, tcp_port, version, udp_key, udp_key_ip, verified) = match layout
        {
            NodesDatLayout::Extended => {
                let e: NodesDatEntryExt = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
                (
                    e.node_id,
                    e.ip,
                    e.udp_port,
                    e.tcp_port,
                    e.version,
                    KadUdpKey::new(e.udp_key),
                    (e.udp_key_ip != 0)
                        .then(|| std::net::Ipv4Addr::from(e.udp_key_ip.to_be_bytes())),
                    e.verified != 0,
                )
            }
            NodesDatLayout::Legacy | NodesDatLayout::Basic => {
                let e: NodesDatEntry = cursor.read_le().map_err(|_| DhtError::NodesDatParse)?;
                (
                    e.node_id,
                    e.ip,
                    e.udp_port,
                    e.tcp_port,
                    if layout == NodesDatLayout::Legacy {
                        0
                    } else {
                        e.version
                    },
                    KadUdpKey::ZERO,
                    None,
                    true,
                )
            }
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
            udp_key_ip,
            verified,
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
                udp_key_ip: None,
                verified: false,
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
                udp_key_ip: None,
                verified: false,
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
            udp_key: contact.udp_key.value(),
            udp_key_ip: contact
                .udp_key_ip
                .map_or(0, |ip| u32::from_be_bytes(ip.octets())),
            verified: u8::from(contact.verified),
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

    fn make_basic_entry(seed: u8, ip: [u8; 4], ver_or_type: u8) -> Vec<u8> {
        let mut e = vec![seed; 16];
        e.extend_from_slice(&u32::from_be_bytes(ip).to_le_bytes());
        let udp = 4600 + u16::from(seed);
        let tcp = 4700 + u16::from(seed);
        e.extend_from_slice(&udp.to_le_bytes());
        e.extend_from_slice(&tcp.to_le_bytes());
        e.push(ver_or_type);
        assert_eq!(e.len(), 25);
        e
    }

    fn make_ext_entry(
        seed: u8,
        ip: [u8; 4],
        ver: u8,
        udp_key: u32,
        udp_key_ip: [u8; 4],
        verified: bool,
    ) -> Vec<u8> {
        let mut e = make_basic_entry(seed, ip, ver);
        e.extend_from_slice(&udp_key.to_le_bytes());
        e.extend_from_slice(&u32::from_be_bytes(udp_key_ip).to_le_bytes());
        e.push(u8::from(verified));
        assert_eq!(e.len(), 34);
        e
    }

    fn legacy_file(count: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&count.to_le_bytes());
        for index in 0..count {
            let seed = (index + 1) as u8;
            data.extend(make_basic_entry(seed, [198, 51, 100, seed], 2));
        }
        data
    }

    fn modern_file(version: u32, edition: Option<u32>, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&version.to_le_bytes());
        if let Some(edition) = edition {
            data.extend_from_slice(&edition.to_le_bytes());
        }
        data.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for entry in entries {
            data.extend_from_slice(entry);
        }
        data
    }

    #[test]
    fn unversioned_counts_zero_one_two_three_and_more_are_unambiguous() {
        for count in [0, 1, 2, 3, 7] {
            let contacts = parse_nodes_dat(&legacy_file(count)).unwrap();
            assert_eq!(contacts.len(), count as usize, "legacy count {count}");
            assert!(contacts.iter().all(|contact| contact.version == 0));
            assert!(contacts.iter().all(|contact| contact.verified));
            assert!(contacts.iter().all(|contact| contact.udp_key_ip.is_none()));
        }
    }

    #[test]
    fn modern_version_one_reads_exact_basic_records() {
        let data = modern_file(1, None, &[make_basic_entry(1, [192, 0, 2, 1], 9)]);
        let contacts = parse_nodes_dat(&data).unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].version, 9);
        assert_eq!(contacts[0].udp_key, KadUdpKey::ZERO);
        assert!(contacts[0].verified);
    }

    #[test]
    fn modern_version_two_preserves_key_binding_and_verified_state() {
        let entries = [
            make_ext_entry(
                1,
                [203, 0, 113, 1],
                10,
                0x1122_3344,
                [198, 51, 100, 90],
                true,
            ),
            make_ext_entry(2, [203, 0, 113, 2], 8, 0, [0, 0, 0, 0], false),
        ];
        let contacts = parse_nodes_dat(&modern_file(2, None, &entries)).unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].udp_key, KadUdpKey::new(0x1122_3344));
        assert_eq!(
            contacts[0].udp_key_ip,
            Some("198.51.100.90".parse().unwrap())
        );
        assert!(contacts[0].verified);
        assert_eq!(contacts[1].udp_key, KadUdpKey::ZERO);
        assert_eq!(contacts[1].udp_key_ip, None);
        assert!(!contacts[1].verified);
    }

    #[test]
    fn modern_version_three_normal_reads_extended_records() {
        let entry = make_ext_entry(
            3,
            [203, 0, 113, 3],
            10,
            0x5566_7788,
            [198, 51, 100, 91],
            false,
        );
        let contacts = parse_nodes_dat(&modern_file(3, Some(0), &[entry])).unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].version, 10);
        assert_eq!(contacts[0].udp_key, KadUdpKey::new(0x5566_7788));
        assert_eq!(
            contacts[0].udp_key_ip,
            Some("198.51.100.91".parse().unwrap())
        );
        assert!(!contacts[0].verified);
    }

    #[test]
    fn modern_version_three_bootstrap_edition_reads_basic_records() {
        let entry = make_basic_entry(4, [203, 0, 113, 4], 8);
        let contacts = parse_nodes_dat(&modern_file(3, Some(1), &[entry])).unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].version, 8);
        assert_eq!(contacts[0].udp_key, KadUdpKey::ZERO);
        assert!(contacts[0].verified);
    }

    #[test]
    fn exact_record_sizes_reject_truncation_and_trailing_bytes() {
        let basic = modern_file(1, None, &[make_basic_entry(1, [192, 0, 2, 1], 9)]);
        let extended = modern_file(
            2,
            None,
            &[make_ext_entry(
                1,
                [192, 0, 2, 1],
                9,
                7,
                [198, 51, 100, 1],
                true,
            )],
        );
        for exact in [basic, extended] {
            assert!(parse_nodes_dat(&exact).is_ok());
            assert!(parse_nodes_dat(&exact[..exact.len() - 1]).is_err());
            let mut extra = exact;
            extra.push(0);
            assert!(parse_nodes_dat(&extra).is_err());
        }

        let legacy = legacy_file(2);
        assert!(parse_nodes_dat(&legacy).is_ok());
        assert!(parse_nodes_dat(&legacy[..legacy.len() - 1]).is_err());
        let mut legacy_extra = legacy;
        legacy_extra.push(0);
        assert!(parse_nodes_dat(&legacy_extra).is_err());
    }

    #[test]
    fn malformed_headers_and_unsupported_versions_are_rejected() {
        assert!(parse_nodes_dat(&[]).is_err());
        assert!(parse_nodes_dat(&[0, 0, 0]).is_err());
        assert!(parse_nodes_dat(&modern_file(99, None, &[])).is_err());
        assert!(parse_nodes_dat(&modern_file(3, Some(2), &[])).is_err());
        assert!(parse_nodes_dat(&500_001u32.to_le_bytes()).is_err());
    }

    #[test]
    fn text_contacts_have_no_persisted_security_metadata() {
        let contacts = parse_nodes_text("# comment\n\n192.168.1.1:4672\ninvalid\n10.0.0.1:4673\n");
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].udp_port, 4672);
        assert_eq!(contacts[1].udp_port, 4673);
        assert!(
            contacts
                .iter()
                .all(|contact| contact.udp_key == KadUdpKey::ZERO)
        );
        assert!(
            contacts
                .iter()
                .all(|contact| contact.udp_key_ip.is_none() && !contact.verified)
        );
    }

    #[test]
    fn encoding_roundtrips_all_extended_security_metadata() {
        let contact = BootstrapContact {
            node_id: NodeId::from_bytes([0x11; 16]),
            ip: "1.2.3.4".parse().unwrap(),
            udp_port: 4665,
            tcp_port: 4662,
            version: 9,
            udp_key: KadUdpKey::new(0xA1B2_C3D4),
            udp_key_ip: Some("198.51.100.44".parse().unwrap()),
            verified: true,
        };

        let data = encode_nodes_dat(std::slice::from_ref(&contact)).unwrap();
        assert_eq!(data.len(), 12 + 34);
        assert_eq!(&data[..12], &[0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]);
        let parsed = parse_nodes_dat(&data).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].node_id, contact.node_id);
        assert_eq!(parsed[0].ip, contact.ip);
        assert_eq!(parsed[0].udp_port, contact.udp_port);
        assert_eq!(parsed[0].tcp_port, contact.tcp_port);
        assert_eq!(parsed[0].version, contact.version);
        assert_eq!(parsed[0].udp_key, contact.udp_key);
        assert_eq!(parsed[0].udp_key_ip, contact.udp_key_ip);
        assert_eq!(parsed[0].verified, contact.verified);
    }
}
