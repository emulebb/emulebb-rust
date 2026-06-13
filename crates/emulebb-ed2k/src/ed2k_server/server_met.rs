//! Parser for the classic eMule `server.met` server-list file.
//!
//! Layout (matches the eMuleBB master `CServerList::LoadServermetFromFile`):
//! `u8 version (0x0E | 0xE0)` then `u32 count`, and per entry a packed
//! `ServerMet_Struct { u32 ip; u16 port; u32 tagcount }` followed by `tagcount`
//! ED2K tags. The IP is stored little-endian and rendered LSB-first, i.e. the
//! four file bytes are the dotted octets in order.

use std::net::Ipv4Addr;

use anyhow::{Result, ensure};

use super::tag_codec::{DecodedTagValue, decode_tag_value};

const MET_HEADER: u8 = 0x0E;
const MET_HEADER_WITH_LARGEFILES: u8 = 0xE0;
/// ED2K server-name tag (`ST_SERVERNAME`).
const TAG_SERVER_NAME: u8 = 0x01;

/// One server parsed from a `server.met` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServerMetEntry {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub name: Option<String>,
}

/// Parses a `server.met` payload into server entries (IP, port, optional name).
pub fn parse_server_met(data: &[u8]) -> Result<Vec<ParsedServerMetEntry>> {
    ensure!(data.len() >= 5, "server.met payload too short");
    let version = data[0];
    ensure!(
        version == MET_HEADER || version == MET_HEADER_WITH_LARGEFILES,
        "unsupported server.met version 0x{version:02X}"
    );
    let mut pos = 1usize;
    let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;
    if count > 1_000_000 {
        anyhow::bail!("implausible server.met count {count}");
    }

    let mut servers = Vec::with_capacity(count.min(4096) as usize);
    for _ in 0..count {
        ensure!(data.len() >= pos + 10, "truncated server.met entry header");
        let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
        let port = u16::from_le_bytes([data[pos + 4], data[pos + 5]]);
        let tag_count = u32::from_le_bytes(data[pos + 6..pos + 10].try_into().unwrap());
        pos += 10;

        let mut name = None;
        for _ in 0..tag_count {
            let (tag_name, value, rest) = decode_tag_value(&data[pos..])?;
            let consumed = (data.len() - pos) - rest.len();
            pos += consumed;
            if tag_name == Some(TAG_SERVER_NAME)
                && let Some(DecodedTagValue::String(text)) = value
            {
                name = Some(text);
            }
        }

        if !ip.is_unspecified() && port != 0 {
            servers.push(ParsedServerMetEntry { ip, port, name });
        }
    }
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short_string_name_tag(name: &str) -> Vec<u8> {
        // TAGTYPE_STR1.. compact string with a one-byte (short) tag name.
        let mut tag = Vec::new();
        let type_byte = 0x80 | (0x11 + (name.len() as u8 - 1)); // short-name | TAGTYPE_STR1+len-1
        tag.push(type_byte);
        tag.push(TAG_SERVER_NAME);
        tag.extend_from_slice(name.as_bytes());
        tag
    }

    #[test]
    fn parses_ip_port_and_name() {
        let mut data = vec![MET_HEADER];
        data.extend_from_slice(&1u32.to_le_bytes()); // one server
        data.extend_from_slice(&[45, 82, 80, 155]); // ip 45.82.80.155
        data.extend_from_slice(&5687u16.to_le_bytes()); // port
        let name_tag = short_string_name_tag("Lugd");
        data.extend_from_slice(&1u32.to_le_bytes()); // tagcount
        data.extend_from_slice(&name_tag);

        let servers = parse_server_met(&data).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].ip, Ipv4Addr::new(45, 82, 80, 155));
        assert_eq!(servers[0].port, 5687);
        assert_eq!(servers[0].name.as_deref(), Some("Lugd"));
    }

    #[test]
    fn rejects_bad_version() {
        let data = [0x99u8, 0, 0, 0, 0];
        assert!(parse_server_met(&data).is_err());
    }
}
