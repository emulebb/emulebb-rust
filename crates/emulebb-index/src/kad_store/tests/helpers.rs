use std::net::Ipv4Addr;

use emulebb_kad_proto::{NodeId, Tag, TagName, TagValue, tag_name};

pub(super) fn numbered_node_id(index: usize) -> NodeId {
    let mut bytes = [0; 16];
    bytes[0..4].copy_from_slice(&(index as u32).to_le_bytes());
    NodeId::from_bytes(bytes)
}

pub(super) fn numbered_ipv4(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(1, 1, (index / 250 + 1) as u8, (index % 250 + 1) as u8)
}

pub(super) fn source_publish_tags(source_tcp_port: u16) -> Vec<Tag> {
    vec![
        Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
        Tag::filesize(456),
        Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(source_tcp_port)),
    ]
}

pub(super) fn restrictive_string_payload(value: &str) -> Vec<u8> {
    let mut payload = vec![0x01];
    payload.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
    payload.extend(value.as_bytes());
    payload
}

pub(super) fn short_tag_names(tags: &[Tag]) -> Vec<u8> {
    tags.iter()
        .filter_map(|tag| match tag.name {
            TagName::Short(name) => Some(name),
            _ => None,
        })
        .collect()
}
