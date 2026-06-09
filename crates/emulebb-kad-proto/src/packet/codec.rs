use binrw::{BinReaderExt, BinWriterExt};
use std::io::{Cursor, Read, Write};

use crate::error::ProtoError;
use crate::hash::Ed2kHash;
use crate::node_id::NodeId;
use crate::tag::{StringDecodeMode, Tag};

use super::types::{
    FindBuddyRes, PublishRes, SearchKeyReq, SearchRes, SearchResultEntry, SearchSourceReq,
};

fn read_kad_search_entry_id(cursor: &mut Cursor<&[u8]>) -> Result<Ed2kHash, ProtoError> {
    let entry_id = cursor.read_le::<NodeId>()?;
    Ok(Ed2kHash::from_bytes(entry_id.to_be_bytes()))
}

fn write_kad_search_entry_id(
    cursor: &mut Cursor<Vec<u8>>,
    entry_id: &Ed2kHash,
) -> Result<(), ProtoError> {
    cursor.write_le(&NodeId::from_be_bytes(entry_id.0))?;
    Ok(())
}

pub(super) fn read_search_res(cursor: &mut Cursor<&[u8]>) -> Result<SearchRes, ProtoError> {
    // SEARCH_RES is the one Kad path where eMule/aMule allow non-UTF-8 strings to
    // fall back to the local ANSI code page for backward-compatible display.
    // Reference:
    // - eMule srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_RES
    // - eMule srchybrid/kademlia/io/DataIO.cpp CDataIO::ReadStringUTF8(bool bOptACP)
    // - aMule src/kademlia/net/KademliaUDPListener.cpp ProcessSearchResponse
    let sender_id = cursor.read_le::<NodeId>()?;
    let target = cursor.read_le::<NodeId>()?;
    let count = cursor.read_le::<u16>()?;
    let mut results = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let entry_id = read_kad_search_entry_id(cursor)?;
        let tag_count = cursor.read_le::<u8>()?;
        let mut tags = Vec::with_capacity(tag_count as usize);
        for _ in 0..tag_count {
            tags.push(Tag::read_with_mode(
                cursor,
                binrw::Endian::Little,
                StringDecodeMode::SearchResult,
            )?);
        }
        results.push(SearchResultEntry { entry_id, tags });
    }

    Ok(SearchRes {
        sender_id,
        target,
        results,
    })
}

pub(super) fn write_search_res(
    cursor: &mut Cursor<Vec<u8>>,
    packet: &SearchRes,
) -> Result<(), ProtoError> {
    cursor.write_le(&packet.sender_id)?;
    cursor.write_le(&packet.target)?;
    cursor
        .write_le(&u16::try_from(packet.results.len()).expect("search result count exceeds u16"))?;
    for result in &packet.results {
        write_kad_search_entry_id(cursor, &result.entry_id)?;
        cursor.write_le(&u8::try_from(result.tags.len()).expect("tag count exceeds u8"))?;
        for tag in &result.tags {
            cursor.write_le(tag)?;
        }
    }
    Ok(())
}

pub(super) fn read_find_buddy_res(cursor: &mut Cursor<&[u8]>) -> Result<FindBuddyRes, ProtoError> {
    let buddy_id = cursor.read_le::<NodeId>()?;
    let client_hash = cursor.read_le::<Ed2kHash>()?;
    let tcp_port = cursor.read_le::<u16>()?;
    let connect_options = if cursor.position() < cursor.get_ref().len() as u64 {
        Some(cursor.read_le::<u8>()?)
    } else {
        None
    };

    Ok(FindBuddyRes {
        buddy_id,
        client_hash,
        tcp_port,
        connect_options,
    })
}

pub(super) fn write_find_buddy_res(
    cursor: &mut Cursor<Vec<u8>>,
    packet: &FindBuddyRes,
) -> Result<(), ProtoError> {
    cursor.write_le(&packet.buddy_id)?;
    cursor.write_le(&packet.client_hash)?;
    cursor.write_le(&packet.tcp_port)?;
    if let Some(connect_options) = packet.connect_options {
        cursor.write_le(&connect_options)?;
    }
    Ok(())
}

pub(super) fn read_publish_res(cursor: &mut Cursor<&[u8]>) -> Result<PublishRes, ProtoError> {
    let target = cursor.read_le::<NodeId>()?;
    let load = cursor.read_le::<u8>()?;
    let options = if cursor.position() < cursor.get_ref().len() as u64 {
        Some(cursor.read_le::<u8>()?)
    } else {
        None
    };

    Ok(PublishRes {
        target,
        load,
        options,
    })
}

pub(super) fn write_publish_res(
    cursor: &mut Cursor<Vec<u8>>,
    packet: &PublishRes,
) -> Result<(), ProtoError> {
    cursor.write_le(&packet.target)?;
    cursor.write_le(&packet.load)?;
    if let Some(options) = packet.options {
        cursor.write_le(&options)?;
    }
    Ok(())
}

pub(super) fn read_search_key_req(cursor: &mut Cursor<&[u8]>) -> Result<SearchKeyReq, ProtoError> {
    let target = cursor.read_le::<NodeId>()?;
    let start_position = cursor.read_le::<u16>()?;
    let mut restrictive_payload = Vec::new();
    cursor
        .read_to_end(&mut restrictive_payload)
        .map_err(ProtoError::Io)?;
    Ok(SearchKeyReq {
        target,
        start_position,
        restrictive_payload,
    })
}

pub(super) fn write_search_key_req(
    buf: &mut Cursor<Vec<u8>>,
    packet: &SearchKeyReq,
) -> Result<(), ProtoError> {
    buf.write_le(&packet.target)?;
    buf.write_le(&packet.start_position)?;
    buf.write_all(&packet.restrictive_payload)
        .map_err(ProtoError::Io)?;
    Ok(())
}

pub(super) fn read_search_source_req(
    cursor: &mut Cursor<&[u8]>,
) -> Result<SearchSourceReq, ProtoError> {
    let target = cursor.read_le::<NodeId>()?;
    let remaining = cursor
        .get_ref()
        .len()
        .saturating_sub(cursor.position() as usize);
    let (start_position, size) = match remaining {
        4 => (0, u64::from(cursor.read_le::<u32>()?)),
        8 => (0, cursor.read_le::<u64>()?),
        10 => {
            let start_position = cursor.read_le::<u16>()? & 0x7FFF;
            (start_position, cursor.read_le::<u64>()?)
        }
        _ => return Err(ProtoError::BufferTooShort),
    };
    Ok(SearchSourceReq {
        target,
        start_position,
        size,
    })
}

pub(super) fn write_search_source_req(
    buf: &mut Cursor<Vec<u8>>,
    packet: &SearchSourceReq,
) -> Result<(), ProtoError> {
    buf.write_le(&packet.target)?;
    buf.write_le(&packet.start_position)?;
    buf.write_le(&packet.size)?;
    Ok(())
}
