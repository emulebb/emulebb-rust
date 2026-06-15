use std::{io::Cursor, net::Ipv4Addr};

use anyhow::{Context, Result, ensure};
use binrw::{BinRead, BinWrite};
use chrono::{DateTime, Utc};
use emulebb_kad_proto::{Ed2kHash, NodeId, Tag};
use emulebb_metadata::{
    MetadataKadKeywordPublish, MetadataKadNotePublish, MetadataKadPublishCache,
    MetadataKadSourcePublish,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KadPublishCacheSnapshot {
    pub keyword_publishes: Vec<KadKeywordPublishSnapshot>,
    pub source_publishes: Vec<KadSourcePublishSnapshot>,
    pub note_publishes: Vec<KadNotePublishSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KadKeywordPublishSnapshot {
    pub observed_at: DateTime<Utc>,
    pub target: NodeId,
    pub file_hash: Ed2kHash,
    pub tags: Vec<Tag>,
    pub load: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KadSourcePublishSnapshot {
    pub observed_at: DateTime<Utc>,
    pub target: NodeId,
    pub publisher_id: NodeId,
    pub source_ip: Ipv4Addr,
    pub source_tcp_port: u16,
    pub source_udp_port: u16,
    pub tags: Vec<Tag>,
    pub load: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KadNotePublishSnapshot {
    pub observed_at: DateTime<Utc>,
    pub target: NodeId,
    pub publisher_id: NodeId,
    pub publisher_ip: Ipv4Addr,
    pub tags: Vec<Tag>,
    pub load: Option<u8>,
}

pub fn metadata_from_publish_snapshot(
    snapshot: &KadPublishCacheSnapshot,
) -> Result<MetadataKadPublishCache> {
    Ok(MetadataKadPublishCache {
        keyword_publishes: snapshot
            .keyword_publishes
            .iter()
            .map(metadata_keyword_publish)
            .collect::<Result<Vec<_>>>()?,
        source_publishes: snapshot
            .source_publishes
            .iter()
            .map(metadata_source_publish)
            .collect::<Result<Vec<_>>>()?,
        note_publishes: snapshot
            .note_publishes
            .iter()
            .map(metadata_note_publish)
            .collect::<Result<Vec<_>>>()?,
    })
}

pub fn publish_snapshot_from_metadata(
    metadata: MetadataKadPublishCache,
) -> Result<KadPublishCacheSnapshot> {
    Ok(KadPublishCacheSnapshot {
        keyword_publishes: metadata
            .keyword_publishes
            .into_iter()
            .map(keyword_publish_from_metadata)
            .collect::<Result<Vec<_>>>()?,
        source_publishes: metadata
            .source_publishes
            .into_iter()
            .map(source_publish_from_metadata)
            .collect::<Result<Vec<_>>>()?,
        note_publishes: metadata
            .note_publishes
            .into_iter()
            .map(note_publish_from_metadata)
            .collect::<Result<Vec<_>>>()?,
    })
}

fn metadata_keyword_publish(
    publish: &KadKeywordPublishSnapshot,
) -> Result<MetadataKadKeywordPublish> {
    Ok(MetadataKadKeywordPublish {
        target_node_id: publish.target.to_string(),
        file_hash: publish.file_hash.to_string(),
        raw_tags: encode_tags(&publish.tags)?,
        load: publish.load,
        observed_at_ms: publish.observed_at.timestamp_millis(),
    })
}

fn metadata_source_publish(publish: &KadSourcePublishSnapshot) -> Result<MetadataKadSourcePublish> {
    Ok(MetadataKadSourcePublish {
        target_node_id: publish.target.to_string(),
        publisher_id: publish.publisher_id.to_string(),
        file_hash: target_file_hash(publish.target).to_string(),
        source_ip: publish.source_ip.to_string(),
        source_tcp_port: publish.source_tcp_port,
        source_udp_port: publish.source_udp_port,
        raw_tags: encode_tags(&publish.tags)?,
        load: publish.load,
        observed_at_ms: publish.observed_at.timestamp_millis(),
    })
}

fn metadata_note_publish(publish: &KadNotePublishSnapshot) -> Result<MetadataKadNotePublish> {
    Ok(MetadataKadNotePublish {
        target_node_id: publish.target.to_string(),
        publisher_id: publish.publisher_id.to_string(),
        publisher_ip: publish.publisher_ip.to_string(),
        file_hash: Some(target_file_hash(publish.target).to_string()),
        raw_tags: encode_tags(&publish.tags)?,
        load: publish.load,
        observed_at_ms: publish.observed_at.timestamp_millis(),
    })
}

fn keyword_publish_from_metadata(
    publish: MetadataKadKeywordPublish,
) -> Result<KadKeywordPublishSnapshot> {
    Ok(KadKeywordPublishSnapshot {
        observed_at: timestamp_ms(publish.observed_at_ms, "Kad keyword observed_at_ms")?,
        target: publish.target_node_id.parse()?,
        file_hash: publish.file_hash.parse()?,
        tags: decode_tags(&publish.raw_tags)?,
        load: publish.load,
    })
}

fn source_publish_from_metadata(
    publish: MetadataKadSourcePublish,
) -> Result<KadSourcePublishSnapshot> {
    Ok(KadSourcePublishSnapshot {
        observed_at: timestamp_ms(publish.observed_at_ms, "Kad source observed_at_ms")?,
        target: publish.target_node_id.parse()?,
        publisher_id: publish.publisher_id.parse()?,
        source_ip: publish.source_ip.parse()?,
        source_tcp_port: publish.source_tcp_port,
        source_udp_port: publish.source_udp_port,
        tags: decode_tags(&publish.raw_tags)?,
        load: publish.load,
    })
}

fn note_publish_from_metadata(publish: MetadataKadNotePublish) -> Result<KadNotePublishSnapshot> {
    Ok(KadNotePublishSnapshot {
        observed_at: timestamp_ms(publish.observed_at_ms, "Kad note observed_at_ms")?,
        target: publish.target_node_id.parse()?,
        publisher_id: publish.publisher_id.parse()?,
        publisher_ip: publish.publisher_ip.parse()?,
        tags: decode_tags(&publish.raw_tags)?,
        load: publish.load,
    })
}

fn encode_tags(tags: &[Tag]) -> Result<Vec<u8>> {
    ensure!(
        u16::try_from(tags.len()).is_ok(),
        "Kad publish tag list exceeds u16 entries"
    );
    let mut cursor = Cursor::new(Vec::new());
    (tags.len() as u16).write_le(&mut cursor)?;
    for tag in tags {
        tag.write_le(&mut cursor)?;
    }
    Ok(cursor.into_inner())
}

fn decode_tags(raw: &[u8]) -> Result<Vec<Tag>> {
    let mut cursor = Cursor::new(raw);
    let tag_count = u16::read_le(&mut cursor).context("Kad publish tag count is missing")? as usize;
    let mut tags = Vec::with_capacity(tag_count);
    for _ in 0..tag_count {
        tags.push(Tag::read_le(&mut cursor).context("invalid Kad publish tag payload")?);
    }
    ensure!(
        cursor.position() == raw.len() as u64,
        "Kad publish tag payload has trailing bytes"
    );
    Ok(tags)
}

fn target_file_hash(target: NodeId) -> Ed2kHash {
    Ed2kHash::from_bytes(target.to_be_bytes())
}

fn timestamp_ms(value: i64, label: &str) -> Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp_millis(value)
        .with_context(|| format!("invalid {label}: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use emulebb_kad_proto::{
        SearchKeyReq, SearchNotesReq, SearchSourceReq, TagName, TagValue, tag_name,
    };
    use std::time::Duration;

    use crate::{KadLocalStore, KadLocalStoreConfig};

    #[test]
    fn publish_snapshot_roundtrips_through_metadata() {
        let snapshot = KadPublishCacheSnapshot {
            keyword_publishes: vec![KadKeywordPublishSnapshot {
                observed_at: Utc.timestamp_millis_opt(1_000).single().unwrap(),
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                file_hash: "11112222333344445555666677778888".parse().unwrap(),
                tags: vec![
                    Tag::filename("Zazolc Gesla Jazn.bin"),
                    Tag::new_short(tag_name::DESCRIPTION, TagValue::String("local note".into())),
                ],
                load: Some(1),
            }],
            source_publishes: vec![KadSourcePublishSnapshot {
                observed_at: Utc.timestamp_millis_opt(2_000).single().unwrap(),
                target: "22222222333333334444444455555555".parse().unwrap(),
                publisher_id: "aaaaaaaaaaaabbbbbbbbbbbbcccccccc".parse().unwrap(),
                source_ip: Ipv4Addr::new(192, 0, 2, 20),
                source_tcp_port: 4662,
                source_udp_port: 4672,
                tags: vec![Tag::new_short(tag_name::FILESIZE, TagValue::U64(1024))],
                load: Some(2),
            }],
            note_publishes: vec![KadNotePublishSnapshot {
                observed_at: Utc.timestamp_millis_opt(3_000).single().unwrap(),
                target: "33333333444444445555555566666666".parse().unwrap(),
                publisher_id: "bbbbbbbbbbbbccccccccccccdddddddd".parse().unwrap(),
                publisher_ip: Ipv4Addr::new(192, 0, 2, 21),
                tags: vec![Tag::new_short(
                    tag_name::DESCRIPTION,
                    TagValue::String("Zażółć note".into()),
                )],
                load: Some(3),
            }],
        };

        let metadata = metadata_from_publish_snapshot(&snapshot).unwrap();
        let restored = publish_snapshot_from_metadata(metadata).unwrap();

        assert_eq!(restored, snapshot);
    }

    #[test]
    fn invalid_tag_payload_is_rejected() {
        let metadata = MetadataKadPublishCache {
            keyword_publishes: vec![MetadataKadKeywordPublish {
                target_node_id: "00112233445566778899aabbccddeeff".to_string(),
                file_hash: "11112222333344445555666677778888".to_string(),
                raw_tags: vec![1, 0, 0xaa],
                load: None,
                observed_at_ms: 1,
            }],
            source_publishes: Vec::new(),
            note_publishes: Vec::new(),
        };

        assert!(publish_snapshot_from_metadata(metadata).is_err());
    }

    #[test]
    fn tag_storage_preserves_wire_tag_shape() {
        let tag = Tag::new_short(tag_name::FILESIZE, TagValue::U64(9_000_000_000));
        let raw = encode_tags(std::slice::from_ref(&tag)).unwrap();
        let tags = decode_tags(&raw).unwrap();

        assert_eq!(tags.len(), 1);
        assert!(matches!(
            (&tags[0].name, &tags[0].value),
            (TagName::Short(name), TagValue::U64(value))
                if *name == tag_name::FILESIZE && *value == 9_000_000_000
        ));
    }

    #[test]
    fn publish_snapshot_hydrates_keyword_search_response() {
        let target = NodeId::from_bytes([1; 16]);
        let file_hash = Ed2kHash::from_bytes([2; 16]);
        let mut store = KadLocalStore::new(config());
        store.merge_publish_snapshot(
            KadPublishCacheSnapshot {
                keyword_publishes: vec![KadKeywordPublishSnapshot {
                    observed_at: ts(1),
                    target,
                    file_hash,
                    tags: vec![
                        Tag::filename("Sample Unicode Zazolc.bin"),
                        Tag::filesize(123),
                    ],
                    load: None,
                }],
                source_publishes: Vec::new(),
                note_publishes: Vec::new(),
            },
            ts(2),
        );

        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(3),
            )
            .expect("keyword response");

        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].entry_id, file_hash);
    }

    #[test]
    fn publish_snapshot_hydrates_source_and_note_responses() {
        let target = NodeId::from_bytes([3; 16]);
        let publisher_id = NodeId::from_bytes([4; 16]);
        let mut store = KadLocalStore::new(config());
        store.merge_publish_snapshot(
            KadPublishCacheSnapshot {
                keyword_publishes: Vec::new(),
                source_publishes: vec![KadSourcePublishSnapshot {
                    observed_at: ts(1),
                    target,
                    publisher_id,
                    source_ip: Ipv4Addr::new(192, 0, 2, 80),
                    source_tcp_port: 4662,
                    source_udp_port: 4672,
                    tags: source_publish_tags(4662),
                    load: None,
                }],
                note_publishes: vec![KadNotePublishSnapshot {
                    observed_at: ts(1),
                    target,
                    publisher_id,
                    publisher_ip: Ipv4Addr::new(192, 0, 2, 81),
                    tags: vec![
                        Tag::filesize(456),
                        Tag::new_short(
                            tag_name::DESCRIPTION,
                            TagValue::String("local note".into()),
                        ),
                    ],
                    load: None,
                }],
            },
            ts(2),
        );

        assert!(
            store
                .source_search_response(
                    NodeId::from_bytes([9; 16]),
                    &SearchSourceReq {
                        target,
                        start_position: 0,
                        size: 456,
                    },
                    10,
                    ts(3),
                )
                .is_some()
        );
        assert!(
            store
                .notes_search_response(
                    NodeId::from_bytes([9; 16]),
                    &SearchNotesReq { target, size: 456 },
                    10,
                    ts(3),
                )
                .is_some()
        );
    }

    #[test]
    fn publish_snapshot_skips_expired_entries_on_hydrate() {
        let mut config = config();
        config.keyword_ttl = Duration::from_secs(5);
        let target = NodeId::from_bytes([1; 16]);
        let mut store = KadLocalStore::new(config);
        store.merge_publish_snapshot(
            KadPublishCacheSnapshot {
                keyword_publishes: vec![KadKeywordPublishSnapshot {
                    observed_at: ts(1),
                    target,
                    file_hash: Ed2kHash::from_bytes([2; 16]),
                    tags: vec![Tag::filename("expired.bin"), Tag::filesize(123)],
                    load: None,
                }],
                source_publishes: Vec::new(),
                note_publishes: Vec::new(),
            },
            ts(10),
        );

        assert_eq!(store.publish_snapshot(ts(10)).keyword_publishes.len(), 0);
    }

    fn config() -> KadLocalStoreConfig {
        KadLocalStoreConfig {
            enabled: true,
            keyword_ttl: Duration::from_secs(60),
            source_ttl: Duration::from_secs(60),
            notes_ttl: Duration::from_secs(60),
            keyword_capacity: 2,
            source_capacity: 2,
            notes_capacity: 2,
            source_per_file_capacity: 2,
            notes_per_file_capacity: 2,
        }
    }

    fn ts(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    fn source_publish_tags(source_tcp_port: u16) -> Vec<Tag> {
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(source_tcp_port)),
        ]
    }
}
