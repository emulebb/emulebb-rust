mod kad_swarm_support;

use std::time::Duration;

use emulebb_kad_proto::{Ed2kHash, Tag, TagValue, tag_name};
use kad_swarm_support::{LocalKadSwarm, file_hash, node_id};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

const FILE_SIZE: u64 = 1_048_576;
const SEARCH_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn local_kad_swarm_bootstraps_from_lan_seed() {
    let mut swarm = LocalKadSwarm::new().await;
    let seed = swarm.add_seed(1).await;
    let follower = swarm.add_bootstrap_node(2, seed).await;

    swarm.nodes[follower]
        .dht
        .bootstrap()
        .await
        .expect("bootstrap from LAN seed");

    assert!(swarm.nodes[follower].dht.is_bootstrapped());
    assert!(swarm.nodes[follower].dht.routing_table_size() > 0);
}

#[tokio::test]
async fn local_kad_swarm_publishes_and_searches_keywords() {
    let swarm = LocalKadSwarm::with_star_topology(4).await;
    let target = node_id(0x41);
    let hash = file_hash(0x51);
    let tags = vec![
        Tag::filename("Synthetic Unicode Sample äöü.txt"),
        Tag::filesize(FILE_SIZE),
        Tag::sources(1),
    ];

    let stats = swarm.nodes[1]
        .dht
        .publish_keyword(target, hash, tags, None)
        .await
        .expect("publish keyword");
    assert!(stats.attempted_contacts > 0);
    assert!(stats.acked_contacts > 0);

    let cancel = CancellationToken::new();
    let mut results = swarm.nodes[2]
        .dht
        .search_keywords_with_cancel(target, cancel.clone());
    let found = tokio::time::timeout(SEARCH_TIMEOUT, async {
        while let Some(result) = results.next().await {
            if result.hash == hash {
                return result;
            }
        }
        panic!("keyword search ended before expected result");
    })
    .await
    .expect("keyword search timed out");
    cancel.cancel();

    assert_eq!(found.size, Some(FILE_SIZE));
    assert!(
        found
            .names
            .iter()
            .any(|name| name == "Synthetic Unicode Sample äöü.txt")
    );
}

#[tokio::test]
async fn local_kad_swarm_publishes_and_searches_sources() {
    let swarm = LocalKadSwarm::with_star_topology(4).await;
    let hash = file_hash(0x61);
    let publisher_id = node_id(0x62);
    let source_ip = swarm.bind_ip();
    let source_tcp_port = 38_462;
    let source_udp_port = swarm.nodes[1].addr.port();
    let tags = vec![
        Tag::filesize(FILE_SIZE),
        Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(source_tcp_port)),
        Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(source_udp_port)),
        Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(1)),
    ];

    let stats = swarm.nodes[1]
        .dht
        .publish_source(hash, publisher_id, tags)
        .await
        .expect("publish source");
    assert!(stats.attempted_contacts > 0);
    assert!(stats.acked_contacts > 0);

    let cancel = CancellationToken::new();
    let mut results =
        swarm.nodes[2]
            .dht
            .search_sources_with_cancel(hash, FILE_SIZE, cancel.clone());
    let found = tokio::time::timeout(SEARCH_TIMEOUT, async {
        while let Some(result) = results.next().await {
            if result.file_hash == hash {
                return result;
            }
        }
        panic!("source search ended before expected result");
    })
    .await
    .expect("source search timed out");
    cancel.cancel();

    assert_eq!(found.ip, source_ip);
    assert_eq!(found.tcp_port, source_tcp_port);
    assert_eq!(found.udp_port, source_udp_port);
    assert_eq!(
        found.source_id,
        Ed2kHash::from_bytes(publisher_id.to_be_bytes())
    );
}

#[tokio::test]
async fn local_kad_swarm_publishes_and_searches_notes() {
    let swarm = LocalKadSwarm::with_star_topology(4).await;
    let hash = file_hash(0x71);
    let publisher_id = node_id(0x72);
    let tags = vec![
        Tag::filesize(FILE_SIZE),
        Tag::new_short(
            tag_name::DESCRIPTION,
            TagValue::String("useful sample".into()),
        ),
        Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
    ];

    let stats = swarm.nodes[1]
        .dht
        .publish_notes(hash, publisher_id, tags)
        .await
        .expect("publish notes");
    assert!(stats.attempted_contacts > 0);
    assert!(stats.acked_contacts > 0);

    let cancel = CancellationToken::new();
    let mut results = swarm.nodes[2]
        .dht
        .search_notes_with_cancel(hash, FILE_SIZE, cancel.clone());
    let found = tokio::time::timeout(SEARCH_TIMEOUT, async {
        while let Some(result) = results.next().await {
            if result.file_hash == hash {
                return result;
            }
        }
        panic!("notes search ended before expected result");
    })
    .await
    .expect("notes search timed out");
    cancel.cancel();

    assert_eq!(
        found.source_id,
        Ed2kHash::from_bytes(publisher_id.to_be_bytes())
    );
    assert_eq!(found.rating, Some(4));
    assert_eq!(found.comment.as_deref(), Some("useful sample"));
}
