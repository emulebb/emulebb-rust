mod kad_swarm_support;

use std::time::Duration;

use emulebb_core::{
    LocalShare, SharedDirectoriesUpdate, SharedDirectoryRootUpdate, TransferCreate,
};
use emulebb_kad_proto::{Ed2kHash, Tag, TagValue, tag_name};
use kad_swarm_support::{
    LocalKadSwarm, deterministic_payload, file_hash, free_lan_tcp_port, node_id, open_network_core,
    unique_test_dir, wait_for_completed_transfer, wait_for_kad_connected,
};
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

#[tokio::test]
async fn local_kad_swarm_discovers_source_and_completes_ed2k_transfer() {
    let swarm = LocalKadSwarm::with_star_topology(4).await;
    let bootstrap = swarm.nodes[0].addr;
    let bind_ip = swarm.bind_ip();
    let runtime_dir = unique_test_dir("kad-source-ed2k-transfer");
    let payload_name = "Kad Unicode Transfer äöü 漢.bin";
    let payload = deterministic_payload(2 * 1024 * 1024 + 17);
    let shared_root = runtime_dir.join("shared");
    let nested_root = shared_root.join("nested").join("unicode");
    std::fs::create_dir_all(&nested_root).expect("create nested shared root");
    let payload_path = nested_root.join(payload_name);
    std::fs::write(&payload_path, &payload).expect("write shared payload");

    let seed_core = open_network_core(
        &runtime_dir.join("seed"),
        bind_ip,
        bootstrap,
        free_lan_tcp_port(bind_ip),
        [0x31; 16],
        true,
    );
    seed_core
        .set_shared_directories(SharedDirectoriesUpdate {
            roots: vec![SharedDirectoryRootUpdate::Object {
                path: shared_root.display().to_string(),
                recursive: true,
            }],
            confirm_replace_roots: true,
        })
        .await
        .expect("configure seed shared tree");
    let shares = seed_core
        .reload_shared_directories()
        .await
        .expect("reload seed shared tree");
    let share = require_share_by_name(&shares, payload_name);
    seed_core.connect_ed2k().await.expect("start seed network");
    wait_for_kad_connected(&seed_core).await;

    let download_core = open_network_core(
        &runtime_dir.join("download"),
        bind_ip,
        bootstrap,
        free_lan_tcp_port(bind_ip),
        [0x32; 16],
        false,
    );
    download_core
        .connect_ed2k()
        .await
        .expect("start downloader network");
    wait_for_kad_connected(&download_core).await;

    let transfer = download_core
        .create_transfer(TransferCreate {
            link: Some(share.ed2k_link.clone()),
            links: None,
            paused: Some(true),
            category_id: None,
            category_name: None,
        })
        .await
        .expect("queue Kad-discovered transfer");
    download_core
        .resume_transfer(&transfer.hash)
        .await
        .expect("resume Kad-discovered transfer");

    let completed = wait_for_completed_transfer(&download_core, &transfer.hash).await;
    assert_eq!(completed.size_bytes, payload.len() as u64);
    assert_eq!(completed.completed_bytes, payload.len() as u64);
}

fn require_share_by_name(shares: &[LocalShare], name: &str) -> LocalShare {
    shares
        .iter()
        .find(|share| share.name == name)
        .cloned()
        .unwrap_or_else(|| panic!("shared tree did not publish {name}"))
}
