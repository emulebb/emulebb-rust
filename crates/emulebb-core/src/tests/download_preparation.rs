use super::*;
use crate::download_preparation::DownloadPreparation;

#[tokio::test]
async fn known_size_waiting_preparation_never_hydrates_without_a_useful_source() {
    let root = unique_runtime_dir("core-waiting-source-preparation");
    let mut network = test_network_config_with_store(
        &root,
        KadLocalStoreConfig::default(),
        SnoopQueueConfig::default(),
    );
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.p2p_bind_ip = Some(Ipv4Addr::LOCALHOST);
    network.ed2k.server_entries.clear();
    network.ed2k.server_endpoints.clear();
    let core = EmulebbCore::new_with_network(
        "test",
        FileIndex::in_memory().unwrap(),
        &root,
        Some(network),
    )
    .unwrap();
    let (_, created) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: "94949494949494949494949494949494".into(),
                name: "Sample.bin".into(),
                size_bytes: Some(0x4000000000),
            },
            category: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            redownload: false,
        })
        .await
        .unwrap();
    let id = created.id;
    drop(created);
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    let token = job.token;
    let guard = core
        .download_attempts
        .try_prepare(token, job.file_hash.parse().unwrap())
        .unwrap();
    drop(job);
    let baseline = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    assert!(matches!(
        core.prepare_download_sources(&guard, &CancellationToken::new())
            .await
            .unwrap(),
        DownloadPreparation::Waiting
    ));
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    assert_eq!(
        job.token, token,
        "source preparation must not begin another execution"
    );
    assert!(job.storage.is_none());
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        baseline
    );
    assert!(!core.download_attempts.owns(token));
    assert!(core.state.lock().await.transfers.is_empty());
}
