use super::*;
use crate::{
    DownloadCreate, DownloadCreateSource, DownloadWaitingReason, download_admission::MemorySampler,
    tests::download_preparation::local_preparation_core,
};
use emulebb_ed2k::ed2k_transfer::Ed2kSourceHint;
use emulebb_metadata::DownloadIntent;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn live_pressure_preserves_payload_owner_and_gradually_readmits_ready_work() {
    let root = crate::unique_runtime_dir("scheduler-live-memory-pressure");
    let (core, _) = local_preparation_core(&root.join("receiver"), [0x71; 16], None);
    core.ed2k_transfers.apply_download_limit(128 * 1024).await;
    let shutdown = CancellationToken::new();
    let mut seeds = Vec::new();
    let mut ready = Vec::new();
    let mut files = Vec::new();
    for index in 0..2u8 {
        let library = root.join(format!("library-{index}"));
        std::fs::create_dir_all(&library).unwrap();
        let payload = vec![0x72 + index; 512 * 1024];
        std::fs::write(library.join("Payload.bin"), &payload).unwrap();
        let (seed, network) = local_preparation_core(
            &root.join(format!("seed-{index}")),
            [0x72 + index; 16],
            None,
        );
        seed.create_library_root(&library.to_string_lossy(), false)
            .await
            .unwrap()
            .unwrap();
        let shares = seed.reload_shared_directories().await.unwrap();
        let hash = shares
            .iter()
            .find(|file| file.name == "Payload.bin")
            .unwrap()
            .hash
            .clone();
        drop(shares);
        seed.connect_ed2k().await.unwrap();
        let (_, created) = core
            .create_download(DownloadCreate {
                source: DownloadCreateSource::Content {
                    hash: hash.clone(),
                    name: "Payload.bin".into(),
                    size_bytes: Some(payload.len() as u64),
                },
                category: None,
                intent: DownloadIntent::Started,
                redownload: false,
            })
            .await
            .unwrap();
        let id = created.id;
        drop(created);
        let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
        let token = job.token;
        drop(job);
        core.ed2k_transfers
            .remember_source(
                token,
                Ed2kSourceHint {
                    ip: Ipv4Addr::LOCALHOST.to_string(),
                    tcp_port: network.listen_port,
                    user_hash: Some(hex::encode(network.user_hash)),
                    connect_options: None,
                    file_comment: String::new(),
                    file_rating: 0,
                },
            )
            .await
            .unwrap();
        let guard = core
            .download_attempts
            .try_prepare(token, hash.parse().unwrap())
            .unwrap();
        let source = core
            .prepare_download_sources(&guard, &shutdown)
            .await
            .unwrap();
        assert!(matches!(
            source,
            crate::download_preparation::DownloadPreparation::Direct(_)
        ));
        let entry = ReadyDownload {
            guard,
            source,
            remaining_bytes: payload.len() as u64,
            rare: false,
        };
        entry.guard.mark_ready(entry.deadline());
        if index == 1 {
            // Keep waiting work ordinary, so pressure is the only scheduling cause.
            core.ed2k_transfers
                .remember_source_availability(
                    token,
                    Ed2kSourceHint {
                        ip: "192.0.2.254".into(),
                        tcp_port: 4662,
                        user_hash: Some("79".repeat(16)),
                        connect_options: None,
                        file_comment: String::new(),
                        file_rating: 0,
                    },
                    payload.len() as u64,
                    vec![true],
                )
                .await
                .unwrap();
            assert!(!core.ready_source_is_rare(&entry).await);
        }
        ready.push(entry);
        files.push((id, hash, payload));
        seeds.push(seed);
    }

    let (reached, delivery) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    *core.download_delivery_gate.lock().await = Some((reached, resume));
    core.download_hydration_busy.store(true, Ordering::Release);
    let (ticks, clock) = watch::channel(());
    let mut workers = JoinSet::new();
    let mut last = None;
    let waiting = ready.pop().unwrap();
    core.admit_ready_downloads(&mut ready, &mut last, &mut workers, &clock, &shutdown)
        .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while core.download_hydration_busy.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let selected_job = core
        .ed2k_transfers
        .download_job(files[0].0)
        .await
        .unwrap()
        .unwrap();
    let selected = selected_job.token;
    drop(selected_job);
    let old_reader = core.ed2k_transfers.manifest(selected).await.unwrap();
    ticks.send_replace(());
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let job = core
                .ed2k_transfers
                .download_job(files[0].0)
                .await
                .unwrap()
                .unwrap();
            let token = job.token;
            let verified = job.payload_verified;
            drop(job);
            if core.ed2k_transfers.downloaded_session_bytes(token) > 0 {
                assert!(
                    !verified,
                    "pressure must begin during actual payload execution"
                );
                assert_eq!(token, selected);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    ready.push(waiting);
    let waiting_token = ready[0].guard.token();
    core.refresh_download_admission(&mut MemorySampler::with_available(0))
        .await;
    core.admit_ready_downloads(&mut ready, &mut last, &mut workers, &clock, &shutdown)
        .await;
    let stats = core.transfer_stats().await.unwrap();
    assert_eq!(stats.resources.active, 1);
    assert_eq!(stats.resources.concurrency.target, 0);
    assert_eq!(stats.resources.preparing, 1);
    assert_eq!(stats.resources.waiting, 0);
    assert!(
        stats.resources.resident_memory.used_bytes <= stats.resources.resident_memory.limit_bytes
    );
    drop(stats);
    assert!(core.download_attempts.owns(selected));
    assert_eq!(ready.len(), 1);
    assert_eq!(
        core.download_detail(files[1].0)
            .await
            .unwrap()
            .unwrap()
            .summary
            .waiting_reason,
        Some(DownloadWaitingReason::Resources)
    );
    let waiting_job = core
        .ed2k_transfers
        .download_job(waiting_token.job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(waiting_job.token, waiting_token);
    assert!(
        waiting_job.storage.is_none(),
        "ready work has not begun storage hydration"
    );
    drop(waiting_job);

    // The payload finishes naturally. Hold its normal output-delivery boundary:
    // neither a lower target nor a finished network round releases ownership early.
    tokio::time::timeout(Duration::from_secs(20), delivery)
        .await
        .unwrap()
        .unwrap();
    assert!(workers.try_join_next().is_none());
    assert!(core.download_attempts.owns(selected));
    assert_eq!(core.download_attempts.admission_counts().1, 1);
    let verified = core
        .ed2k_transfers
        .download_job(files[0].0)
        .await
        .unwrap()
        .unwrap();
    assert!(verified.payload_verified);
    assert!(
        verified.completed_at_s.is_none(),
        "output delivery is still held"
    );
    drop(verified);
    let before_retirement = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), workers.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!core.download_attempts.owns(selected));
    assert_eq!(core.download_attempts.admission_counts().1, 0);
    assert_eq!(
        std::fs::read(&core.share(&files[0].1).await.unwrap().path).unwrap(),
        files[0].2
    );
    let pinned_bytes = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    assert!(
        pinned_bytes < before_retirement,
        "safe retirement evicts unused cache backing"
    );
    drop(old_reader);
    assert!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes
            < pinned_bytes,
        "evicted backing stays charged through its last reader"
    );
    core.admit_ready_downloads(&mut ready, &mut last, &mut workers, &clock, &shutdown)
        .await;
    assert_eq!(
        ready.len(),
        1,
        "retirement alone does not reopen pressure-closed admission"
    );

    let mut recovered = MemorySampler::with_available(8 * 1024 * 1024 * 1024);
    core.refresh_download_admission(&mut recovered).await;
    assert_eq!(core.download_attempts.admission_counts().0.active, 1);
    core.refresh_download_admission(&mut recovered).await;
    assert_eq!(
        core.download_attempts.admission_counts().0.active,
        1,
        "idle recovery does not speculate"
    );
    core.ed2k_transfers.apply_download_limit(0).await;
    core.admit_ready_downloads(&mut ready, &mut last, &mut workers, &clock, &shutdown)
        .await;
    assert!(ready.is_empty());
    assert_eq!(core.download_attempts.admission_counts().1, 1);
    core.refresh_download_admission(&mut recovered).await;
    assert_eq!(core.download_attempts.admission_counts().0.active, 2);
    ticks.send_replace(());
    tokio::time::timeout(Duration::from_secs(20), workers.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(&core.share(&files[1].1).await.unwrap().path).unwrap(),
        files[1].2
    );
    assert_eq!(core.download_attempts.admission_counts().1, 0);
    assert_eq!(
        core.ed2k_transfers.download_resource_snapshot().connections,
        0
    );
    for seed in seeds {
        seed.disconnect_ed2k().await.unwrap();
    }
}
