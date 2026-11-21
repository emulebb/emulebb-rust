use super::*;
use transfer::{Ed2kSourceHint, Ed2kTransferRuntime, test_support::admit_download_job};

fn source() -> Ed2kSourceHint {
    Ed2kSourceHint {
        ip: "192.0.2.1".into(),
        tcp_port: 4662,
        user_hash: Some("12".repeat(16)),
        connect_options: None,
        file_comment: String::new(),
        file_rating: 0,
    }
}

#[tokio::test]
async fn source_status_works_at_full_resident_budget_and_requires_new_session_proof() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let job = admit_download_job(
        &runtime,
        emulebb_kad_proto::Ed2kHash([0x51; 16]),
        "probe.bin".into(),
        16,
    );
    let mut full = Vec::new();
    while let Ok(credit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
        full.push(credit);
    }
    let remainder = 128 * 1024 * 1024 - runtime.download_resource_snapshot().resident_bytes;
    full.push(
        runtime
            .local_mutations
            .residents
            .reserve_bookkeeping(job.token.job_id, remainder)
            .unwrap(),
    );
    runtime
        .remember_source_availability(job.token, source(), 16, vec![true])
        .await
        .unwrap();
    let page = runtime
        .download_source_availability_after(job.token, 0, i64::MAX, 0, 256)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(page[0].has_part(0));
    assert!(
        runtime
            .download_source_has_rare_part(job.token, [0x12; 16])
            .await
            .unwrap()
    );
    assert_eq!(
        runtime.download_resource_snapshot().resident_bytes,
        128 * 1024 * 1024
    );
    assert!(runtime.manifest_cache.lock().await.is_empty());
    drop(page);
    drop(full);
    runtime.local_mutations.seal_and_drain().await.unwrap();
    drop(runtime);
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    assert!(
        !runtime
            .download_source_has_rare_part(job.token, [0x12; 16])
            .await
            .unwrap()
    );
    assert!(
        runtime
            .download_source_availability_after(job.token, 0, i64::MAX, 0, 256)
            .await
            .unwrap()
            .is_empty()
    );
    runtime
        .remember_source_availability(job.token, source(), 16, vec![true])
        .await
        .unwrap();
    assert_eq!(
        runtime
            .download_source_availability_after(job.token, 0, i64::MAX, 0, 256)
            .await
            .unwrap()
            .len(),
        1
    );
    runtime.local_mutations.seal_and_drain().await.unwrap();
}

#[tokio::test]
async fn cancelled_status_observer_preserves_owned_commit_and_releases_work_budget() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let job = admit_download_job(
        &runtime,
        emulebb_kad_proto::Ed2kHash([0x52; 16]),
        "probe.bin".into(),
        16,
    );
    let registry = Arc::clone(&runtime.local_mutations);
    let resident_before = registry.residents.used_bytes();
    let (reached, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    registry.install_publication_gate(reached, gate);
    let hint = source();
    let delta = MetadataDownloadPeerDelta::Availability {
        source: emulebb_metadata::MetadataTransferSource {
            ip: hint.ip,
            tcp_port: hint.tcp_port,
            user_hash: hint.user_hash,
            connect_options: hint.connect_options,
            file_comment: hint.file_comment,
            file_rating: hint.file_rating,
        },
        session_id: runtime.source_discovery_session,
        file_size_bytes: 16,
        available_parts: vec![true],
        observed_at_s: 10,
    };
    let receipt = registry
        .submit_peer_delta(
            &runtime,
            job.token,
            &delta,
            runtime.lock_manifest(job.token).await,
        )
        .unwrap();
    ready.await.unwrap();
    drop(receipt);
    release.send(()).unwrap();
    registry.seal_and_drain().await.unwrap();
    let page = runtime
        .metadata
        .download_job_source_availability(emulebb_metadata::MetadataDownloadAvailabilityQuery {
            token: job.token,
            session_id: runtime.source_discovery_session,
            observed_since_s: 0,
            observed_until_s: 20,
            after_source_id: 0,
            limit: 1,
        })
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(registry.state.lock().unwrap().capacity.usage().bytes, 0);
    assert_eq!(registry.residents.used_bytes(), resident_before);
}
