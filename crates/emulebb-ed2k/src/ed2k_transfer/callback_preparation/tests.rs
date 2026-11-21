use super::*;

#[tokio::test]
async fn captured_request_acknowledgment_cannot_consume_a_new_preparation_for_the_same_execution() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let download = work(&runtime);
    let first = runtime
        .prepare_callback_download(download.clone(), Duration::from_secs(3))
        .unwrap();
    let server = "192.0.2.10:4661".parse().unwrap();
    runtime
        .reserve_callback_ticket(
            super::super::Ed2kCallbackTicketRequest::server(
                server,
                17,
                None,
                4662,
                first.download().clone(),
                Duration::from_secs(3),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut claim = runtime
        .claim_callback_session(super::super::Ed2kCallbackHelloIdentity {
            user_hash: [0x49; 16],
            client_id: 17,
            server_endpoint: Some(server),
            peer_ip: Some("192.0.2.10".parse().unwrap()),
            tcp_port: 4662,
        })
        .unwrap()
        .unwrap();
    let captured = claim.current().unwrap().unwrap();
    let second = runtime
        .prepare_callback_download(download, Duration::from_secs(3))
        .unwrap();
    runtime
        .reserve_callback_ticket(
            super::super::Ed2kCallbackTicketRequest::server(
                server,
                17,
                None,
                4662,
                second.download().clone(),
                Duration::from_secs(3),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    claim.acknowledge_download(&captured).unwrap();
    assert_eq!(
        claim
            .current()
            .unwrap()
            .as_ref()
            .map(|download| download.preparation_id),
        Some(second.download().preparation_id)
    );
    drop(claim);
}

fn work(runtime: &Ed2kTransferRuntime) -> Ed2kCallbackDownload {
    let job = crate::ed2k_transfer::test_support::admit_download_job(
        runtime,
        emulebb_kad_proto::Ed2kHash([0x48; 16]),
        "Sample.bin".into(),
        16,
    );
    Ed2kCallbackDownload {
        preparation_id: None,
        job_token: job.token,
        file_hash: job.file_hash.parse().unwrap(),
        display_name: "Sample.bin".into(),
        file_size: 16,
        source: super::super::Ed2kSourceHint {
            ip: "192.0.2.10".into(),
            tcp_port: 4662,
            user_hash: None,
            connect_options: None,
            file_comment: String::new(),
            file_rating: 0,
        },
    }
}

#[tokio::test]
async fn claimed_preparation_retains_capacity_until_listener_settlement() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let download = work(&runtime);
    let first = runtime
        .prepare_callback_download(download.clone(), Duration::from_secs(3))
        .unwrap();
    let second = runtime
        .prepare_callback_download(download.clone(), Duration::from_secs(3))
        .unwrap();
    assert!(
        runtime
            .prepare_callback_download(download.clone(), Duration::from_secs(3))
            .is_err()
    );
    let captured = first.download().clone();
    let session = runtime
        .claim_callback_preparation(&captured)
        .unwrap()
        .unwrap();
    assert!(
        runtime
            .claim_callback_preparation(&captured)
            .unwrap()
            .is_none()
    );
    drop(first);
    assert!(session.cancellation().is_cancelled());
    assert!(
        runtime
            .prepare_callback_download(download.clone(), Duration::from_secs(3))
            .is_err()
    );
    drop(session);
    let next = runtime
        .prepare_callback_download(download, Duration::from_secs(3))
        .unwrap();
    assert_ne!(next.download().preparation_id, captured.preparation_id);
    drop((second, next));
    assert!(
        runtime
            .callback_preparations
            .state
            .lock()
            .unwrap()
            .pending
            .is_empty()
    );
}

#[tokio::test]
async fn one_shot_admission_releases_preparation_capacity_and_waits_for_completion() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let download = work(&runtime);
    let mut owner = runtime
        .prepare_callback_download(download.clone(), Duration::from_secs(3))
        .unwrap();
    let mut session = runtime
        .claim_callback_preparation(owner.download())
        .unwrap()
        .unwrap();
    session
        .publish(Ed2kCallbackPreparationOutcome::Available(
            Ed2kPeerAvailability {
                peer: "192.0.2.10:4662".parse().unwrap(),
                user_hash: [0x49; 16],
                file_name: None,
                available_parts: vec![true],
            },
        ))
        .unwrap();
    assert!(matches!(
        owner.availability().await.unwrap(),
        Ed2kCallbackPreparationOutcome::Available(_)
    ));
    assert!(
        owner
            .start(JobToken {
                job_id: emulebb_metadata::JobId::new(99).unwrap(),
                ..download.job_token
            })
            .is_err()
    );
    owner.start(download.job_token).unwrap();
    assert!(owner.start(download.job_token).is_err());
    assert_eq!(
        session.admit(&runtime).await.unwrap(),
        Some(download.job_token)
    );
    let first = runtime
        .prepare_callback_download(download.clone(), Duration::from_secs(3))
        .unwrap();
    let second = runtime
        .prepare_callback_download(download, Duration::from_secs(3))
        .unwrap();
    session.complete(Ed2kPeerDownloadOutcome::Completed);
    assert_eq!(
        owner.completed().await.unwrap(),
        Ed2kPeerDownloadOutcome::Completed
    );
    drop((first, second, owner));
}

#[tokio::test]
async fn cancelled_pending_work_settles_without_a_listener_or_retained_slot() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let download = work(&runtime);
    let mut owner = runtime
        .prepare_callback_download(download.clone(), Duration::from_secs(3))
        .unwrap();
    owner.cancel();
    assert!(owner.completed().await.is_err());
    assert!(
        runtime
            .claim_callback_preparation(owner.download())
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .prepare_callback_download(download, Duration::from_secs(3))
            .is_ok()
    );
}
