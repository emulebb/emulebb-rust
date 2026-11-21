use super::*;
use crate::FileIndex;
use emulebb_metadata::DownloadJobRequest;

#[tokio::test]
async fn comment_pages_skip_plain_sources_and_preserve_byte_bounded_continuation() {
    use emulebb_metadata::{MetadataDownloadPeerDelta, MetadataTransferSource};
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let name = "n".repeat(65_536);
    let job = core
        .metadata_store
        .admit_download_job(&DownloadJobRequest {
            file_hash: "28".repeat(16),
            display_name: name.clone(),
            expected_size_bytes: None,
            category_id: None,
            intent: DownloadIntent::Started,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    let mut expected = Vec::new();
    for value in 1..=300 {
        let comment = if value % 8 == 0 {
            format!("note-{value}")
        } else {
            String::new()
        };
        let rating = if value == 300 { 4 } else { 0 };
        if !comment.is_empty() || rating > 0 {
            expected.push((comment.clone(), rating));
        }
        core.metadata_store
            .apply_download_peer_delta(
                job.token,
                &MetadataDownloadPeerDelta::Source {
                    source: MetadataTransferSource {
                        ip: "192.0.2.28".into(),
                        tcp_port: value,
                        user_hash: None,
                        connect_options: None,
                        file_comment: comment,
                        file_rating: rating,
                    },
                    description_only: false,
                },
            )
            .unwrap();
    }
    assert!(core.metadata_store.stop_download_job(job.token).unwrap());
    let mut actual = Vec::new();
    let mut after = 0;
    let mut pages = 0;
    loop {
        let page = core
            .download_comments_page(job.token.job_id, after, 200)
            .await
            .unwrap()
            .unwrap();
        assert!(!page.comments.is_empty());
        assert!(page.comments.iter().all(|row| row.file_name == name));
        assert!(
            page.comments
                .iter()
                .map(|row| row.file_name.len() + row.comment.len())
                .sum::<usize>()
                < 1024 * 1024
        );
        actual.extend(
            page.comments
                .iter()
                .map(|row| (row.comment.clone(), row.rating)),
        );
        pages += 1;
        assert!(pages < 6);
        if !page.has_more {
            assert!(page.next_after.is_none());
            break;
        }
        let next = page.next_after.unwrap();
        assert!(next > after);
        after = next;
    }
    assert!(pages > 1);
    assert_eq!(actual, expected);
    assert!(
        core.ed2k_transfers
            .download_job(job.token.job_id)
            .await
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
}
pub(super) fn admit(
    core: &EmulebbCore,
    byte: u32,
    size: Option<u64>,
    intent: DownloadIntent,
) -> DownloadJobRecord {
    core.metadata_store
        .admit_download_job(&DownloadJobRequest {
            file_hash: format!("{byte:032x}"),
            display_name: "Sample.bin".into(),
            expected_size_bytes: size,
            category_id: None,
            intent,
            piece_size: emulebb_ed2k::ed2k_transfer::ED2K_PART_SIZE,
        })
        .unwrap()
        .job
}
#[tokio::test]
async fn header_pages_browse_history_in_numeric_order_without_allocating_storage() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    for id in 1..=1000 {
        admit(&core, id, Some(8), DownloadIntent::Stopped);
    }
    let first = core
        .download_page(DownloadJobQuery::default())
        .await
        .unwrap();
    assert_eq!(first.downloads.len(), 100);
    assert!(first.has_more);
    assert!(
        first
            .downloads
            .windows(2)
            .all(|pair| pair[0].id > pair[1].id)
    );
    assert!(
        first
            .downloads
            .iter()
            .all(|download| download.state == DownloadState::Stopped)
    );
    let second = core
        .download_page(DownloadJobQuery {
            before: first.next_before,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(second.downloads.len(), 100);
    assert!(
        second
            .downloads
            .iter()
            .all(|download| download.id < first.downloads.last().unwrap().id)
    );
    assert!(
        core.ed2k_transfers
            .download_job(second.downloads[0].id)
            .await
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
}
#[tokio::test]
async fn unknown_size_projection_has_canonical_identity_shape_and_seconds() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let job = admit(&core, 1, None, DownloadIntent::Started);
    let page = core.download_page(Default::default()).await.unwrap();
    let value = serde_json::to_value(&page.downloads[0]).unwrap();
    let expected: std::collections::BTreeSet<_> = [
        "id",
        "hash",
        "name",
        "sizeBytes",
        "progress",
        "intent",
        "state",
        "waitingReason",
        "category",
        "createdAt",
        "updatedAt",
        "completedAt",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    assert_eq!(value["id"], job.token.job_id.to_string());
    assert_eq!(value["hash"], job.file_hash);
    assert!(value["sizeBytes"].is_null());
    assert!(value["progress"].is_null());
    assert_eq!(value["state"], "waiting-metadata");
    assert!(value["waitingReason"].is_null());
    assert_eq!(value["createdAt"], job.created_at_s);
}
#[test]
fn draining_generation_is_not_reported_stopped_or_downloading() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let mut job = admit(&core, 1, Some(8), DownloadIntent::Started);
    let old = job.token;
    assert_eq!(
        observed_state(&job, &[(old, false)], &[]),
        DownloadState::Downloading
    );
    job.token.generation += 1;
    assert_eq!(
        observed_state(&job, &[(old, false)], &[]),
        DownloadState::Stopping
    );
    job.intent = DownloadIntent::Stopped;
    assert_eq!(
        observed_state(&job, &[(old, true)], &[]),
        DownloadState::Stopping
    );
    assert_eq!(observed_state(&job, &[], &[]), DownloadState::Stopped);
}

#[tokio::test]
async fn creation_keeps_queued_geometry_lazy_and_duplicate_admission_unchanged() {
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let request = serde_json::from_value(serde_json::json!({
        "source": {"type":"content", "hash":"00112233445566778899aabbccddeeff", "name":"Chosen.bin", "sizeBytes":null},
        "intent":"stopped"
    })).unwrap();
    let (created, first) = core.create_download(request).await.unwrap();
    assert!(created);
    assert_eq!(first.state, DownloadState::Stopped);
    assert_eq!(first.size_bytes, None);
    let id = first.id;
    drop(first);
    let duplicate = serde_json::from_value(serde_json::json!({
        "source": {"type":"ed2k-link", "link":"ed2k://|file|Other.bin|8|00112233445566778899aabbccddeeff|/"},
        "redownload":true
    })).unwrap();
    let (created, second) = core.create_download(duplicate).await.unwrap();
    assert!(!created);
    assert_eq!(second.id, id);
    assert_eq!(second.name, "Chosen.bin");
    assert_eq!(second.intent, DownloadIntent::Stopped);
    assert_eq!(second.size_bytes, None);
    drop(second);
    let job = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    assert!(job.storage.is_none());
}

#[test]
fn creation_defaults_start_one_content_source_and_use_the_native_intent_domain() {
    let input: crate::DownloadCreate = serde_json::from_value(serde_json::json!({
        "source": {"type":"content", "hash":"00112233445566778899aabbccddeeff", "name":"Sample.bin"}
    }))
    .unwrap();
    assert_eq!(input.intent, DownloadIntent::Started);
    assert!(!input.redownload);
    assert!(input.category.is_none());
    let serialized = serde_json::to_value(input).unwrap();
    assert_eq!(serialized["intent"], "started");
    assert!(serialized["source"]["sizeBytes"].is_null());
}

#[tokio::test]
async fn job_controls_preserve_allocation_and_require_explicit_storage_failure_retry() {
    use crate::DownloadChange;
    let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    let (_, admitted) = core.create_download(serde_json::from_value(serde_json::json!({
        "source": {"type":"content", "hash":"00112233445566778899aabbccddeeff", "name":"Sample.bin", "sizeBytes":8},
        "intent":"stopped"
    })).unwrap()).await.unwrap();
    let id = admitted.id;
    drop(admitted);
    assert_eq!(
        core.start_download(id).await.unwrap(),
        DownloadChange::Changed
    );
    let started = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    let token = started.token;
    let allocation = started.storage.clone();
    drop(started);
    assert_eq!(
        core.start_download(id).await.unwrap(),
        DownloadChange::Unchanged
    );
    let failure = emulebb_metadata::DownloadJobStorageFailure::new(
        "STORAGE_UNAVAILABLE",
        "sample storage unavailable",
        1,
    )
    .unwrap();
    let failed = core
        .ed2k_transfers
        .fail_download_job_storage(token, &failure)
        .await
        .unwrap();
    assert!(failed.applied);
    let failed_token = failed.job.as_ref().unwrap().token;
    drop(failed);
    let failed = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    assert_eq!(failed.storage_failure.as_ref(), Some(&failure));
    drop(failed);
    assert_eq!(
        core.start_download(id).await.unwrap(),
        DownloadChange::Changed
    );
    let retried = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
    assert!(retried.storage_failure.is_none());
    assert_ne!(retried.token, failed_token);
    assert_eq!(retried.storage, allocation);
    drop(retried);
    assert_eq!(
        core.stop_download(id).await.unwrap(),
        DownloadChange::Changed
    );
    assert_eq!(
        core.stop_download(id).await.unwrap(),
        DownloadChange::Unchanged
    );
    assert_eq!(
        core.remove_download(id, false).await.unwrap(),
        DownloadChange::Changed
    );
    assert!(
        core.ed2k_transfers
            .download_job(id)
            .await
            .unwrap()
            .unwrap()
            .removed_at_s
            .is_some()
    );
}
