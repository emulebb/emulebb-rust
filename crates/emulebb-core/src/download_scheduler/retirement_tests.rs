use super::*;
use crate::{DownloadCreate, DownloadCreateSource};
use emulebb_index::FileIndex;
use emulebb_metadata::{DownloadIntent, JobToken};
use std::{net::Ipv4Addr, sync::atomic::Ordering};

async fn prepared() -> (EmulebbCore, DownloadAttemptGuard, JobToken) {
    let core =
        EmulebbCore::new_in_memory("test", emulebb_index::FileIndex::in_memory().unwrap()).unwrap();
    let (_, created) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: "56565656565656565656565656565656".into(),
                name: "Sample.bin".into(),
                size_bytes: Some(16),
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
    let mut guard = core
        .download_attempts
        .try_enter(job.token, job.file_hash.parse().unwrap())
        .unwrap();
    let token = job.token;
    drop(job);
    let started = core
        .ed2k_transfers
        .begin_download_job_execution(token, Some(&core.transfer_root))
        .await
        .unwrap();
    let job = started.as_ref().unwrap();
    let selected = emulebb_ed2k::ed2k_transfer::new_transfer_job(
        job.token,
        job.file_hash.parse().unwrap(),
        job.display_name.clone(),
        job.expected_size_bytes.unwrap(),
    );
    assert!(guard.rebind(job.token));
    let token = job.token;
    drop(started);
    drop(core.ed2k_transfers.ensure_job(&selected).await.unwrap());
    (core, guard, token)
}

#[tokio::test]
async fn unsuccessful_hydration_retires_begun_execution_and_only_faults_storage_errors() {
    use emulebb_ed2k::ed2k_transfer::LocalMutationError;
    for case in 0..4 {
        let (core, guard, token) = prepared().await;
        let result = match case {
            0 => Ok(None),
            1 => Err(LocalMutationError::Busy.into()),
            2 => Err(LocalMutationError::Closing.into()),
            _ => Err(anyhow::anyhow!("synthetic storage preparation failure")),
        };
        let before = core.download_attempts.available();
        let (_ticks, mut clock) = watch::channel(());
        assert!(
            core.finish_download_hydration(&guard, result, &mut clock, &CancellationToken::new())
                .await
                .is_none()
        );
        assert!(guard.cancellation().is_cancelled());
        assert_eq!(
            core.download_attempts.available(),
            before,
            "cleanup retains ownership until the guard drops"
        );
        let current = core
            .ed2k_transfers
            .download_job(token.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.intent, DownloadIntent::Started);
        assert!(current.token.generation > token.generation);
        if case == 3 {
            assert_eq!(
                current.storage_failure.as_ref().unwrap().code(),
                "STORAGE_PREPARATION_FAILED"
            );
            assert!(
                core.ed2k_transfers
                    .download_jobs_after(None, 1, true)
                    .await
                    .unwrap()
                    .is_empty()
            );
        } else {
            assert!(current.storage_failure.is_none());
            assert_eq!(
                core.ed2k_transfers
                    .download_jobs_after(None, 1, true)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        drop(current);
        assert!(
            core.ed2k_transfers
                .manifest_optional(token)
                .await
                .unwrap()
                .is_none(),
            "old cache backing must be retired"
        );
        drop(guard);
        assert_eq!(core.download_attempts.available().0, before.0 + 1);
    }
}

#[tokio::test]
async fn successful_hydration_keeps_native_execution_and_attempt_owned() {
    let (core, guard, token) = prepared().await;
    let manifest = core.ed2k_transfers.manifest(token).await.unwrap();
    let transfer = core
        .transfer_from_manifest(&manifest, "downloading")
        .unwrap();
    drop(manifest);
    let (_ticks, mut clock) = watch::channel(());
    let shutdown = CancellationToken::new();
    assert!(
        core.finish_download_hydration(&guard, Ok(Some(transfer)), &mut clock, &shutdown)
            .await
            .is_some()
    );
    assert!(!guard.cancellation().is_cancelled());
    assert!(core.download_attempts.owns(token));
    assert_eq!(
        core.ed2k_transfers
            .download_job(token.job_id)
            .await
            .unwrap()
            .unwrap()
            .token,
        token
    );
    assert!(
        core.ed2k_transfers
            .manifest_optional(token)
            .await
            .unwrap()
            .is_some()
    );
    core.retire_download_selection(&guard, &mut clock, &shutdown)
        .await;
    assert!(
        core.ed2k_transfers
            .manifest_optional(token)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn local_hydration_busy_keeps_one_execution_and_lease_until_retry_or_cancellation() {
    for action in 0..4 {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let (_, created) = core
            .create_download(DownloadCreate {
                source: DownloadCreateSource::Content {
                    hash: "95959595959595959595959595959595".into(),
                    name: "Sample.bin".into(),
                    size_bytes: Some(16),
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
        let original = job.token;
        let mut guard = core
            .download_attempts
            .try_prepare(original, job.file_hash.parse().unwrap())
            .unwrap();
        drop(job);
        let endpoint = (Ipv4Addr::LOCALHOST, 41010);
        core.state
            .lock()
            .await
            .active_download_peer_endpoints
            .insert(endpoint, original);
        let baseline = core
            .ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes;
        core.download_hydration_busy.store(true, Ordering::Release);
        let cancel = guard.cancellation();
        let shutdown = CancellationToken::new();
        let (ticks, mut clock) = tokio::sync::watch::channel(());
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(if action == 3 { 1 } else { 5 });
        let hydration = core.wait_for_download_hydration(
            &mut guard,
            Some(endpoint),
            Some(deadline),
            &mut clock,
            &shutdown,
        );
        let release = async {
            while core.download_hydration_busy.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            let current = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
            assert_eq!(current.token.generation, original.generation + 1);
            assert!(
                current
                    .storage
                    .as_ref()
                    .is_some_and(|storage| storage.identity.is_none() && !storage.path.exists())
            );
            assert!(current.storage_failure.is_none());
            assert_eq!(
                core.state
                    .lock()
                    .await
                    .active_download_peer_endpoints
                    .get(&endpoint),
                Some(&current.token)
            );
            assert!(
                core.category_mutation_gate.try_lock().is_ok(),
                "capacity waits must not hold the category gate"
            );
            let token = current.token;
            drop(current);
            assert_eq!(
                core.ed2k_transfers
                    .download_resource_snapshot()
                    .resident_bytes,
                baseline,
                "Busy was injected before manifest/storage hydration"
            );

            match action {
                0 => {
                    ticks.send_replace(());
                }
                1 => cancel.cancel(),
                2 => shutdown.cancel(),
                _ => {}
            }
            token
        };
        let (result, selected_token) = tokio::time::timeout(Duration::from_secs(6), async {
            tokio::join!(hydration, release)
        })
        .await
        .unwrap();
        let result = result.unwrap();
        assert_eq!(result.is_some(), action == 0);
        assert_eq!(
            guard.token(),
            selected_token,
            "local retries cannot begin another generation"
        );
        let current = core.ed2k_transfers.download_job(id).await.unwrap().unwrap();
        assert_eq!(current.token, selected_token);
        assert!(current.storage_failure.is_none());
        if action == 0 {
            assert!(
                current
                    .storage
                    .as_ref()
                    .is_some_and(|storage| storage.identity.is_some() && storage.path.exists())
            );
        }
        drop(current);
        core.retire_download_selection(&guard, &mut clock, &shutdown)
            .await;
        assert!(
            !core
                .state
                .lock()
                .await
                .active_download_peer_endpoints
                .contains_key(&endpoint)
        );
    }
}
