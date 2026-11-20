use super::*;
use emulebb_metadata::JobId;

fn manifest_fixture() -> Ed2kResumeManifest {
    Ed2kResumeManifest::new(&super::super::Ed2kTransferJob {
        token: emulebb_metadata::JobToken {
            job_id: JobId::new(1).unwrap(),
            generation: 1,
        },
        file_hash: "11".repeat(16),
        display_name: "Sample.bin".into(),
        file_size: 1024,
        piece_size: super::super::ED2K_PART_SIZE,
    })
}

#[test]
fn reader_departure_before_unwrap_still_requires_mutable_allowance() {
    let control = Arc::new(ResidentControl::default());
    let mut current = control.copy_manifest(&manifest_fixture()).unwrap();
    let reader = current.clone();
    assert!(Arc::get_mut(&mut current.0).is_none());
    drop(reader);
    let allocation = Arc::try_unwrap(current.0).unwrap();
    assert!(allocation.reservation.bytes < MANIFEST_BYTES);
    let draft = ResidentManifest::edit_unwrapped(allocation).unwrap();
    assert_eq!(control.usage.lock().unwrap().bytes, MANIFEST_BYTES);
    let current = draft.freeze().unwrap();
    assert_eq!(
        control.usage.lock().unwrap().bytes,
        backing_bytes(&current).unwrap()
    );
}

#[test]
fn owned_edit_refusal_returns_intact_pin_after_unwrap_and_can_be_readmitted() {
    let control = Arc::new(ResidentControl::default());
    let mut current = control.copy_manifest(&manifest_fixture()).unwrap();
    let reader = current.clone();
    assert!(Arc::get_mut(&mut current.0).is_none());
    drop(reader);
    let mut held = Vec::new();
    while let Ok(permit) = control.reserve(current.token.job_id) {
        held.push(permit);
    }
    let before = control.usage.lock().unwrap().bytes;
    let allocation = Arc::try_unwrap(current.0).unwrap();
    let (current, error) = ResidentManifest::edit_unwrapped(allocation).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert_eq!(current.display_name, "Sample.bin");
    assert_eq!(control.usage.lock().unwrap().bytes, before);
    drop(held);
    let draft = current.try_edit_owned().unwrap();
    assert_eq!(control.usage.lock().unwrap().bytes, MANIFEST_BYTES);
    drop(draft);
    assert_eq!(control.usage.lock().unwrap().bytes, 0);
    assert_eq!(control.usage.lock().unwrap().jobs, 0);
}

#[test]
fn maximum_geometry_reports_concurrent_resident_requirement() {
    let mut manifest = manifest_fixture();
    let job = super::super::Ed2kTransferJob {
        token: manifest.token,
        file_hash: manifest.file_hash.clone(),
        display_name: "n".repeat(65_536),
        file_size: 0x4000000000,
        piece_size: super::super::ED2K_PART_SIZE,
    };
    manifest = Ed2kResumeManifest::new(&job);
    manifest.comment = "c".repeat(65_536);
    manifest.delivered_path = Some(std::path::PathBuf::from("p".repeat(32_768)));
    let count = manifest.pieces.len();
    manifest.md4_hashset = (0..count).map(|_| hex::encode([0u8; 16])).collect();
    manifest.aich_hashset = (0..count).map(|_| hex::encode([0u8; 20])).collect();
    manifest.aich_root = Some(hex::encode([0u8; 20]));
    manifest.verified_ranges = (0..count)
        .step_by(2)
        .map(|index| super::super::Ed2kSharedRange {
            start: index as u64 * manifest.piece_size,
            end: ((index as u64 + 1) * manifest.piece_size).min(manifest.file_size),
        })
        .collect();
    for piece in &mut manifest.pieces {
        piece.block_bitmap = Some("55".repeat(7));
    }
    let one = backing_bytes(&manifest).unwrap();
    let selected = MAX_JOBS * one;
    let writers = super::super::local_mutation::MAX_UNITS;
    let with_writer = selected + writers * MANIFEST_BYTES;
    eprintln!(
        "resident capacity: per_job={one}, selected_jobs={MAX_JOBS}, selected_bytes={selected}, concurrent_writers={writers}, with_writers={with_writer}, cap={MAX_BYTES}"
    );
    assert!(one <= MANIFEST_BYTES);
    assert!(
        with_writer <= MAX_BYTES,
        "resident cap must cover selected geometry plus all admitted replacements"
    );
    let control = Arc::new(ResidentControl::default());
    let mut residents = Vec::with_capacity(MAX_JOBS);
    for id in 1..=MAX_JOBS {
        let job_id = JobId::new(id as i64).unwrap();
        let reservation = control.reserve(job_id).unwrap();
        let mut backing = manifest.clone();
        backing.token.job_id = job_id;
        residents.push(reservation.publish(backing).unwrap());
    }
    let old_pins: Vec<_> = residents.iter().take(writers).cloned().collect();
    let permits: Vec<_> = residents
        .iter()
        .take(writers)
        .map(|resident| control.reserve(resident.token.job_id).unwrap())
        .collect();
    assert!(control.usage.lock().unwrap().bytes <= MAX_BYTES);
    for (resident, permit) in residents.iter_mut().zip(permits) {
        resident
            .write_with(permit, |manifest| {
                manifest.rating = 1;
                Ok(())
            })
            .unwrap();
    }
    assert!(old_pins.iter().all(|resident| resident.rating == 0));
    assert!(
        residents
            .iter()
            .take(writers)
            .all(|resident| resident.rating == 1)
    );
    drop(old_pins);
    assert_eq!(
        control.usage.lock().unwrap().bytes,
        residents
            .iter()
            .map(|resident| backing_bytes(resident).unwrap())
            .sum::<usize>()
    );
    drop(residents);
    assert_eq!(control.usage.lock().unwrap().bytes, 0);
    assert_eq!(control.usage.lock().unwrap().jobs, 0);
}

#[test]
fn preadmitted_write_preserves_old_pin_and_releases_replacement_slack() {
    let control = Arc::new(ResidentControl::default());
    let mut current = control.copy_manifest(&manifest_fixture()).unwrap();
    let old = current.clone();
    let permit = control.reserve(current.token.job_id).unwrap();
    current
        .write_with(permit, |manifest| {
            manifest.comment = "Updated".into();
            Ok(())
        })
        .unwrap();
    assert!(old.comment.is_empty());
    assert_eq!(current.comment, "Updated");
    assert!(!Arc::ptr_eq(&old.0, &current.0));
    assert_eq!(control.usage.lock().unwrap().jobs, 1);
    assert_eq!(
        control.usage.lock().unwrap().bytes,
        backing_bytes(&old).unwrap() + backing_bytes(&current).unwrap()
    );
    drop(old);
    assert_eq!(
        control.usage.lock().unwrap().bytes,
        backing_bytes(&current).unwrap()
    );
}

#[test]
fn unpinned_write_reuses_backing_and_settles_after_rejected_delta() {
    let control = Arc::new(ResidentControl::default());
    let mut current = control.copy_manifest(&manifest_fixture()).unwrap();
    let identity = Arc::as_ptr(&current.0);
    for _ in 0..16 {
        let permit = control.reserve(current.token.job_id).unwrap();
        current
            .write_with(permit, |manifest| {
                manifest.comment = "Updated".into();
                Ok(())
            })
            .unwrap();
        assert_eq!(Arc::as_ptr(&current.0), identity);
        assert_eq!(
            control.usage.lock().unwrap().bytes,
            backing_bytes(&current).unwrap()
        );
    }
    let permit = control.reserve(current.token.job_id).unwrap();
    assert!(
        current
            .write_with(permit, |_| anyhow::bail!("rejected delta"))
            .is_err()
    );
    assert_eq!(
        control.usage.lock().unwrap().bytes,
        backing_bytes(&current).unwrap()
    );
}

#[test]
fn backing_release_wakes_existing_registry_without_task_completion() {
    let registry = super::super::local_mutation::LocalMutationRegistry::default();
    let mut reservation = registry.residents.reserve(JobId::new(1).unwrap()).unwrap();
    let before = registry.capacity_revision();
    reservation.resize(1024).unwrap();
    assert!(registry.capacity_revision() > before);
    let before = registry.capacity_revision();
    reservation.resize(1024).unwrap();
    assert_eq!(registry.capacity_revision(), before);
    drop(reservation);
    assert!(registry.capacity_revision() > before);
}

#[test]
fn retained_charge_and_shared_job_slot_follow_last_owner() {
    let control = Arc::new(ResidentControl::default());
    let mut original = control.reserve(JobId::new(1).unwrap()).unwrap();
    original.resize(1024).unwrap();
    let mut replacement = original.copy().unwrap();
    replacement.resize(2048).unwrap();
    {
        let usage = control.usage.lock().unwrap();
        assert_eq!(usage.bytes, 3072);
        assert_eq!(usage.jobs, 1);
    }
    drop(original);
    {
        let usage = control.usage.lock().unwrap();
        assert_eq!(usage.bytes, 2048);
        assert_eq!(usage.jobs, 1);
    }
    drop(replacement);
    let usage = control.usage.lock().unwrap();
    assert_eq!(usage.bytes, 0);
    assert_eq!(usage.jobs, 0);
    assert!(usage.slots.is_empty());
}

#[test]
fn failed_growth_preserves_existing_charge_and_reservation() {
    let control = Arc::new(ResidentControl::default());
    let mut first = control.reserve(JobId::new(1).unwrap()).unwrap();
    first.resize(1024).unwrap();
    let mut rest = Vec::new();
    while let Ok(reservation) = first.copy() {
        rest.push(reservation);
    }
    let replacement = rest.pop().unwrap();
    let before = control.usage.lock().unwrap().bytes;
    assert!(first.resize(MANIFEST_BYTES).is_err());
    assert_eq!(first.bytes, 1024);
    assert_eq!(control.usage.lock().unwrap().bytes, before);
    drop(replacement);
    first.resize(MANIFEST_BYTES).unwrap();
    assert_eq!(
        control.usage.lock().unwrap().bytes,
        (rest.len() + 1) * MANIFEST_BYTES
    );
}

#[test]
fn distinct_job_limit_survives_multiple_reservations_per_job() {
    let control = Arc::new(ResidentControl::default());
    let mut reservations = Vec::new();
    for id in 1..=MAX_JOBS {
        let mut reservation = control.reserve(JobId::new(id as i64).unwrap()).unwrap();
        reservation.resize(1024).unwrap();
        reservations.push(reservation);
    }
    assert!(
        control
            .reserve(JobId::new(MAX_JOBS as i64 + 1).unwrap())
            .is_err()
    );
    let same_job = reservations[0].copy().unwrap();
    drop(reservations.remove(0));
    assert!(
        control
            .reserve(JobId::new(MAX_JOBS as i64 + 1).unwrap())
            .is_err()
    );
    drop(same_job);
    assert!(
        control
            .reserve(JobId::new(MAX_JOBS as i64 + 1).unwrap())
            .is_ok()
    );
}

#[tokio::test]
async fn prefix_appends_reuse_unpinned_backing_and_keep_old_readers_immutable() {
    let root = crate::paths::unique_test_dir("resident-prefix-delta");
    let runtime = super::super::Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = super::super::test_support::admit_download_job(
        &runtime,
        "11".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        super::super::ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    let identity = Arc::as_ptr(
        &runtime
            .manifest_cache
            .lock()
            .await
            .get(&job.token.job_id)
            .unwrap()
            .0,
    );
    let bytes = vec![0x33; super::super::ED2K_EMBLOCK_SIZE as usize];
    for index in 0..10 {
        let start = index * super::super::ED2K_EMBLOCK_SIZE;
        let (_, result) = runtime
            .append_piece_block_with_manifest(
                job.token,
                0,
                start,
                start + bytes.len() as u64,
                &bytes,
            )
            .await
            .unwrap();
        assert_eq!(
            Arc::as_ptr(&result.0),
            identity,
            "unpinned prefix must not clone full geometry"
        );
        drop(result);
    }
    let old = runtime.manifest(job.token).await.unwrap();
    let previous_progress = old.pieces[0].bytes_written;
    let (_, result) = runtime
        .append_piece_block_with_manifest(
            job.token,
            0,
            previous_progress,
            previous_progress + bytes.len() as u64,
            &bytes,
        )
        .await
        .unwrap();
    assert_ne!(Arc::as_ptr(&result.0), identity);
    assert_eq!(old.pieces[0].bytes_written, previous_progress);
    assert_eq!(
        result.pieces[0].bytes_written,
        previous_progress + bytes.len() as u64
    );
    drop(result);
    drop(old);
    assert_eq!(
        runtime.checkpoint_dirty_download_progress().await.unwrap(),
        1
    );
}

#[tokio::test]
async fn resident_pressure_rejects_prefix_before_payload_or_cache_mutation() {
    let root = crate::paths::unique_test_dir("resident-prefix-pressure");
    let runtime = super::super::Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = super::super::test_support::admit_download_job(
        &runtime,
        "22".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        super::super::ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    let before = std::fs::metadata(runtime.payload_path(job.token.job_id).unwrap())
        .ok()
        .map(|metadata| metadata.len());
    let mut held = Vec::new();
    while let Ok(permit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
        held.push(permit);
    }
    let error = runtime
        .append_piece_block_with_manifest(job.token, 0, 0, 32, &[0x55; 32])
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert_eq!(
        std::fs::metadata(runtime.payload_path(job.token.job_id).unwrap())
            .ok()
            .map(|metadata| metadata.len()),
        before
    );
    assert_eq!(
        runtime
            .manifest_cache
            .lock()
            .await
            .get(&job.token.job_id)
            .unwrap()
            .pieces[0]
            .bytes_written,
        0
    );
    drop(held);
    runtime
        .append_piece_block_with_manifest(job.token, 0, 0, 32, &[0x55; 32])
        .await
        .unwrap();
}

#[tokio::test]
async fn ordinary_store_refuses_before_sql_when_credit_or_revision_is_exhausted() {
    for exhausted_revision in [false, true] {
        let root = crate::paths::unique_test_dir("resident-store-preadmission");
        let runtime = super::super::Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let job = super::super::test_support::admit_download_job(
            &runtime,
            "66".repeat(16).parse().unwrap(),
            "Sample.bin".into(),
            super::super::ED2K_PART_SIZE,
        );
        let old = runtime.ensure_job(&job).await.unwrap();
        let io = runtime.lock_manifest(job.token).await;
        let before = runtime
            .metadata
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        let mut proposed = (*old).clone();
        proposed.pieces[0].bytes_written = 32;
        let mut held = Vec::new();
        if exhausted_revision {
            runtime
                .manifest_checkpoint_state
                .lock()
                .await
                .get_mut(&job.token)
                .unwrap()
                .revision = u64::MAX;
        } else {
            while let Ok(permit) = runtime.local_mutations.residents.reserve(job.token.job_id) {
                held.push(permit);
            }
        }
        let error = runtime
            .store_manifest_unlocked(&proposed, io.clone())
            .await
            .unwrap_err();
        if exhausted_revision {
            assert!(error.to_string().contains("revision exhausted"));
        } else {
            assert!(matches!(
                error.downcast_ref::<LocalMutationError>(),
                Some(LocalMutationError::Busy)
            ));
        }
        assert_eq!(
            runtime
                .metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap(),
            before
        );
        assert!(Arc::ptr_eq(
            &runtime.manifest_cache.lock().await[&job.token.job_id].0,
            &old.0
        ));
        drop(held);
        if exhausted_revision {
            runtime
                .manifest_checkpoint_state
                .lock()
                .await
                .get_mut(&job.token)
                .unwrap()
                .revision = 0;
        }
        runtime
            .store_manifest_unlocked(&proposed, io)
            .await
            .unwrap();
        assert_eq!(
            runtime
                .metadata
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces[0]
                .prefix_bytes,
            32
        );
        assert_eq!(old.pieces[0].bytes_written, 0);
    }
}

#[tokio::test]
async fn cancelled_store_retains_io_until_publication_before_the_next_writer_snapshots() {
    let root = crate::paths::unique_test_dir("resident-store-competing-writers");
    let runtime = Arc::new(super::super::Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = super::super::test_support::admit_download_job(
        &runtime,
        "77".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        2 * super::super::ED2K_PART_SIZE,
    );
    let old = runtime.ensure_job(&job).await.unwrap();
    let (reached, ready) = tokio::sync::oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(reached, resume);
    let token = job.token;
    let owner = Arc::clone(&runtime);
    let caller = tokio::spawn(async move {
        let io = owner.lock_manifest(token).await;
        let mut proposal = owner.load_manifest_unlocked(token).await?.edit()?;
        proposal.pieces[0].bytes_written = 32;
        owner.store_manifest_unlocked(&proposal, io).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), ready)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .metadata
            .download_job_manifest(token.job_id)
            .unwrap()
            .unwrap()
            .pieces[0]
            .prefix_bytes,
        32
    );
    let reader_during_sql = runtime.manifest_cache.lock().await[&token.job_id].clone();
    assert_eq!(reader_during_sql.pieces[0].bytes_written, 0);
    let mut held = Vec::new();
    while let Ok(permit) = runtime.local_mutations.residents.reserve(token.job_id) {
        held.push(permit);
    }
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        super::super::store::scoped_lock(&runtime.manifest_locks, token.job_id)
            .try_lock_owned()
            .is_none()
    );
    let (captured, snapshot) = tokio::sync::oneshot::channel();
    let (allow, allowed) = tokio::sync::oneshot::channel();
    let owner = Arc::clone(&runtime);
    let second = tokio::spawn(async move {
        let io = owner.lock_manifest(token).await;
        let mut proposal = owner.load_manifest_unlocked(token).await?.edit()?;
        let _ = captured.send(proposal.pieces[0].bytes_written);
        let _ = allowed.await;
        proposal.pieces[1].bytes_written = 64;
        owner.store_manifest_unlocked(&proposal, io).await
    });
    release.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), snapshot)
            .await
            .unwrap()
            .unwrap(),
        32
    );
    drop(held);
    allow.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let current = runtime.manifest_cache.lock().await[&token.job_id].clone();
    assert_eq!(current.pieces[0].bytes_written, 32);
    assert_eq!(current.pieces[1].bytes_written, 64);
    assert_eq!(reader_during_sql.pieces[0].bytes_written, 0);
    let stored = runtime
        .metadata
        .download_job_manifest(token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.pieces[0].prefix_bytes, 32);
    assert_eq!(stored.pieces[1].prefix_bytes, 64);
    let states = runtime.manifest_checkpoint_state.lock().await;
    assert_eq!(states[&token].persisted_bytes_written, 96);
    assert!(states[&token].dirty_piece_indexes.is_empty());
    drop(states);
    assert_eq!(
        runtime
            .local_mutations
            .residents
            .usage
            .lock()
            .unwrap()
            .bytes,
        backing_bytes(&old).unwrap() + backing_bytes(&current).unwrap() + size_of::<u64>()
    );
    drop(old);
    drop(reader_during_sql);
    assert_eq!(
        runtime
            .local_mutations
            .residents
            .usage
            .lock()
            .unwrap()
            .bytes,
        backing_bytes(&current).unwrap() + size_of::<u64>()
    );
}

#[test]
fn rejected_joint_admission_spends_no_credit_and_creates_no_retry_wake() {
    let registry = super::super::local_mutation::LocalMutationRegistry::default();
    let before = registry.capacity_revision();
    let result = registry.residents.reserve_with(JobId::new(1).unwrap(), || {
        Err::<(), _>(LocalMutationError::Busy.into())
    });
    assert!(result.is_err());
    let usage = registry.residents.usage.lock().unwrap();
    assert_eq!(usage.bytes, 0);
    assert_eq!(usage.jobs, 0);
    drop(usage);
    assert_eq!(registry.capacity_revision(), before);
}

#[tokio::test]
async fn hydration_waits_for_content_without_holding_a_category_reader() {
    use super::super::local_mutation::job_read::{JobRead, JobReadResult};
    use std::{
        future::{Future, poll_fn},
        task::Poll,
        time::Duration,
    };
    let root = crate::paths::unique_test_dir("resident-hydration-lock-order");
    let runtime = super::super::Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = super::super::test_support::admit_download_job(
        &runtime,
        "88".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        super::super::ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    runtime
        .manifest_cache
        .lock()
        .await
        .remove(&job.token.job_id);
    let content = runtime.lock_content(&job.file_hash).await;
    let (reached, ready) = tokio::sync::oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(reached, resume);
    let receipt = runtime
        .local_mutations
        .submit_job_read(&runtime, JobRead::SelectExecution(job.token))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), ready)
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    // The held guard owns two strong mutex references. Two more prove the
    // hydration worker has entered its content-lock wait, without a sleep race.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .content_locks
                .lock()
                .unwrap()
                .get(&job.file_hash)
                .is_some_and(|lock| lock.strong_count() >= 4)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut writer = Box::pin(Arc::clone(&runtime.category_assignment_gate).write_owned());
    let Poll::Ready(writer) = poll_fn(|cx| Poll::Ready(writer.as_mut().poll(cx))).await else {
        panic!("hydration retained category read while waiting for content");
    };
    drop(writer);
    let category = runtime.category_assignment_gate.read().await;
    drop(content);
    let JobReadResult::Execution(Some(current)) =
        tokio::time::timeout(Duration::from_secs(5), receipt)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    else {
        panic!("missing selected execution");
    };
    assert_eq!(current.token, job.token);
    drop(category);
}

#[tokio::test]
async fn stale_private_hydration_cannot_activate_after_committed_metadata_change() {
    use super::super::local_mutation::job_read::JobRead;
    let root = crate::paths::unique_test_dir("resident-hydration-observation");
    let runtime = super::super::Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = super::super::test_support::admit_download_job(
        &runtime,
        "44".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        super::super::ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    runtime
        .manifest_cache
        .lock()
        .await
        .remove(&job.token.job_id);
    let (reached, ready) = tokio::sync::oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(reached, resume);
    let receipt = runtime
        .local_mutations
        .submit_job_read(&runtime, JobRead::SelectExecution(job.token))
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), ready)
        .await
        .unwrap()
        .unwrap();
    runtime
        .metadata
        .update_shared_content_metadata(&job.file_hash, None, Some(("updated", 0)))
        .unwrap();
    release.send(()).unwrap();
    let error = receipt
        .await
        .unwrap()
        .err()
        .expect("stale hydration must fail");
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert!(
        !runtime
            .manifest_cache
            .lock()
            .await
            .contains_key(&job.token.job_id)
    );
    let current = runtime.ensure_job(&job).await.unwrap();
    assert_eq!(current.comment, "updated");
}

#[tokio::test]
async fn private_hydration_keeps_newer_dirty_resident_and_its_accounting() {
    use super::super::local_mutation::job_read::{JobRead, JobReadResult};
    let root = crate::paths::unique_test_dir("resident-hydration-current-cache");
    let runtime = super::super::Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let job = super::super::test_support::admit_download_job(
        &runtime,
        "55".repeat(16).parse().unwrap(),
        "Sample.bin".into(),
        super::super::ED2K_PART_SIZE,
    );
    drop(runtime.ensure_job(&job).await.unwrap());
    runtime
        .manifest_cache
        .lock()
        .await
        .remove(&job.token.job_id);
    let (reached, ready) = tokio::sync::oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(reached, resume);
    let receipt = runtime
        .local_mutations
        .submit_job_read(&runtime, JobRead::SelectExecution(job.token))
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), ready)
        .await
        .unwrap()
        .unwrap();
    let mut newer = Ed2kResumeManifest::new(&job);
    newer.pieces[0].bytes_written = 8;
    runtime.note_dirty_piece_unlocked(&newer, 0).await.unwrap();
    let current = runtime.cache_manifest_unlocked(&newer).await.unwrap();
    release.send(()).unwrap();
    let JobReadResult::Execution(Some(result)) = receipt.await.unwrap().unwrap() else {
        panic!("selected execution missing")
    };
    assert!(Arc::ptr_eq(&current.0, &result.0));
    assert_eq!(result.pieces[0].bytes_written, 8);
    assert!(
        runtime.manifest_checkpoint_state.lock().await[&job.token]
            .dirty_piece_indexes
            .contains(&0)
    );
    assert_eq!(
        runtime
            .metadata
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .checkpointed_bytes,
        0
    );
}
