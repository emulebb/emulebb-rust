use super::*;
fn token(id: i64, generation: u64) -> JobToken {
    JobToken {
        job_id: JobId::new(id).unwrap(),
        generation,
    }
}
fn hash(byte: u8) -> Ed2kHash {
    Ed2kHash::from_bytes([byte; 16])
}

#[test]
fn promotion_keeps_one_guard_and_waits_for_ordinary_capacity() {
    let control = Arc::new(DownloadAttemptControl::with_limit(Some(1)));
    let active = control.try_enter(token(1, 1), hash(1)).unwrap();
    let prepared = control.try_prepare(token(2, 1), hash(2)).unwrap();
    let nonce = prepared.nonce;
    assert!(
        prepared.preparation_has_headroom(2),
        "preparation is independent of ordinary payload admission"
    );
    assert!(control.owns_observation(token(2, 1)));
    assert!(
        !control.owns(token(2, 1)),
        "preparation grants no payload authority"
    );
    assert!(!prepared.promote());
    assert_eq!(control.snapshot().len(), 1);
    assert!(matches!(
        control.try_enter(token(2, 1), hash(2)),
        Err(AdmissionDenied::Duplicate)
    ));
    drop(active);
    assert!(!prepared.preparation_has_headroom(0));
    assert!(prepared.preparation_has_headroom(1));
    assert!(prepared.promote());
    assert_eq!(prepared.nonce, nonce);
    assert!(control.owns(token(2, 1)));
    assert_eq!(control.snapshot(), [(token(2, 1), false)]);
    control.apply_concurrency_limit(Some(0));
    assert!(
        prepared.promote(),
        "already-owned executions drain after a lower limit"
    );
    assert!(control.cancel(token(2, 1).job_id));
    assert!(!prepared.promote(), "cancellation must never be revived");
    assert!(!control.owns_observation(token(2, 1)));
    assert!(prepared.cancellation().is_cancelled());
    drop(prepared);
    assert!(control.snapshot().is_empty());
}

#[test]
fn preparation_cannot_promote_while_the_shared_cohort_must_drain() {
    let control = Arc::new(DownloadAttemptControl::default());
    let first = control.try_prepare(token(1, 1), hash(1)).unwrap();
    let second = control.try_prepare(token(2, 1), hash(2)).unwrap();
    control.apply_admission_window(crate::download_admission::AdmissionWindow {
        active: 1,
        preparing: 0,
        total: 1,
    });
    assert!(!first.promote());
    assert!(!first.cancellation().is_cancelled());
    drop(second);
    assert!(first.promote());
    assert_eq!(control.available(), (0, 0));
}

#[test]
fn adaptive_window_honors_user_limit_without_initial_baseline_clipping() {
    let control = Arc::new(DownloadAttemptControl::with_limit(Some(24)));
    control.apply_admission_window(crate::download_admission::AdmissionWindow {
        active: 32,
        preparing: 2,
        total: 34,
    });
    let guards: Vec<_> = (1..=24)
        .map(|id| control.try_enter(token(id, 1), hash(id as u8)).unwrap())
        .collect();
    assert!(matches!(
        control.try_enter(token(25, 1), hash(25)),
        Err(AdmissionDenied::Busy)
    ));
    control.apply_admission_window(crate::download_admission::AdmissionWindow {
        active: 0,
        preparing: 0,
        total: 0,
    });
    assert_eq!(control.available(), (0, 0));
    assert!(
        guards
            .iter()
            .all(|guard| !guard.cancellation().is_cancelled())
    );
    assert_eq!(
        control.snapshot().len(),
        24,
        "pressure drains without cancelling owned work"
    );
    drop(guards);
    assert_eq!(control.admission_counts().1, 0);
}

#[test]
fn active_and_preparation_share_adaptive_total_capacity() {
    let control = Arc::new(DownloadAttemptControl::default());
    control.apply_admission_window(crate::download_admission::AdmissionWindow {
        active: 2,
        preparing: 2,
        total: 2,
    });
    let active = control.try_enter(token(1, 1), hash(1)).unwrap();
    let preparation = control.try_prepare(token(2, 1), hash(2)).unwrap();
    assert_eq!(control.available(), (0, 0));
    assert!(matches!(
        control.try_enter(token(3, 1), hash(3)),
        Err(AdmissionDenied::Busy)
    ));
    assert!(matches!(
        control.try_prepare(token(3, 1), hash(3)),
        Err(AdmissionDenied::Busy)
    ));
    drop(active);
    assert!(control.try_enter(token(3, 1), hash(3)).is_ok());
    drop(preparation);
}

#[tokio::test]
async fn verification_excludes_selection_until_actual_execution_retirement() {
    let control = Arc::new(DownloadAttemptControl::default());
    let active = control.try_enter(token(1, 1), hash(1)).unwrap();
    let verification = control.try_verify(token(1, 1), hash(1)).unwrap();
    assert!(active.cancellation().is_cancelled());
    assert!(matches!(
        control.try_prepare(token(1, 2), hash(1)),
        Err(AdmissionDenied::Busy)
    ));
    assert!(matches!(
        control.try_enter(token(2, 1), hash(1)),
        Err(AdmissionDenied::Busy)
    ));
    assert!(matches!(
        control.try_verify(token(1, 1), hash(1)),
        Err(AdmissionDenied::Duplicate)
    ));
    {
        let wait = verification.wait_for_execution();
        tokio::pin!(wait);
        assert!(futures_util::poll!(&mut wait).is_pending());
        drop(active);
        wait.await;
    }
    verification.rebind(token(1, 2));
    assert_eq!(control.verifications(), vec![token(1, 2)]);
    drop(verification);
    assert!(control.try_enter(token(1, 3), hash(1)).is_ok());
}

#[test]
fn verification_capacity_refusal_does_not_cancel_another_execution() {
    let control = Arc::new(DownloadAttemptControl::default());
    let first = control.try_verify(token(1, 1), hash(1)).unwrap();
    let second = control.try_verify(token(2, 1), hash(2)).unwrap();
    let active = control.try_enter(token(3, 1), hash(3)).unwrap();
    assert!(matches!(
        control.try_verify(token(3, 1), hash(3)),
        Err(AdmissionDenied::Busy)
    ));
    assert!(!active.cancellation().is_cancelled());
    drop(first);
    drop(second);
    assert!(control.verifications().is_empty());
}

#[test]
fn initial_active_and_preparation_windows_share_content_ownership() {
    let control = Arc::new(DownloadAttemptControl::default());
    let active: Vec<_> = (1..=16)
        .map(|id| control.try_enter(token(id, 1), hash(id as u8)).unwrap())
        .collect();
    let first = control.try_prepare(token(17, 1), hash(17)).unwrap();
    let second = control.try_prepare(token(18, 1), hash(18)).unwrap();
    assert_eq!(control.available(), (0, 0));
    assert_eq!(
        control.snapshot().len(),
        16,
        "preparation is never exposed as downloading"
    );
    assert!(matches!(
        control.try_prepare(token(19, 1), hash(19)),
        Err(AdmissionDenied::Busy)
    ));
    assert!(matches!(
        control.try_enter(token(19, 1), hash(19)),
        Err(AdmissionDenied::Busy)
    ));
    assert!(!control.owns(first.token()));
    assert!(control.selected_token(hash(17).0).is_none());
    control.cancel_all();
    assert_eq!(
        control.available(),
        (0, 0),
        "cancellation is not retirement"
    );
    drop(active);
    assert!(matches!(
        control.try_enter(token(19, 1), hash(17)),
        Err(AdmissionDenied::Busy)
    ));
    drop(first);
    assert!(control.try_enter(token(19, 1), hash(17)).is_ok());
    drop(second);
    assert_eq!(control.available(), (16, 2));
}

#[test]
fn admission_precedes_tasks_and_drop_releases_without_an_async_runtime() {
    let control = Arc::new(DownloadAttemptControl::default());
    let guards: Vec<_> = (1..=crate::download_admission::AdmissionWindow::default().active)
        .map(|id| {
            control
                .try_enter(token(id as i64, 1), hash(id as u8))
                .unwrap()
        })
        .collect();
    assert!(matches!(
        control.try_enter(token(100, 1), hash(100)),
        Err(AdmissionDenied::Busy)
    ));
    drop(guards);
    assert!(control.state.lock().unwrap().entries.is_empty());
    assert!(control.try_enter(token(100, 1), hash(100)).is_ok());
}
#[test]
fn cancellation_keeps_generation_and_content_owned_until_actual_exit() {
    let control = Arc::new(DownloadAttemptControl::default());
    let old = control.try_enter(token(1, 1), hash(1)).unwrap();
    assert_eq!(old.token(), token(1, 1));
    assert!(control.cancel(JobId::new(1).unwrap()));
    assert!(old.cancellation().is_cancelled());
    assert!(matches!(
        control.try_enter(token(1, 2), hash(1)),
        Err(AdmissionDenied::Duplicate)
    ));
    assert!(matches!(
        control.try_enter(token(2, 1), hash(1)),
        Err(AdmissionDenied::Busy)
    ));
    drop(old);
    assert!(control.try_enter(token(2, 1), hash(1)).is_ok());
}
#[test]
fn stale_execution_cannot_cancel_a_new_generation_of_the_same_job() {
    let control = Arc::new(DownloadAttemptControl::default());
    let old = control.try_enter(token(1, 1), hash(1)).unwrap();
    drop(old);
    let current = control.try_enter(token(1, 2), hash(1)).unwrap();
    assert!(!control.cancel_execution(token(1, 1)));
    assert!(!current.cancellation().is_cancelled());
    assert!(control.cancel_execution(token(1, 2)));
    assert!(current.cancellation().is_cancelled());
    assert_eq!(control.snapshot().len(), 1);
    drop(current);
    assert!(!control.cancel_execution(token(1, 2)));
}

#[test]
fn stale_guard_cannot_clear_a_replacement_owner() {
    let control = Arc::new(DownloadAttemptControl::default());
    let old = control.try_enter(token(1, 1), hash(1)).unwrap();
    // Exercise nonce fencing independently of normal one-owner admission.
    control
        .state
        .lock()
        .unwrap()
        .entries
        .remove(&JobId::new(1).unwrap());
    let replacement = control.try_enter(token(1, 2), hash(1)).unwrap();
    drop(old);
    assert_eq!(
        control.state.lock().unwrap().entries[&JobId::new(1).unwrap()].nonce,
        replacement.nonce
    );
    assert!(!replacement.cancellation().is_cancelled());
}
#[test]
fn all_cancel_signals_do_not_release_owned_slots() {
    let control = Arc::new(DownloadAttemptControl::default());
    let first = control.try_enter(token(1, 1), hash(1)).unwrap();
    let second = control.try_enter(token(2, 1), hash(2)).unwrap();
    control.cancel_all();
    assert!(first.cancellation().is_cancelled());
    assert!(second.cancellation().is_cancelled());
    assert_eq!(control.state.lock().unwrap().entries.len(), 2);
}

#[test]
fn operator_stop_covers_older_execution_but_cannot_cancel_a_later_start() {
    let control = Arc::new(DownloadAttemptControl::default());
    let older = control.try_enter(token(1, 1), hash(1)).unwrap();
    assert!(control.cancel_through(token(1, 2)));
    assert!(older.cancellation().is_cancelled());
    drop(older);
    let newer = control.try_enter(token(1, 3), hash(1)).unwrap();
    assert!(!control.cancel_through(token(1, 2)));
    assert!(!newer.cancellation().is_cancelled());
}

#[test]
fn initial_allocation_rebinds_one_slot_and_a_prior_cancellation_cannot_be_revived() {
    let control = Arc::new(DownloadAttemptControl::default());
    let mut guard = control.try_enter(token(1, 0), hash(1)).unwrap();
    assert!(guard.rebind(token(1, 1)));
    assert_eq!(control.snapshot(), vec![(token(1, 1), false)]);
    assert!(!control.cancel_through(token(1, 0)));
    assert!(!guard.rebind(token(2, 2)));
    assert!(control.cancel_through(token(1, 1)));
    assert!(!guard.rebind(token(1, 2)));
    assert!(guard.cancellation().is_cancelled());
    assert_eq!(
        guard.token(),
        token(1, 2),
        "native generation remains known for retirement"
    );
    assert!(!control.owns(token(1, 2)));
    assert!(control.selected_token(hash(1).0).is_none());
    assert_eq!(guard.hash(), hash(1));
    assert_eq!(control.snapshot(), vec![(token(1, 2), true)]);
    drop(guard);
    assert!(control.snapshot().is_empty());
}
