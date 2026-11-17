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
fn sixteen_active_and_two_preparations_have_separate_caps_and_share_content_ownership() {
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
    let guards: Vec<_> = (1..=MAX_ACTIVE)
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
    drop(guard);
    assert!(control.snapshot().is_empty());
}
