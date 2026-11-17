use super::*;

fn job(value: i64) -> JobId {
    JobId::new(value).unwrap()
}

#[test]
fn subscription_baseline_and_following_changes_have_no_capture_gap() {
    let events = std::sync::Arc::new(DownloadEvents::default());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker = {
        let events = events.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            for value in 1..=256 {
                events.changed(job(value));
            }
        })
    };
    barrier.wait();
    let mut subscription = events.subscribe(DownloadEventResetReason::Initial, None);
    let baseline = subscription.reset.id();
    worker.join().unwrap();
    let mut ids = Vec::new();
    while let Ok(event) = subscription.receiver.try_recv() {
        assert_eq!(event.epoch(), subscription.reset.epoch());
        ids.push(event.id());
    }
    assert_eq!(ids, ((baseline + 1)..=256).collect::<Vec<_>>());
}

#[test]
fn lag_reset_replaces_old_receiver_before_delivering_newer_events() {
    let events = DownloadEvents::default();
    let mut old = events.subscribe(DownloadEventResetReason::Initial, None);
    for _ in 0..=CHANNEL_CAPACITY {
        events.changed(job(1));
    }
    let missed = match old.receiver.try_recv() {
        Err(broadcast::error::TryRecvError::Lagged(missed)) => missed,
        other => panic!("expected lag, got {other:?}"),
    };
    let mut current = events.subscribe(DownloadEventResetReason::Lagged, Some(missed));
    drop(old);
    assert_eq!(current.reset.id(), (CHANNEL_CAPACITY + 1) as u64);
    assert!(matches!(
        current.receiver.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
    events.removed(job(1));
    let next = current.receiver.try_recv().unwrap();
    assert_eq!(next.id(), current.reset.id() + 1);
    assert_eq!(next.epoch(), current.reset.epoch());
    assert!(matches!(next,DownloadEvent::Removed{download_id,..} if download_id==job(1)));
    assert!(events.diagnostics().queued_event_count <= CHANNEL_CAPACITY);
}

#[test]
fn sequence_rollover_changes_epoch_and_emits_reset_before_identity_only_change() {
    let events = DownloadEvents::default();
    events.state.lock().unwrap().revision = u64::MAX;
    let mut subscription = events.subscribe(DownloadEventResetReason::Initial, None);
    let previous_epoch = subscription.reset.epoch().to_owned();
    events.changed(job(9));
    let reset = subscription.receiver.try_recv().unwrap();
    assert!(matches!(
        reset,
        DownloadEvent::SyncReset {
            reason: DownloadEventResetReason::EpochChanged,
            ..
        }
    ));
    assert_eq!(reset.id(), 0);
    assert_ne!(reset.epoch(), previous_epoch);
    let next = subscription.receiver.try_recv().unwrap();
    assert_eq!(next.cursor(), format!("{}:1", reset.epoch()));
    assert_eq!(
        serde_json::to_value(&next).unwrap(),
        serde_json::json!({"type":"download.changed","id":1,"epoch":reset.epoch(),"downloadId":"9"})
    );
}
