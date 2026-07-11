use super::*;

fn request(query: &str) -> SearchCreate {
    SearchCreate {
        query: query.to_string(),
        method: "server".to_string(),
        ..SearchCreate::default()
    }
}

fn ready(server: bool, kad: bool) -> SearchBackendReadiness {
    SearchBackendReadiness { server, kad }
}

fn enqueue(queue: &mut SearchQueue, id: &str, query: &str, lane: SearchQueueLane, now: Instant) {
    queue
        .enqueue(id.to_string(), request(query), lane, now)
        .expect("enqueue succeeds");
}

#[test]
fn lane_for_method_maps_network_methods_only() {
    assert_eq!(
        SearchQueueLane::for_method("server"),
        Some(SearchQueueLane::Server)
    );
    assert_eq!(
        SearchQueueLane::for_method("GLOBAL"),
        Some(SearchQueueLane::Server)
    );
    assert_eq!(
        SearchQueueLane::for_method("kad"),
        Some(SearchQueueLane::Kad)
    );
    assert_eq!(SearchQueueLane::for_method(""), Some(SearchQueueLane::Auto));
    assert_eq!(
        SearchQueueLane::for_method("automatic"),
        Some(SearchQueueLane::Auto)
    );
    assert_eq!(SearchQueueLane::for_method("bogus"), None);
}

#[test]
fn queued_search_waits_until_backend_ready_then_dispatches() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Server, now);

    let tick = queue.tick(now, ready(false, false));
    assert!(tick.dispatches.is_empty());
    assert_eq!(queue.pending_len(), 1);

    let tick = queue.tick(now + Duration::from_secs(2), ready(true, false));
    assert_eq!(tick.dispatches.len(), 1);
    assert_eq!(tick.dispatches[0].lane, ConcreteSearchLane::Server);
    assert_eq!(tick.dispatches[0].entry.search_id, "1");
    assert_eq!(tick.dispatches[0].entry.send_attempts, 1);
    assert_eq!(queue.pending_len(), 0);
}

#[test]
fn single_in_flight_server_search_at_a_time() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Server, now);
    enqueue(&mut queue, "2", "beta", SearchQueueLane::Server, now);

    let tick = queue.tick(now, ready(true, false));
    assert_eq!(tick.dispatches.len(), 1);

    // Well past the slot spacing, but the first search is still in flight.
    let tick = queue.tick(now + Duration::from_secs(60), ready(true, false));
    assert!(tick.dispatches.is_empty());

    queue.finish(ConcreteSearchLane::Server);
    let tick = queue.tick(now + Duration::from_secs(60), ready(true, false));
    assert_eq!(tick.dispatches.len(), 1);
    assert_eq!(tick.dispatches[0].entry.search_id, "2");
}

#[test]
fn drain_spacing_enforces_slot_between_dispatches() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Server, now);
    enqueue(&mut queue, "2", "beta", SearchQueueLane::Server, now);

    assert_eq!(queue.tick(now, ready(true, false)).dispatches.len(), 1);
    queue.finish(ConcreteSearchLane::Server);

    // Lane free but inside the 5s slot: the second search must wait.
    let tick = queue.tick(now + Duration::from_secs(2), ready(true, false));
    assert!(tick.dispatches.is_empty());

    let tick = queue.tick(now + SEARCH_QUEUE_DRAIN_SLOT, ready(true, false));
    assert_eq!(tick.dispatches.len(), 1);
    assert_eq!(tick.dispatches[0].entry.search_id, "2");
}

#[test]
fn kad_lane_drains_one_at_a_time_independently_of_server_lane() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Server, now);
    enqueue(&mut queue, "2", "beta", SearchQueueLane::Kad, now);
    enqueue(&mut queue, "3", "gamma", SearchQueueLane::Kad, now);

    // Server backend down must not block the Kad lane (no head-of-line
    // starvation across lanes), and only one Kad dispatch per tick.
    let tick = queue.tick(now, ready(false, true));
    assert_eq!(tick.dispatches.len(), 1);
    assert_eq!(tick.dispatches[0].lane, ConcreteSearchLane::Kad);
    assert_eq!(tick.dispatches[0].entry.search_id, "2");

    let tick = queue.tick(now + Duration::from_secs(60), ready(false, true));
    assert!(tick.dispatches.is_empty(), "kad search still in flight");

    queue.finish(ConcreteSearchLane::Kad);
    let tick = queue.tick(now + Duration::from_secs(60), ready(false, true));
    assert_eq!(tick.dispatches.len(), 1);
    assert_eq!(tick.dispatches[0].entry.search_id, "3");
}

#[test]
fn auto_lane_prefers_server_then_falls_back_to_kad() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Auto, now);
    let tick = queue.tick(now, ready(true, true));
    assert_eq!(tick.dispatches[0].lane, ConcreteSearchLane::Server);

    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "2", "beta", SearchQueueLane::Auto, now);
    let tick = queue.tick(now, ready(false, true));
    assert_eq!(tick.dispatches[0].lane, ConcreteSearchLane::Kad);
}

#[test]
fn retry_requeues_at_front_until_attempts_exhausted() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Server, now);
    enqueue(&mut queue, "2", "beta", SearchQueueLane::Server, now);

    let mut when = now;
    for attempt in 1..=SEARCH_QUEUE_MAX_SEND_ATTEMPTS {
        let mut tick = queue.tick(when, ready(true, false));
        assert_eq!(tick.dispatches.len(), 1);
        let dispatch = tick.dispatches.pop().unwrap();
        // The retried search stays ahead of the later submission.
        assert_eq!(dispatch.entry.search_id, "1");
        assert_eq!(dispatch.entry.send_attempts, attempt);
        queue.finish(dispatch.lane);
        if attempt < SEARCH_QUEUE_MAX_SEND_ATTEMPTS {
            assert!(queue.requeue_for_retry(dispatch.entry), "retry budget left");
        } else {
            assert!(
                !queue.requeue_for_retry(dispatch.entry),
                "attempt budget exhausted"
            );
        }
        when += SEARCH_QUEUE_DRAIN_SLOT;
    }

    // The exhausted search is gone; the next queued one drains normally.
    let tick = queue.tick(when, ready(true, false));
    assert_eq!(tick.dispatches.len(), 1);
    assert_eq!(tick.dispatches[0].entry.search_id, "2");
}

#[test]
fn duplicate_queued_query_is_rejected_per_lane() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "Alpha Beta", SearchQueueLane::Server, now);
    assert_eq!(
        queue.enqueue(
            "2".to_string(),
            request("  alpha beta "),
            SearchQueueLane::Server,
            now
        ),
        Err(SearchEnqueueError::DuplicateQueued)
    );
    // Same query on a different lane is a different network search.
    assert!(
        queue
            .enqueue(
                "3".to_string(),
                request("alpha beta"),
                SearchQueueLane::Kad,
                now
            )
            .is_ok()
    );
}

#[test]
fn queue_cap_rejects_overflow_explicitly() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    for index in 0..SEARCH_QUEUE_CAP {
        enqueue(
            &mut queue,
            &index.to_string(),
            &format!("query-{index}"),
            SearchQueueLane::Server,
            now,
        );
    }
    assert_eq!(
        queue.enqueue(
            "overflow".to_string(),
            request("overflow-query"),
            SearchQueueLane::Server,
            now
        ),
        Err(SearchEnqueueError::QueueFull)
    );
}

#[test]
fn over_age_entries_expire_instead_of_waiting_forever() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Server, now);

    let tick = queue.tick(now + SEARCH_QUEUE_MAX_WAIT, ready(false, false));
    assert!(
        tick.expired.is_empty(),
        "at the bound the entry still waits"
    );

    let tick = queue.tick(
        now + SEARCH_QUEUE_MAX_WAIT + Duration::from_secs(1),
        ready(false, false),
    );
    assert_eq!(tick.expired.len(), 1);
    assert_eq!(tick.expired[0].search_id, "1");
    assert_eq!(queue.pending_len(), 0);
}

#[test]
fn drain_task_slot_is_claimed_once_and_released_only_when_idle() {
    let now = Instant::now();
    let mut queue = SearchQueue::new();
    enqueue(&mut queue, "1", "alpha", SearchQueueLane::Server, now);

    assert!(queue.claim_drain_task());
    assert!(!queue.claim_drain_task(), "second claim must lose");

    assert!(
        !queue.release_drain_task_if_idle(),
        "pending entry: keep running"
    );
    let mut tick = queue.tick(now, ready(true, false));
    let dispatch = tick.dispatches.pop().unwrap();
    assert!(
        !queue.release_drain_task_if_idle(),
        "in-flight search: keep running"
    );
    queue.finish(dispatch.lane);
    assert!(queue.release_drain_task_if_idle());
    assert!(queue.claim_drain_task(), "slot reusable after release");
}
