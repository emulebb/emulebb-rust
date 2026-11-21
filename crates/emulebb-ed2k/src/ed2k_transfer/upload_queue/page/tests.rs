use super::*;

fn fixture(software: Option<&str>) -> (Ed2kUploadQueueState, Instant) {
    let mut queue = Ed2kUploadQueueState::new(Ed2kUploadQueueConfig {
        base_slots: 1,
        elastic_percent: 0,
        ..Default::default()
    });
    let now = Instant::now();
    for id in 1..=64u16 {
        let mut peer = test_support_peer();
        peer.ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, id as u8));
        peer.tcp_port += id;
        peer.user_hash = Some([id as u8; 16]);
        peer.client_software = software.map(str::to_owned);
        queue.begin_session(
            Ed2kUploadSessionKey {
                peer,
                file_hash: "45".repeat(16),
            },
            u64::from(id),
            now,
            i128::from(2 + id % 5),
            i128::from(1000 + id * 25),
            1000,
            1000,
        );
    }
    assert!(queue.waiting_order.len() > 10);
    for session in queue.sessions.values_mut() {
        session.requester_part_status = Some(vec![true; 8192]);
    }
    (queue, now + Duration::from_secs(1))
}

fn ranked_ids(queue: &Ed2kUploadQueueState, now: Instant) -> Vec<uuid::Uuid> {
    queue
        .ranked_waiting_keys(now)
        .into_iter()
        .map(|key| queue.sessions[key].public_id)
        .collect()
}

fn traverse(queue: &Ed2kUploadQueueState, now: Instant) -> Vec<uuid::Uuid> {
    let mut after = None;
    let mut ids = Vec::new();
    loop {
        let page = queue.waiting_page(after, 7, true, now).unwrap();
        assert_eq!(page.total, Some(queue.waiting_session_count()));
        assert!(page.entries.len() <= 7);
        for entry in &page.entries {
            assert!(entry.requester_part_status.is_none());
            assert_eq!(entry.queue_rank, Some((ids.len() + 1) as u16));
            assert_eq!(entry.management_rank, Some(ids.len() + 1));
            ids.push(entry.id);
        }
        if !page.has_more {
            assert!(page.next_after.is_none());
            break;
        }
        assert!(!page.entries.is_empty());
        assert_eq!(page.next_after, page.entries.last().map(|entry| entry.id));
        after = page.next_after;
    }
    ids
}

fn active_fixture(software: Option<&str>) -> (Ed2kUploadQueueState, Instant) {
    let (mut queue, now) = fixture(software);
    for session in queue.sessions.values_mut() {
        session.public_id = uuid::Uuid::from_u128(u128::from(session.connection_id));
        if session.connection_id % 4 == 0 {
            session.phase = Ed2kUploadSessionPhase::Uploading;
            session.upload_started_at = Some(now + Duration::from_secs(3));
        }
    }
    (queue, now + Duration::from_secs(8))
}

#[test]
fn active_pages_traverse_stable_ids_without_bitmaps_or_queue_maintenance() {
    let (queue, now) = active_fixture(None);
    let mut expected: Vec<_> = queue
        .sessions
        .values()
        .filter(|session| session.phase != Ed2kUploadSessionPhase::Waiting)
        .map(|session| session.public_id)
        .collect();
    expected.sort();
    let original = queue.sessions.len();
    let mut after = None;
    let mut actual = Vec::new();
    loop {
        let page = queue.active_page(after, 3, true, now).unwrap();
        assert_eq!(page.total, Some(expected.len()));
        assert!(page.entries.len() <= 3);
        for entry in &page.entries {
            assert!(entry.requester_part_status.is_none());
            assert!(entry.management_rank.is_none());
            assert!(entry.queue_rank.is_none());
            if entry.phase == Ed2kUploadSessionPhaseSnapshot::Uploading {
                assert_eq!(entry.upload_duration_seconds, Some(5));
                assert_eq!(entry.wait_duration_seconds, 4);
            } else {
                assert!(entry.upload_duration_seconds.is_none());
            }
            actual.push(entry.id);
        }
        after = page.next_after;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(actual, expected);
    assert_eq!(queue.sessions.len(), original);
    let future = now + queue.config.waiting_timeout + Duration::from_secs(1);
    assert_eq!(
        queue
            .active_page(None, 200, false, future)
            .unwrap()
            .entries
            .len(),
        expected.len()
    );
    assert_eq!(
        queue.sessions.len(),
        original,
        "reads must not reap expired waiting entries"
    );
}

#[test]
fn active_pages_are_byte_bounded_and_departed_or_waiting_anchors_expire() {
    let (mut queue, now) = active_fixture(Some(&"€".repeat(65_535)));
    let mut expected: Vec<_> = queue
        .sessions
        .values()
        .filter(|session| session.phase != Ed2kUploadSessionPhase::Waiting)
        .map(|session| session.public_id)
        .collect();
    expected.sort();
    let mut actual = Vec::new();
    let mut after = None;
    loop {
        let page = queue.active_page(after, 200, false, now).unwrap();
        assert!(page.entries.len() < expected.len());
        assert!(page.total.is_none());
        for entry in &page.entries {
            assert_eq!(entry.client_software.as_deref().unwrap().len(), 3 * 65_535);
            actual.push(entry.id);
        }
        after = page.next_after;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(actual, expected);
    let anchor = expected[0];
    let key = queue
        .sessions
        .iter()
        .find(|(_, session)| session.public_id == anchor)
        .unwrap()
        .0
        .clone();
    queue.sessions.get_mut(&key).unwrap().phase = Ed2kUploadSessionPhase::Waiting;
    assert!(matches!(
        queue.active_page(Some(anchor), 1, false, now),
        Err(Ed2kUploadQueuePageError::CursorExpired)
    ));
    queue.sessions.remove(&key);
    assert!(matches!(
        queue.active_page(Some(anchor), 1, false, now),
        Err(Ed2kUploadQueuePageError::CursorExpired)
    ));
    for limit in [0, 201] {
        assert!(matches!(
            queue.active_page(None, limit, false, now),
            Err(Ed2kUploadQueuePageError::InvalidLimit)
        ));
    }
}

#[test]
fn management_details_match_live_rank_without_copying_bits_or_expiring_state() {
    let (queue, now) = fixture(None);
    let expected = queue.waiting_page(None, 200, false, now).unwrap();
    for row in expected.entries {
        let detail = queue
            .client_snapshot(&row.id.to_string(), true, now)
            .unwrap();
        assert_eq!(detail.management_rank, row.management_rank);
        assert!(detail.requester_part_status.is_none());
        assert_eq!(detail.wait_duration_seconds, 1);
        assert!(detail.upload_duration_seconds.is_none());
    }
    let old_len = queue.sessions.len();
    let row = queue
        .waiting_page(None, 1, false, now)
        .unwrap()
        .entries
        .remove(0);
    assert!(
        queue
            .client_snapshot(
                &row.id.to_string(),
                true,
                now + queue.config.waiting_timeout + Duration::from_secs(1)
            )
            .is_none()
    );
    assert_eq!(queue.sessions.len(), old_len);
}

#[test]
fn management_rank_is_not_limited_by_the_wire_rank_field() {
    let (mut queue, now) = fixture(None);
    let (key, session) = queue
        .sessions
        .iter()
        .find(|(_, session)| session.phase == Ed2kUploadSessionPhase::Waiting)
        .map(|(key, session)| (key.clone(), session.clone()))
        .unwrap();
    queue.sessions.clear();
    queue.waiting_order.clear();
    for n in 1..=65_536u32 {
        let mut key = key.clone();
        key.peer.ip = IpAddr::V4(std::net::Ipv4Addr::from(n));
        let mut session = session.clone();
        session.public_id = uuid::Uuid::from_u128(u128::from(n));
        session.waiting_sequence = u64::from(n);
        session.requester_part_status = None;
        queue.waiting_order.push(key.clone());
        queue.sessions.insert(key, session);
    }
    let last = queue
        .client_snapshot(&uuid::Uuid::from_u128(65_536).to_string(), true, now)
        .unwrap();
    assert_eq!(last.management_rank, Some(65_536));
    assert_eq!(last.queue_rank, Some(u16::MAX));
}

#[tokio::test]
async fn native_active_pages_retain_their_budget_until_result_drop() {
    let runtime = crate::ed2k_transfer::Ed2kTransferRuntime::load_or_create(
        &crate::paths::unique_test_dir("active-upload-page-budget"),
    )
    .unwrap();
    let page = runtime.active_upload_page(None, 100, true).await.unwrap();
    assert!(page.entries.is_empty());
    assert_eq!(page.total, Some(0));
    assert_eq!(
        runtime.download_resource_snapshot().transient_bytes,
        1024 * 1024
    );
    drop(page);
    assert_eq!(runtime.download_resource_snapshot().transient_bytes, 0);
    assert!(runtime.active_upload_page(None, 0, false).await.is_err());
    assert_eq!(runtime.download_resource_snapshot().transient_bytes, 0);
}

#[test]
fn pages_match_scheduler_ranking_without_copying_requester_bitmaps() {
    let (queue, now) = fixture(None);
    assert_eq!(traverse(&queue, now), ranked_ids(&queue, now));
    assert!(
        queue
            .waiting_page(None, 1, false, now)
            .unwrap()
            .total
            .is_none()
    );
    assert!(matches!(
        queue.waiting_page(None, 0, false, now),
        Err(Ed2kUploadQueuePageError::InvalidLimit)
    ));
    assert!(matches!(
        queue.waiting_page(None, 201, false, now),
        Err(Ed2kUploadQueuePageError::InvalidLimit)
    ));
}

#[test]
fn byte_limited_pages_preserve_every_client_and_complete_software_text() {
    let (queue, now) = fixture(Some(&"€".repeat(65_535)));
    let expected = ranked_ids(&queue, now);
    let mut ids = Vec::new();
    let mut after = None;
    loop {
        let page = queue.waiting_page(after, 200, false, now).unwrap();
        assert!(page.entries.len() < expected.len());
        for entry in &page.entries {
            assert_eq!(entry.client_software.as_deref().unwrap().len(), 3 * 65_535);
            ids.push(entry.id);
        }
        after = page.next_after;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(ids, expected);
}

#[test]
fn saturated_waiting_sequences_keep_stable_scheduler_ties() {
    let (mut queue, now) = fixture(None);
    for session in queue.sessions.values_mut() {
        session.waiting_sequence = u64::MAX;
        session.file_priority_score = 7;
        session.credit_score_permille = 1000;
    }
    assert_eq!(traverse(&queue, now), ranked_ids(&queue, now));
}

#[test]
fn removed_promoted_and_expired_anchors_require_refresh() {
    let (mut queue, now) = fixture(None);
    let anchor = queue
        .waiting_page(None, 1, false, now)
        .unwrap()
        .next_after
        .unwrap();
    let key = queue
        .waiting_order
        .iter()
        .find(|key| queue.sessions[*key].public_id == anchor)
        .unwrap()
        .clone();
    queue.sessions.get_mut(&key).unwrap().phase = Ed2kUploadSessionPhase::Granted;
    assert!(matches!(
        queue.waiting_page(Some(anchor), 7, false, now),
        Err(Ed2kUploadQueuePageError::CursorExpired)
    ));
    let session = queue.sessions.get_mut(&key).unwrap();
    session.phase = Ed2kUploadSessionPhase::Waiting;
    session.last_activity = now - queue.config.waiting_timeout - Duration::from_secs(1);
    assert!(matches!(
        queue.waiting_page(Some(anchor), 7, false, now),
        Err(Ed2kUploadQueuePageError::CursorExpired)
    ));
    assert!(
        queue.sessions.contains_key(&key),
        "reads must not run protocol retirement"
    );
    queue.sessions.remove(&key);
    assert!(matches!(
        queue.waiting_page(Some(anchor), 7, false, now),
        Err(Ed2kUploadQueuePageError::CursorExpired)
    ));
}

#[test]
fn continuation_uses_live_anchor_rank_after_score_changes() {
    let (mut queue, now) = fixture(None);
    let first = queue.waiting_page(None, 7, false, now).unwrap();
    let anchor = first.next_after.unwrap();
    let anchor_key = queue
        .waiting_order
        .iter()
        .find(|key| queue.sessions[*key].public_id == anchor)
        .unwrap()
        .clone();
    queue
        .sessions
        .get_mut(&anchor_key)
        .unwrap()
        .file_priority_score = 2;
    let current = ranked_ids(&queue, now);
    let position = current.iter().position(|id| *id == anchor).unwrap();
    let expected: Vec<_> = current.iter().skip(position + 1).take(7).copied().collect();
    let page = queue.waiting_page(Some(anchor), 7, false, now).unwrap();
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        expected
    );
    for (offset, entry) in page.entries.iter().enumerate() {
        assert_eq!(entry.queue_rank, Some((position + offset + 2) as u16));
    }
}
