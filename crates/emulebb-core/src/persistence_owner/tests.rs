use super::*;

fn setup() -> (MetadataStore, Arc<Mutex<CoreState>>, Arc<PersistenceOwner>) {
    let store = MetadataStore::in_memory().unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    (store, state, owner)
}

fn usage(owner: &PersistenceOwner) -> (usize, usize) {
    let admission = owner.admission.lock().unwrap();
    let quota = admission.quota.lock().unwrap();
    (quota.slots, quota.bytes)
}

async fn wait_for_slots(owner: &PersistenceOwner, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if usage(owner).0 == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_caller_keeps_permit_until_ordered_publication_and_drain() {
    let (store, state, owner) = setup();
    let guard = state.lock().await;
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("11".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    task.abort();
    assert_eq!(usage(&owner).0, 1);
    let close = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.close_and_drain().await })
    };
    tokio::task::yield_now().await;
    assert!(!close.is_finished());
    drop(guard);
    close.await.unwrap().unwrap();
    assert_eq!(state.lock().await.friends.len(), 1);
    assert_eq!(store.load_friends().unwrap().len(), 1);
    assert_eq!(usage(&owner).0, 0);
    assert!(matches!(
        owner.delete("11".repeat(16)).await,
        Err(PersistenceError::Closing)
    ));
}

#[tokio::test]
async fn cancellation_after_commit_cannot_abandon_publication() {
    let (store, state, owner) = setup();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("55".repeat(16), "Sample".into()).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(store.has_friend(&"55".repeat(16)).unwrap());
    assert!(state.lock().await.friends.is_empty());
    assert_eq!(usage(&owner).0, 1);
    task.abort();
    let drain = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.close_and_drain().await })
    };
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    gate.release.notify_one();
    drain.await.unwrap().unwrap();
    assert_eq!(state.lock().await.friends.len(), 1);
    assert_eq!(usage(&owner).0, 0);
}

#[tokio::test]
async fn same_key_fifo_survives_cancelled_delete_between_adds() {
    use std::{fs, path::PathBuf, time::Duration};

    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let path = root.join("metadata.db");
    let store = MetadataStore::open(&path).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let gate = Arc::new(PublicationGate::default());
    *owner.publication_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let first = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("aa".repeat(16), "First".into()).await })
    };
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    *owner.publication_gate.lock().unwrap() = None;
    let delete = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.delete("aa".repeat(16)).await })
    };
    wait_for_slots(&owner, 2).await;
    delete.abort();
    let _ = delete.await;
    let last = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("aa".repeat(16), "Second".into()).await })
    };
    wait_for_slots(&owner, 3).await;
    gate.release.notify_one();
    assert_eq!(first.await.unwrap().unwrap().name, "First");
    assert_eq!(last.await.unwrap().unwrap().name, "Second");
    owner.close_and_drain().await.unwrap();
    assert_eq!(state.lock().await.friends[&"aa".repeat(16)].name, "Second");
    drop(owner);
    drop(store);
    let reopened = MetadataStore::open(&path).unwrap();
    assert_eq!(reopened.load_friends().unwrap()[0].name, "Second");
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn bounded_slots_bytes_and_same_key_fifo() {
    let (store, state, owner) = setup();
    let guard = state.lock().await;
    let mut tasks = Vec::new();
    for n in 0..MAX_SLOTS {
        let owner = Arc::clone(&owner);
        tasks.push(tokio::spawn(async move {
            owner.add(format!("{n:032x}"), "Sample".into()).await
        }));
    }
    wait_for_slots(&owner, MAX_SLOTS).await;
    assert!(matches!(
        owner.add("ff".repeat(16), "Sample".into()).await,
        Err(PersistenceError::Busy)
    ));
    drop(guard);
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    wait_for_slots(&owner, 0).await;
    assert!(matches!(
        owner.add("aa".repeat(16), "x".repeat(MAX_BYTES / 4)).await,
        Err(PersistenceError::TooLarge)
    ));
    let original = owner.add("ff".repeat(16), "First".into()).await.unwrap();
    let duplicate = owner.add("ff".repeat(16), "Second".into()).await.unwrap();
    assert_eq!(original.name, duplicate.name);
    assert_eq!(
        owner.delete("ff".repeat(16)).await.unwrap().unwrap().name,
        "First"
    );
    assert!(owner.delete("ff".repeat(16)).await.unwrap().is_none());
    owner.close_and_drain().await.unwrap();
    assert_eq!(store.load_friends().unwrap().len(), MAX_SLOTS);
    assert_eq!(state.lock().await.friends.len(), MAX_SLOTS);
}

#[tokio::test]
async fn aggregate_owned_bytes_are_reserved_before_work_is_cloned() {
    let (_, state, owner) = setup();
    let guard = state.lock().await;
    let name = "x".repeat(MAX_BYTES / 8);
    let expected = FIXED_CHARGE + 4 * (32 + name.capacity());
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("66".repeat(16), name).await })
    };
    wait_for_slots(&owner, 1).await;
    assert_eq!(usage(&owner).1, expected);
    assert!(matches!(
        owner.add("77".repeat(16), "x".repeat(MAX_BYTES / 8)).await,
        Err(PersistenceError::Busy)
    ));
    drop(guard);
    task.await.unwrap().unwrap();
    owner.close_and_drain().await.unwrap();
    assert_eq!(usage(&owner).1, 0);
}

#[tokio::test]
async fn failed_write_never_publishes_and_drain_reports_failure() {
    let (store, state, owner) = setup();
    assert!(matches!(
        owner.add("invalid".into(), "Sample".into()).await,
        Err(PersistenceError::Storage(_))
    ));
    assert!(state.lock().await.friends.is_empty());
    assert!(store.load_friends().unwrap().is_empty());
    assert!(owner.close_and_drain().await.is_err());
    assert!(owner.close_and_drain().await.is_err());
}

#[tokio::test]
async fn post_commit_worker_failure_reconciles_or_faults_the_domain() {
    use std::sync::atomic::Ordering;

    let (store, state, owner) = setup();
    owner.fault.store(1, Ordering::SeqCst);
    assert!(matches!(
        owner.add("11".repeat(16), "Sample".into()).await,
        Err(PersistenceError::CommittedAfterWorkerFailure)
    ));
    assert!(store.has_friend(&"11".repeat(16)).unwrap());
    assert_eq!(state.lock().await.friends.len(), 1);
    assert!(owner.close_and_drain().await.is_err());

    let (store, state, owner) = setup();
    owner.fault.store(3, Ordering::SeqCst);
    assert!(matches!(
        owner.add("33".repeat(16), "Sample".into()).await,
        Err(PersistenceError::Worker)
    ));
    assert!(!store.has_friend(&"33".repeat(16)).unwrap());
    assert!(state.lock().await.friends.is_empty());
    assert!(owner.close_and_drain().await.is_err());

    let store = MetadataStore::in_memory().unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let slot = PersistenceSlot::default();
    let owner = slot.owner(&store, &state).unwrap();
    let guard = state.lock().await;
    owner.fault.store(2, Ordering::SeqCst);
    let first = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("22".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    let second = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("44".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 2).await;
    drop(guard);
    assert!(matches!(
        first.await.unwrap(),
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(matches!(
        second.await.unwrap(),
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(store.has_friend(&"22".repeat(16)).unwrap());
    assert!(!store.has_friend(&"44".repeat(16)).unwrap());
    assert!(matches!(
        slot.check_friend_state(),
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(matches!(
        owner.delete("22".repeat(16)).await,
        Err(PersistenceError::CommitUnknown)
    ));
    assert!(slot.close_and_drain().await.is_err());
}

#[tokio::test]
async fn drain_releases_worker_profile_lease_before_reopen() {
    use emulebb_metadata::ProfileLeaseGuard;
    use std::{
        fs::{self, OpenOptions, TryLockError},
        path::PathBuf,
    };

    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let lock = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(".emulebb-profile.lock"))
            .unwrap()
    };
    let guard = Arc::new(ProfileLeaseGuard::try_lock(lock()).unwrap());
    let store =
        MetadataStore::open_with_profile_lease(root.join("metadata.db"), Arc::clone(&guard))
            .unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    drop(store);
    drop(guard);
    assert!(matches!(
        ProfileLeaseGuard::try_lock(lock()),
        Err(TryLockError::WouldBlock)
    ));
    owner.add("11".repeat(16), "Sample".into()).await.unwrap();
    owner.close_and_drain().await.unwrap();
    let reopened_guard = Arc::new(ProfileLeaseGuard::try_lock(lock()).unwrap());
    let reopened =
        MetadataStore::open_with_profile_lease(root.join("metadata.db"), reopened_guard).unwrap();
    assert_eq!(reopened.load_friends().unwrap().len(), 1);
    drop(reopened);
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn dropped_last_owner_still_finishes_accepted_write_and_releases_lease() {
    use emulebb_metadata::ProfileLeaseGuard;
    use std::{
        fs::{self, OpenOptions, TryLockError},
        path::PathBuf,
    };

    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let lock = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(".emulebb-profile.lock"))
            .unwrap()
    };
    let lease = Arc::new(ProfileLeaseGuard::try_lock(lock()).unwrap());
    let path = root.join("metadata.db");
    let store = MetadataStore::open_with_profile_lease(&path, Arc::clone(&lease)).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let held = state.lock().await;
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("88".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    task.abort();
    let _ = task.await;
    drop(owner);
    drop(store);
    drop(lease);
    drop(held);
    drop(state);
    let next = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ProfileLeaseGuard::try_lock(lock()) {
                Ok(lease) => break lease,
                Err(TryLockError::WouldBlock) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                }
                Err(error) => panic!("unexpected lock error: {error:?}"),
            }
        }
    })
    .await
    .unwrap();
    let reopened = MetadataStore::open_with_profile_lease(&path, Arc::new(next)).unwrap();
    assert!(reopened.has_friend(&"88".repeat(16)).unwrap());
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn sqlite_writer_contention_keeps_runtime_responsive_and_drains_cancelled_write() {
    use std::{fs, path::PathBuf, time::Duration};

    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join("tmp/persistence-owner-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let path = root.join("metadata.db");
    let store = MetadataStore::open(&path).unwrap();
    let state = Arc::new(Mutex::new(
        profile_state::load_core_state(&store, vec![]).unwrap(),
    ));
    let owner = PersistenceOwner::start(store.clone(), Arc::clone(&state)).unwrap();
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let task = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.add("99".repeat(16), "Sample".into()).await })
    };
    wait_for_slots(&owner, 1).await;
    tokio::time::timeout(Duration::from_secs(1), owner.worker_started.notified())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::time::sleep(Duration::from_millis(100)),
    )
    .await
    .unwrap();
    assert!(!task.is_finished());
    assert!(state.lock().await.friends.is_empty());
    task.abort();
    let _ = task.await;
    let drain = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.close_and_drain().await })
    };
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    drain.await.unwrap().unwrap();
    assert_eq!(state.lock().await.friends.len(), 1);
    drop(owner);
    drop(store);
    let reopened = MetadataStore::open(&path).unwrap();
    assert!(reopened.has_friend(&"99".repeat(16)).unwrap());
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
