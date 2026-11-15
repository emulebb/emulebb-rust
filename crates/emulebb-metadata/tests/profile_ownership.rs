//! Logical profile ownership and inherited-descriptor lifecycle regressions.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    path::PathBuf,
    sync::Arc,
};

use emulebb_metadata::{MetadataStore, ProfileLeaseGuard};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let target = PathBuf::from(
            std::env::var_os("CARGO_TARGET_DIR").expect("ownership tests require CARGO_TARGET_DIR"),
        );
        assert!(target.is_absolute());
        let directory = target
            .join("tmp/metadata-profile-ownership")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }

    fn file(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.0.join(".emulebb-profile.lock"))
            .unwrap()
    }

    fn acquire(&self) -> ProfileLeaseGuard {
        ProfileLeaseGuard::try_lock(self.file()).unwrap()
    }

    fn assert_busy(&self) {
        assert!(matches!(
            ProfileLeaseGuard::try_lock(self.file()),
            Err(TryLockError::WouldBlock)
        ));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn final_logical_owner_unlocks_while_a_duplicate_descriptor_remains_open() {
    let fixture = Fixture::new();
    let file = fixture.file();
    let duplicate = file.try_clone().unwrap();
    let guard = Arc::new(ProfileLeaseGuard::try_lock(file).unwrap());
    let cloned = Arc::clone(&guard);
    fixture.assert_busy();
    drop(guard);
    fixture.assert_busy();
    drop(cloned);
    let next_owner = fixture.acquire();
    // The duplicate models a transient fork/spawn descriptor: it cannot retain
    // ownership after the final logical owner explicitly releases the lease.
    drop(duplicate);
    fixture.assert_busy();
    drop(next_owner);
    assert!(fixture.0.join(".emulebb-profile.lock").is_file());
}

#[test]
fn cloned_and_independent_metadata_handles_retain_the_lease() {
    let fixture = Fixture::new();
    let file = fixture.file();
    let duplicate = file.try_clone().unwrap();
    let guard = Arc::new(ProfileLeaseGuard::try_lock(file).unwrap());
    let database = fixture.0.join("metadata.db");
    let first = MetadataStore::open_with_profile_lease(&database, Arc::clone(&guard)).unwrap();
    let cloned = first.clone();
    let independent =
        MetadataStore::open_with_profile_lease(&database, Arc::clone(&guard)).unwrap();
    drop(guard);
    drop(first);
    fixture.assert_busy();
    drop(cloned);
    fixture.assert_busy();
    drop(independent);
    let next_owner = fixture.acquire();
    // Closing the final connection checkpoints its WAL before ownership passes.
    assert!(!database.with_extension("db-wal").exists());
    assert!(!database.with_extension("db-shm").exists());
    drop(duplicate);
    drop(next_owner);
}

#[test]
fn metadata_constructor_errors_release_the_final_logical_owner() {
    let fixture = Fixture::new();
    let file = fixture.file();
    let duplicate = file.try_clone().unwrap();
    let guard = Arc::new(ProfileLeaseGuard::try_lock(file).unwrap());
    let database = fixture.0.join("metadata.db");
    let result = MetadataStore::open_with_profile_lease_and_storage(&database, guard, || {
        anyhow::bail!("injected storage initialization failure")
    });
    assert!(result.is_err());
    let file = fixture.file();
    let open_error_duplicate = file.try_clone().unwrap();
    let guard = Arc::new(ProfileLeaseGuard::try_lock(file).unwrap());
    assert!(MetadataStore::open_with_profile_lease(&fixture.0, guard).is_err());
    let next_owner = fixture.acquire();
    drop(duplicate);
    drop(open_error_duplicate);
    drop(next_owner);
}

#[cfg(unix)]
#[test]
fn inherited_child_drop_cannot_unlock_the_parent_lease() {
    let fixture = Fixture::new();
    let guard = fixture.acquire();
    // SAFETY: the fork child touches only this stack-owned File+PID guard, then
    // calls _exit. Guard Drop checks the PID via getpid (std::process::id), skips
    // unlock in the child, and closes File. getpid, close and _exit are
    // async-signal-safe; no Arc, allocation, mutex, logging, assertion, fixture
    // teardown or test-harness return occurs in the child of this threaded test.
    let child = unsafe { libc::fork() };
    if child == 0 {
        drop(guard);
        // SAFETY: exit without running inherited Rust or test-harness destructors.
        unsafe { libc::_exit(0) };
    }
    assert!(
        child > 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    let mut status = 0;
    loop {
        // SAFETY: child is our positive fork PID and status is writable storage.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        assert_eq!(waited, -1);
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
    assert!(libc::WIFEXITED(status), "child status: {status}");
    assert_eq!(libc::WEXITSTATUS(status), 0);
    fixture.assert_busy();
    drop(guard);
    drop(fixture.acquire());
}
