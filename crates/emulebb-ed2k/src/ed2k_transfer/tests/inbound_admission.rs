//! Runtime-level tests for the inbound-accept admission cap (eMule
//! `CListenSocket::OnAccept` -> `TooManySockets()`): a new inbound peer
//! connection is refused once the live inbound count reaches the
//! concurrent-connection cap, and the slot is freed on handler exit (guard drop).

use crate::ed2k_transfer::Ed2kDownloadCoordinatorConfig;
use crate::ed2k_transfer::Ed2kTransferRuntime;
use crate::paths::unique_test_dir;

fn runtime_with_inbound_cap(label: &str, cap: usize) -> Ed2kTransferRuntime {
    let root = unique_test_dir(label);
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.apply_download_coordinator_config(Ed2kDownloadCoordinatorConfig {
        max_connections: cap,
        ..Ed2kDownloadCoordinatorConfig::default()
    });
    runtime
}

#[test]
fn inbound_connection_is_refused_when_over_the_concurrent_cap() {
    let runtime = runtime_with_inbound_cap("ed2k-inbound-admission-cap", 2);
    // Two admits fill the cap.
    let first = runtime.try_admit_inbound_connection();
    let second = runtime.try_admit_inbound_connection();
    assert!(first.is_some());
    assert!(second.is_some());
    assert_eq!(runtime.inbound_connection_count(), 2);
    // Third is refused (over the cap) -> the listener closes the socket.
    let third = runtime.try_admit_inbound_connection();
    assert!(third.is_none());
    assert_eq!(runtime.inbound_connection_count(), 2);
}

#[test]
fn inbound_slot_is_released_on_handler_exit() {
    let runtime = runtime_with_inbound_cap("ed2k-inbound-admission-release", 1);
    {
        let guard = runtime.try_admit_inbound_connection();
        assert!(guard.is_some());
        assert_eq!(runtime.inbound_connection_count(), 1);
        // While the guard is held the single slot is full.
        assert!(runtime.try_admit_inbound_connection().is_none());
        // guard drops here (mirrors the handler task exiting on any path).
    }
    assert_eq!(runtime.inbound_connection_count(), 0);
    // The freed slot is admissible again.
    let reused = runtime.try_admit_inbound_connection();
    assert!(reused.is_some());
    assert_eq!(runtime.inbound_connection_count(), 1);
}

#[test]
fn zero_cap_disables_the_inbound_admission_gate() {
    let runtime = runtime_with_inbound_cap("ed2k-inbound-admission-unlimited", 0);
    let guards: Vec<_> = (0..1000)
        .map(|_| {
            runtime
                .try_admit_inbound_connection()
                .expect("unlimited cap admits every inbound connection")
        })
        .collect();
    assert_eq!(runtime.inbound_connection_count(), 1000);
    drop(guards);
    assert_eq!(runtime.inbound_connection_count(), 0);
}
