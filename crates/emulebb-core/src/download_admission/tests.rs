use super::*;

fn resources() -> DownloadResourceSnapshot {
    DownloadResourceSnapshot {
        resident_bytes: 0,
        resident_limit: 128 * 1024 * 1024,
        construction_bytes: 6 * 1024 * 1024,
        transient_bytes: 0,
        transient_limit: 8 * 1024 * 1024,
        free_work_units: 4,
        connections: 0,
        connection_limit: 500,
    }
}

#[test]
fn burst_ceiling_uses_available_resources_and_closes_under_pressure() {
    let mut native = resources();
    let open = next_window(
        AdmissionWindow::default(),
        native,
        Some(8 * 1024 * 1024 * 1024),
        1,
        16,
    );
    assert_eq!(open.burst, open.active.div_ceil(4));
    native.resident_bytes = SOFT_RESIDENT_BYTES + 1;
    let resident = next_window(open, native, Some(8 * 1024 * 1024 * 1024), 1, 16);
    assert_eq!(resident.burst, 0);
    native.resident_bytes = 0;
    native.free_work_units = 0;
    let busy = next_window(open, native, Some(8 * 1024 * 1024 * 1024), 1, 16);
    assert_eq!(busy.burst, 0);
    native.free_work_units = 4;
    let host = next_window(open, native, Some(0), 1, 16);
    assert_eq!((host.active, host.burst, host.total), (0, 0, 0));
    native.connection_limit = 2;
    let connections = next_window(open, native, Some(u64::MAX), 1, 16);
    assert!(connections.burst <= 2);
}

#[test]
fn prepared_hydration_does_not_require_a_second_connection_slot() {
    let mut native = resources();
    native.connection_limit = 1;
    native.connections = 1;
    assert_eq!(construction_starts(native), 0);
    assert!(hydration_starts(native) > 0);
    native.free_work_units = 0;
    assert_eq!(hydration_starts(native), 0);
}

#[test]
fn growth_is_gradual_and_can_exceed_initial_baseline() {
    let native = resources();
    let mut window = AdmissionWindow::default();
    for expected in 17..=32 {
        window = next_window(
            window,
            native,
            Some(8 * 1024 * 1024 * 1024),
            2,
            window.active,
        );
        assert_eq!(window.active, expected);
    }
    let idle = next_window(window, native, Some(8 * 1024 * 1024 * 1024), 2, 0);
    assert_eq!(
        idle.active, window.active,
        "idle capacity does not grow speculatively"
    );
}

#[test]
fn host_pressure_closes_then_gradually_recovers_admission() {
    let native = resources();
    let closed = next_window(AdmissionWindow::default(), native, Some(0), 2, 16);
    assert_eq!((closed.active, closed.preparing, closed.total), (0, 0, 0));
    let recovering = next_window(closed, native, Some(1024 * 1024 * 1024), 2, 0);
    assert_eq!(recovering.active, 1);
    assert_eq!(recovering.preparing, 2);
    let unknown = next_window(
        AdmissionWindow {
            active: 100,
            burst: 25,
            preparing: 2,
            total: 102,
        },
        native,
        None,
        2,
        100,
    );
    assert!(unknown.active <= 18);
    assert_eq!(unknown.total, 18);
}

#[test]
fn resident_pressure_keeps_bounded_metadata_preparation_available() {
    let mut native = resources();
    native.resident_bytes = native.resident_limit;
    assert_eq!(construction_starts(native), 0);
    let next = next_window(
        AdmissionWindow::default(),
        native,
        Some(1024 * 1024 * 1024),
        2,
        16,
    );
    assert_eq!(next.active, 15);
    assert_eq!(next.preparing, 2);
}

#[test]
fn connection_and_io_exhaustion_block_new_construction() {
    let mut native = resources();
    native.connections = native.connection_limit;
    assert_eq!(construction_starts(native), 0);
    assert_eq!(
        next_window(AdmissionWindow::default(), native, None, 2, 16).preparing,
        0
    );
    native.connections = 0;
    native.free_work_units = 0;
    assert_eq!(construction_starts(native), 0);
    native.free_work_units = 4;
    native.transient_bytes = native.transient_limit;
    assert_eq!(construction_starts(native), 0);
    native.transient_bytes = 0;
    native.connection_limit = 4;
    let window = next_window(AdmissionWindow::default(), native, Some(u64::MAX), 2, 16);
    assert_eq!(window.total, 2);
    assert!(window.active <= 2);
}

#[test]
fn construction_reserves_update_headroom_inside_fixed_resident_ceiling() {
    let mut native = resources();
    assert!(construction_starts(native) > 0);
    native.resident_bytes = native.resident_limit - 4 * native.construction_bytes;
    assert_eq!(construction_starts(native), 0);
    native.resident_bytes -= native.construction_bytes;
    assert_eq!(construction_starts(native), 1);
}
