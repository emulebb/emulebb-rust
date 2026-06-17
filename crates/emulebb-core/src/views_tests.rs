use super::{
    ServerLiveDetails, apply_server_connection_flags, apply_server_live_details,
    kad_status_from_running, server_info_from_parts,
};

#[test]
fn kad_status_running_is_bootstrapping_until_connected() {
    let status = kad_status_from_running(true);

    assert!(status.running);
    assert!(!status.connected);
    assert_eq!(status.bootstrapping, Some(true));
    assert_eq!(status.firewalled, None);
    assert_eq!(status.users, None);
    assert_eq!(status.files, None);
}

#[test]
fn kad_status_stopped_has_unknown_network_totals() {
    let status = kad_status_from_running(false);

    assert!(!status.running);
    assert!(!status.connected);
    assert_eq!(status.bootstrapping, Some(false));
    assert_eq!(status.contact_count, None);
    assert_eq!(status.users, None);
    assert_eq!(status.files, None);
}

#[test]
fn server_connection_flags_mark_connecting_server_current() {
    let mut server = server_info_from_parts("203.0.113.9", 4661, None, None, true, None, None);

    apply_server_connection_flags(&mut server, None, Some("203.0.113.9:4661"));

    assert!(server.current);
    assert!(server.connecting);
    assert!(!server.connected);
}

#[test]
fn server_connection_flags_prefer_connected_and_clear_stale_flags() {
    let mut server = server_info_from_parts(
        "203.0.113.9",
        4661,
        None,
        None,
        true,
        Some("203.0.113.9:4661"),
        None,
    );
    server.connecting = true;

    apply_server_connection_flags(&mut server, Some("198.51.100.4:4661"), None);

    assert!(!server.current);
    assert!(!server.connecting);
    assert!(!server.connected);
}

#[test]
fn server_live_details_overlay_protocol_status() {
    let mut server = server_info_from_parts("203.0.113.9", 4661, None, None, true, None, None);
    let live = ServerLiveDetails {
        name: Some("live name".to_string()),
        description: Some("live description".to_string()),
        users: Some(4242),
        files: Some(99000),
    };

    apply_server_live_details(&mut server, &live);

    assert_eq!(server.name, "live name");
    assert_eq!(server.description, "live description");
    assert_eq!(server.users, 4242);
    assert_eq!(server.files, 99000);
}
