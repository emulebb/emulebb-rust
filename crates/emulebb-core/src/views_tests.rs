use super::{
    ServerLiveDetails, apply_server_connection_flags, apply_server_live_details,
    format_ed2k_file_link, kad_status_from_running, server_info_from_parts,
};

#[test]
fn ed2k_link_escapes_stock_filename_bytes() {
    assert_eq!(
        format_ed2k_file_link("Linux Guide é%.pdf", 123, "aabb"),
        "ed2k://|file|Linux%20Guide%20%C3%A9%25.pdf|123|aabb|/",
    );
}

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
        dynamic_host: Some("dyn.example".to_string()),
        version: Some("17.06".to_string()),
        auxiliary_ports: vec![4662, 4663],
        users: Some(4242),
        files: Some(99000),
        max_users: Some(5000),
        low_id_users: Some(25),
        ping_ms: Some(37),
        udp_flags: Some(0x331),
        soft_files: Some(500),
        hard_files: Some(600),
        obfuscation_tcp_port: Some(4665),
        obfuscation_udp_port: Some(4675),
        udp_key: Some(0x1122_3344),
        udp_key_ip: Some(0x5566_7788),
    };

    apply_server_live_details(&mut server, &live);

    assert_eq!(server.name, "live name");
    assert_eq!(server.description, "live description");
    assert_eq!(server.dyn_ip, "dyn.example");
    assert_eq!(server.version, "17.06");
    assert_eq!(server.auxiliary_ports, vec![4662, 4663]);
    assert_eq!(server.users, 4242);
    assert_eq!(server.files, 99000);
    assert_eq!(server.max_users, 5000);
    assert_eq!(server.low_id_users, 25);
    assert_eq!(server.ping, 37);
    assert_eq!(server.udp_flags, Some(0x331));
    assert_eq!(server.soft_files, 500);
    assert_eq!(server.hard_files, 600);
    assert_eq!(server.obfuscation_tcp_port, Some(4665));
    assert_eq!(server.obfuscation_udp_port, Some(4675));
    assert_eq!(server.udp_key, Some(0x1122_3344));
    assert_eq!(server.udp_key_ip, Some(0x5566_7788));
}
