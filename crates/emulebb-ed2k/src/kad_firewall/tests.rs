use super::{
    ExternalPortDiscoveryOutcome, FirewallUdpPacketOutcome, FirewalledResponseOutcome,
    KadFirewallState,
};
use chrono::{TimeZone, Utc};

#[test]
fn udp_round_marks_open_on_matching_port() {
    let mut state = KadFirewallState::default();
    let helper = "203.0.113.10".parse().unwrap();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 30, 0).unwrap();
    let observed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 30, 5).unwrap();

    assert!(state.begin_udp_check([helper], [41000, 51000], started_at));
    let outcome = state.record_firewall_udp_packet(helper, 0, 41000, observed_at);

    match outcome {
        FirewallUdpPacketOutcome::Open(summary) => {
            assert!(summary.open);
            assert_eq!(summary.helpers_succeeded, 1);
        }
        other => panic!("expected open result, got {other:?}"),
    }

    assert!(state.udp_open);
    assert!(state.udp_verified);
    assert_eq!(state.last_reported_port, Some(41000));
}

#[test]
fn udp_round_times_out_as_firewalled_after_negative_results() {
    let mut state = KadFirewallState::default();
    let helper_a = "203.0.113.10".parse().unwrap();
    let helper_b = "203.0.113.11".parse().unwrap();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 31, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 31, 20).unwrap();

    assert!(state.begin_udp_check([helper_a, helper_b], [41000], started_at));
    let _ = state.record_firewall_udp_packet(helper_a, 1, 41000, completed_at);
    let _ = state.record_firewall_udp_packet(helper_b, 0, 42000, completed_at);
    let summary = state.finish_udp_check(completed_at).expect("summary");

    assert!(!summary.open);
    assert!(!state.udp_open);
    assert!(state.udp_verified);
    assert_eq!(summary.helpers_failed, 2);
}

#[test]
fn udp_round_discovers_external_port_after_two_corroborating_reporters() {
    let mut state = KadFirewallState::default();
    let helper_a = "203.0.113.20".parse().unwrap();
    let helper_b = "203.0.113.21".parse().unwrap();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 33, 0).unwrap();
    let observed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 33, 5).unwrap();

    // We only predicted our internal port; the NAT remaps to 53000 externally.
    assert!(state.begin_udp_check([helper_a, helper_b], [41000], started_at));

    // First off-list reporter: recorded but not yet trusted.
    let first = state.record_firewall_udp_packet(helper_a, 0, 53000, observed_at);
    assert_eq!(first, FirewallUdpPacketOutcome::Recorded);
    assert!(!state.udp_open);

    // Second corroborating reporter: now trusted as the real external port.
    let second = state.record_firewall_udp_packet(helper_b, 0, 53000, observed_at);
    match second {
        FirewallUdpPacketOutcome::Open(summary) => {
            assert!(summary.open);
            assert_eq!(summary.external_udp_port, Some(53000));
        }
        other => panic!("expected open discovery result, got {other:?}"),
    }
    assert!(state.udp_open);
    assert!(state.udp_verified);
    assert_eq!(state.external_udp_port_for_request(), 53000);
}

#[test]
fn udp_round_does_not_trust_a_single_off_list_port() {
    let mut state = KadFirewallState::default();
    let helper_a = "203.0.113.22".parse().unwrap();
    let helper_b = "203.0.113.23".parse().unwrap();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 34, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 34, 20).unwrap();

    assert!(state.begin_udp_check([helper_a, helper_b], [41000], started_at));
    // Two helpers report two *different* off-list ports: no corroboration.
    let _ = state.record_firewall_udp_packet(helper_a, 0, 53000, completed_at);
    let _ = state.record_firewall_udp_packet(helper_b, 0, 54000, completed_at);
    let summary = state.finish_udp_check(completed_at).expect("summary");

    assert!(!summary.open);
    assert_eq!(summary.external_udp_port, None);
    assert!(!state.udp_open);
}

#[test]
fn udp_round_stays_unverified_when_no_tcp_request_can_be_sent() {
    let mut state = KadFirewallState::default();
    let helper = "203.0.113.12".parse().unwrap();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 32, 0).unwrap();

    assert!(state.begin_udp_check([helper], [41000], started_at));
    state.record_helper_request_failed(helper, "connect failed");

    assert!(state.finish_udp_check(started_at).is_none());
    assert!(!state.udp_verified);
    assert_eq!(
        state.last_error.as_deref(),
        Some("all UDP firewall-check TCP requests failed")
    );
}

#[test]
fn external_port_discovery_resolves_after_two_matching_reporters() {
    let mut state = KadFirewallState::default();
    let started_at = Utc.with_ymd_and_hms(2026, 4, 3, 2, 0, 0).unwrap();
    let observed_at = Utc.with_ymd_and_hms(2026, 4, 3, 2, 0, 2).unwrap();

    state.begin_external_port_discovery(started_at);
    assert_eq!(
        state.record_external_port_candidate("203.0.113.10".parse().unwrap(), 52123, observed_at),
        ExternalPortDiscoveryOutcome::Recorded
    );
    assert_eq!(
        state.record_external_port_candidate("203.0.113.11".parse().unwrap(), 52123, observed_at),
        ExternalPortDiscoveryOutcome::Resolved(52123)
    );
    assert_eq!(state.external_udp_port_for_request(), 52123);
    assert!(!state.needs_external_port_discovery());
}

#[test]
fn external_port_discovery_marks_inconsistent_reports_unreliable() {
    let mut state = KadFirewallState::default();
    let started_at = Utc.with_ymd_and_hms(2026, 4, 3, 2, 1, 0).unwrap();
    let observed_at = Utc.with_ymd_and_hms(2026, 4, 3, 2, 1, 3).unwrap();

    state.begin_external_port_discovery(started_at);
    assert_eq!(
        state.record_external_port_candidate("203.0.113.10".parse().unwrap(), 52123, observed_at),
        ExternalPortDiscoveryOutcome::Recorded
    );
    assert_eq!(
        state.record_external_port_candidate("203.0.113.11".parse().unwrap(), 52124, observed_at),
        ExternalPortDiscoveryOutcome::Recorded
    );
    assert_eq!(
        state.record_external_port_candidate("203.0.113.12".parse().unwrap(), 52125, observed_at),
        ExternalPortDiscoveryOutcome::Unreliable
    );
    assert_eq!(state.external_udp_port_for_request(), 0);
    assert!(!state.needs_external_port_discovery());
}

#[test]
fn tcp_firewall_recheck_tracks_up_to_four_helper_responses() {
    let mut state = KadFirewallState::default();
    let started_at = Utc.with_ymd_and_hms(2026, 4, 2, 23, 0, 0).unwrap();

    state.refresh_tcp_recheck(true, started_at);
    assert!(state.tcp_recheck_active);

    let helpers = [
        "203.0.113.10".parse().unwrap(),
        "203.0.113.11".parse().unwrap(),
        "203.0.113.12".parse().unwrap(),
        "203.0.113.13".parse().unwrap(),
        "203.0.113.14".parse().unwrap(),
    ];

    for helper in helpers.iter().take(4) {
        assert!(state.try_begin_tcp_firewall_probe(*helper, started_at));
    }
    assert!(!state.try_begin_tcp_firewall_probe(helpers[4], started_at));

    for (index, helper) in helpers.iter().take(4).enumerate() {
        let outcome = state.record_firewalled_response(
            *helper,
            "198.51.100.44".parse().unwrap(),
            started_at + chrono::Duration::seconds(index as i64 + 1),
        );
        if index < 3 {
            assert_eq!(outcome, FirewalledResponseOutcome::Recorded);
            assert!(state.tcp_recheck_active);
        } else {
            assert_eq!(outcome, FirewalledResponseOutcome::Completed);
            assert!(!state.tcp_recheck_active);
        }
    }

    assert_eq!(
        state.last_reported_external_ip.as_deref(),
        Some("198.51.100.44")
    );
}

#[test]
fn tcp_firewall_recheck_ignores_untracked_responses() {
    let mut state = KadFirewallState::default();
    let started_at = Utc.with_ymd_and_hms(2026, 4, 2, 23, 5, 0).unwrap();
    state.refresh_tcp_recheck(true, started_at);

    let outcome = state.record_firewalled_response(
        "203.0.113.99".parse().unwrap(),
        "198.51.100.99".parse().unwrap(),
        started_at,
    );

    assert_eq!(outcome, FirewalledResponseOutcome::Ignored);
    assert!(state.tcp_recheck_active);
}
