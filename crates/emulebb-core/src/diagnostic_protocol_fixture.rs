//! Diagnostics-only protocol fixtures that enter production state machines.
//!
//! These controls are compiled only for the packet-diagnostics daemon. They do
//! not persist sources or add them to discovery/source-hint state.

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;

use chrono::Utc;
use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
use emulebb_kad_proto::Ed2kHash;
use serde_json::json;

use crate::EmulebbCore;
use crate::ed2k_buddy_reask::register_kad_buddy_source_for_reask;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuddyRelayEligibilityFixtureState {
    pub tcp_firewalled: bool,
    pub udp_verified: bool,
    pub udp_open: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuddyRelayEligibilityFixtureErrorKind {
    Ed2kRuntimeNotRunning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuddyRelayEligibilityFixtureError {
    pub kind: BuddyRelayEligibilityFixtureErrorKind,
    message: String,
}

impl fmt::Display for BuddyRelayEligibilityFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BuddyRelayEligibilityFixtureError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedLowIdSourceFixture {
    pub file_hash: [u8; 16],
    pub source_ip: Ipv4Addr,
    pub source_tcp_port: u16,
    pub source_udp_port: u16,
    pub source_user_hash: [u8; 16],
    pub source_udp_version: u8,
    pub buddy_ip: Ipv4Addr,
    pub buddy_udp_port: u16,
    pub buddy_id: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuedLowIdSourceFixtureErrorKind {
    TransferNotFound,
    TransferNotActive,
    Ed2kRuntimeNotRunning,
    Ed2kNotConnected,
    UdpReaskDisabled,
    RegistrationRejected,
    WakeFailed,
}

impl QueuedLowIdSourceFixtureErrorKind {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TransferNotFound => "transfer_not_found",
            Self::TransferNotActive => "transfer_not_active",
            Self::Ed2kRuntimeNotRunning => "ed2k_runtime_not_running",
            Self::Ed2kNotConnected => "ed2k_not_connected",
            Self::UdpReaskDisabled => "udp_reask_disabled",
            Self::RegistrationRejected => "registration_rejected",
            Self::WakeFailed => "wake_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedLowIdSourceFixtureError {
    pub kind: QueuedLowIdSourceFixtureErrorKind,
    message: String,
}

impl QueuedLowIdSourceFixtureError {
    fn new(kind: QueuedLowIdSourceFixtureErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for QueuedLowIdSourceFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for QueuedLowIdSourceFixtureError {}

impl EmulebbCore {
    /// Prepare only the local reachability prerequisite for the production Kad
    /// buddy-relay path. All buddy and callback packets still travel through the
    /// ordinary production state machine and sockets.
    #[cfg(feature = "packet-diagnostics")]
    pub async fn prepare_buddy_relay_eligibility_fixture(
        &self,
    ) -> Result<BuddyRelayEligibilityFixtureState, BuddyRelayEligibilityFixtureError> {
        let kad_firewall = self
            .ed2k_runtime
            .lock()
            .await
            .as_ref()
            .map(|runtime| std::sync::Arc::clone(&runtime.kad_firewall))
            .ok_or_else(|| BuddyRelayEligibilityFixtureError {
                kind: BuddyRelayEligibilityFixtureErrorKind::Ed2kRuntimeNotRunning,
                message: "eD2K/Kad runtime is not running".to_string(),
            })?;
        let mut firewall = kad_firewall.lock().await;
        firewall.prepare_buddy_relay_fixture(Utc::now());
        let state = BuddyRelayEligibilityFixtureState {
            tcp_firewalled: firewall.tcp_firewalled().unwrap_or(true),
            udp_verified: firewall.udp_verified,
            udp_open: firewall.udp_open,
        };
        drop(firewall);

        emulebb_ed2k::diag_event::emit(
            "kad_event",
            "buddy_fixture",
            "info",
            json!({}),
            json!({
                "milestone": "buddy_relay_eligibility_prepared",
                "action": "prepare",
                "outcome": "eligible",
                "reason": "diagnostic_test_control",
                "tcpFirewalled": state.tcp_firewalled,
                "udpVerified": state.udp_verified,
                "udpOpen": state.udp_open,
            }),
        );
        Ok(state)
    }

    /// Register one queued LowID source against an existing active transfer and
    /// promptly run the ordinary production UDP-reask tick.
    pub async fn register_queued_lowid_source_fixture(
        &self,
        fixture: &QueuedLowIdSourceFixture,
    ) -> Result<(), QueuedLowIdSourceFixtureError> {
        let file_hash = Ed2kHash::from_bytes(fixture.file_hash);
        let file_hash_hex = file_hash.to_string();
        let transfer = self
            .transfers()
            .await
            .into_iter()
            .find(|transfer| transfer.hash == file_hash_hex)
            .ok_or_else(|| {
                fixture_failure(
                    fixture,
                    QueuedLowIdSourceFixtureErrorKind::TransferNotFound,
                    "transfer does not exist",
                )
            })?;
        if !super::should_retry_download_attempt_state(&transfer.state) {
            return Err(fixture_failure(
                fixture,
                QueuedLowIdSourceFixtureErrorKind::TransferNotActive,
                format!("transfer is not active (state={})", transfer.state),
            ));
        }

        let server_state = self
            .ed2k_runtime
            .lock()
            .await
            .as_ref()
            .map(|runtime| std::sync::Arc::clone(&runtime.server_state))
            .ok_or_else(|| {
                fixture_failure(
                    fixture,
                    QueuedLowIdSourceFixtureErrorKind::Ed2kRuntimeNotRunning,
                    "eD2K runtime is not running",
                )
            })?;
        if !server_state.read().await.connected {
            return Err(fixture_failure(
                fixture,
                QueuedLowIdSourceFixtureErrorKind::Ed2kNotConnected,
                "eD2K runtime is not connected",
            ));
        }

        let reask_handle = self
            .ed2k_reask_handle
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| {
                fixture_failure(
                    fixture,
                    QueuedLowIdSourceFixtureErrorKind::UdpReaskDisabled,
                    "UDP reask is not enabled",
                )
            })?;
        let source = fixture_source(fixture);
        let mut requested = HashSet::new();
        if !register_kad_buddy_source_for_reask(
            &reask_handle,
            file_hash,
            &source,
            fixture.source_udp_version,
            &mut requested,
        ) {
            return Err(fixture_failure(
                fixture,
                QueuedLowIdSourceFixtureErrorKind::RegistrationRejected,
                "queued LowID source registration was rejected",
            ));
        }
        reask_handle.diagnostic_wake_tick().await.map_err(|error| {
            fixture_failure(
                fixture,
                QueuedLowIdSourceFixtureErrorKind::WakeFailed,
                error,
            )
        })?;
        Ok(())
    }
}

fn fixture_source(fixture: &QueuedLowIdSourceFixture) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash: Ed2kHash::from_bytes(fixture.file_hash),
        ip: fixture.source_ip,
        tcp_port: fixture.source_tcp_port,
        client_id: u32::from(fixture.source_ip),
        low_id: true,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: Some(fixture.source_user_hash),
        source_server: None,
        buddy_id: Some(fixture.buddy_id),
        buddy_endpoint: Some((fixture.buddy_ip, fixture.buddy_udp_port)),
        source_udp_port: Some(fixture.source_udp_port),
    }
}

fn fixture_failure(
    fixture: &QueuedLowIdSourceFixture,
    kind: QueuedLowIdSourceFixtureErrorKind,
    message: impl Into<String>,
) -> QueuedLowIdSourceFixtureError {
    let source_peer = format!("{}:{}", fixture.source_ip, fixture.source_tcp_port);
    let source_udp_endpoint = format!("{}:{}", fixture.source_ip, fixture.source_udp_port);
    let buddy_endpoint = format!("{}:{}", fixture.buddy_ip, fixture.buddy_udp_port);
    emulebb_ed2k::diag_event::emit(
        "sched",
        "udp_reask_source_registered",
        "warning",
        json!({
            "fileHash": hex::encode(fixture.file_hash),
            "peer": source_peer,
            "peerHash": hex::encode(fixture.source_user_hash),
        }),
        json!({
            "outcome": "failed",
            "reason": kind.reason(),
            "sourceUdpEndpoint": source_udp_endpoint,
            "sourceUdpVersion": fixture.source_udp_version,
            "lowId": true,
            "buddyEndpoint": buddy_endpoint,
            "buddyId": hex::encode(fixture.buddy_id),
        }),
    );
    QueuedLowIdSourceFixtureError::new(kind, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_index::FileIndex;

    fn fixture() -> QueuedLowIdSourceFixture {
        QueuedLowIdSourceFixture {
            file_hash: [0x11; 16],
            source_ip: Ipv4Addr::new(192, 0, 2, 20),
            source_tcp_port: 4662,
            source_udp_port: 4672,
            source_user_hash: [0x22; 16],
            source_udp_version: 4,
            buddy_ip: Ipv4Addr::new(198, 51, 100, 30),
            buddy_udp_port: 5000,
            buddy_id: [0x33; 16],
        }
    }

    #[test]
    fn fixture_source_is_an_exact_non_persisted_kad_buddy_source() {
        let fixture = fixture();
        let source = fixture_source(&fixture);

        assert!(source.has_kad_buddy_reask_target());
        assert_eq!(source.file_hash, Ed2kHash::from_bytes(fixture.file_hash));
        assert_eq!(source.source_udp_port, Some(fixture.source_udp_port));
        assert_eq!(source.user_hash, Some(fixture.source_user_hash));
        assert_eq!(source.buddy_id, Some(fixture.buddy_id));
        assert_eq!(
            source.buddy_endpoint,
            Some((fixture.buddy_ip, fixture.buddy_udp_port))
        );
    }

    #[tokio::test]
    async fn fixture_requires_an_existing_transfer_before_runtime_state() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();

        let error = core
            .register_queued_lowid_source_fixture(&fixture())
            .await
            .unwrap_err();

        assert_eq!(
            error.kind,
            QueuedLowIdSourceFixtureErrorKind::TransferNotFound
        );
    }
}
