//! Connection-scoped state and controls shared by established peer sessions.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Result;
use emulebb_kad_dht::DhtNode;
use tokio::sync::{Mutex, RwLock};

use crate::{
    ed2k_server::Ed2kServerState,
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadPeerIdentity},
    kad_firewall::KadFirewallState,
};

use super::{
    Ed2kCallbackSessionHandle, OP_EDONKEYPROT, OP_EMULEPROT,
    codec::{ClientIdChange, KadCallbackRequest, decode_client_id_change_payload},
    firewall_helper::{complete_authorized_kad_callback, decode_kad_callback_if_running},
    hello::DecodedHelloProfile,
};

/// Live control-plane dependencies needed by any established peer connection.
#[derive(Clone)]
pub struct Ed2kEstablishedPeerContext {
    /// Live Kad node used to validate and complete buddy-relayed callbacks.
    pub dht: DhtNode,
    /// Shared Kad TCP-firewall check state updated by authenticated ACKs.
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
    /// Listener-owned bounded callback-session dispatcher.
    pub callback_sessions: Ed2kCallbackSessionHandle,
    /// Current server session, used to resolve a changed LowID's server route.
    pub server_state: Arc<RwLock<Ed2kServerState>>,
}

/// Mutable network identity retained for the lifetime of one peer connection.
///
/// Stock updates these fields when `OP_CHANGE_CLIENT_ID` reports that the peer
/// changed servers. Keeping them outside either upload or download role avoids
/// connection-direction-dependent callback and reask routing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct EstablishedPeerIdentity {
    pub(in crate::ed2k_tcp) client_id: Option<u32>,
    pub(in crate::ed2k_tcp) server_endpoint: Option<SocketAddr>,
}

impl EstablishedPeerIdentity {
    pub(in crate::ed2k_tcp) fn from_hello(profile: &DecodedHelloProfile) -> Self {
        Self {
            client_id: Some(profile.identity.client_id),
            server_endpoint: profile.identity.server_endpoint,
        }
    }

    pub(in crate::ed2k_tcp) const fn client_id(self) -> Option<u32> {
        self.client_id
    }

    pub(in crate::ed2k_tcp) const fn server_endpoint(self) -> Option<SocketAddr> {
        self.server_endpoint
    }

    pub(in crate::ed2k_tcp) fn is_low_id(self) -> bool {
        self.client_id
            .is_some_and(|client_id| client_id < 0x0100_0000)
    }

    /// Apply stock's guarded `OP_CHANGE_CLIENT_ID` identity transition.
    ///
    /// A changed LowID is meaningful only when the reported server is known.
    /// Rust currently knows the active server route, which is also the only
    /// route through which it can issue a server callback. HighID changes are
    /// accepted only when the reported ID is the connected peer's IPv4 address.
    pub(in crate::ed2k_tcp) fn apply_client_id_change(
        &mut self,
        peer_ip: IpAddr,
        known_server: Option<SocketAddr>,
        payload: &[u8],
    ) -> Result<AppliedClientIdChange> {
        let change = decode_client_id_change_payload(payload)?;
        let server_endpoint = known_server.filter(|endpoint| {
            endpoint.ip() == IpAddr::V4(Ipv4Addr::from(change.new_server_ip.to_le_bytes()))
        });
        let accepted = if change.new_user_id < 0x0100_0000 {
            server_endpoint.is_some()
        } else {
            matches!(
                peer_ip,
                IpAddr::V4(ip)
                    if change.new_user_id == u32::from_le_bytes(ip.octets())
            )
        };

        if accepted {
            self.client_id = Some(change.new_user_id);
            if let Some(server_endpoint) = server_endpoint {
                self.server_endpoint = Some(server_endpoint);
            }
        }

        Ok(AppliedClientIdChange { change, accepted })
    }

    pub(in crate::ed2k_tcp) fn apply_to_upload_identity(
        self,
        identity: &mut Ed2kUploadPeerIdentity,
    ) {
        identity.client_id = self.client_id;
        identity.server_endpoint = self.server_endpoint;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct AppliedClientIdChange {
    pub(in crate::ed2k_tcp) change: ClientIdChange,
    pub(in crate::ed2k_tcp) accepted: bool,
}

/// Decode and complete an established-session `OP_CALLBACK` through the shared
/// stock authorization path. `None` preserves stock's Kad-stopped ignore rule.
pub(in crate::ed2k_tcp) async fn handle_established_kad_callback(
    context: &Ed2kEstablishedPeerContext,
    transfer_runtime: &Ed2kTransferRuntime,
    payload: &[u8],
    source: &str,
) -> Result<Option<KadCallbackRequest>> {
    let Some(callback) = decode_kad_callback_if_running(&context.dht, payload, source)? else {
        return Ok(None);
    };
    complete_authorized_kad_callback(
        &context.dht,
        transfer_runtime,
        &context.callback_sessions,
        &callback,
        source,
    )
    .await;
    Ok(Some(callback))
}

/// Record an established-session Kad TCP firewall-check acknowledgement.
pub(in crate::ed2k_tcp) async fn record_established_kad_firewall_ack(
    context: &Ed2kEstablishedPeerContext,
    peer_ip: IpAddr,
) -> bool {
    context
        .kad_firewall
        .lock()
        .await
        .record_tcp_open_ack(peer_ip, chrono::Utc::now())
}

/// Stock ignores unknown opcodes inside either recognized peer protocol after
/// HELLO, while malformed framing and unknown protocol markers remain fatal.
pub(in crate::ed2k_tcp) const fn tolerates_unknown_established_opcode(protocol: u8) -> bool {
    matches!(protocol, OP_EDONKEYPROT | OP_EMULEPROT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_tcp::{Ed2kHelloIdentity, decode_hello_profile, encode_hello_request};

    fn identity(client_id: u32, server_ip: Ipv4Addr, server_port: u16) -> EstablishedPeerIdentity {
        let packet = encode_hello_request(Ed2kHelloIdentity {
            user_hash: [0x31; 16],
            client_id,
            tcp_port: 4662,
            udp_port: 4672,
            server_ip: u32::from_le_bytes(server_ip.octets()),
            server_port,
            connect_options: 0,
            direct_udp_callback: false,
        });
        EstablishedPeerIdentity::from_hello(
            &decode_hello_profile(&packet[6..]).expect("decode hello"),
        )
    }

    #[test]
    fn known_server_change_updates_low_id_and_route() {
        let old_server = Ipv4Addr::new(203, 0, 113, 10);
        let new_server = Ipv4Addr::new(203, 0, 113, 11);
        let new_endpoint = SocketAddr::new(IpAddr::V4(new_server), 4661);
        let mut identity = identity(0x0102_0304, old_server, 4661);
        let mut payload = 0x0000_1234_u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&u32::from_le_bytes(new_server.octets()).to_le_bytes());

        let applied = identity
            .apply_client_id_change(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
                Some(new_endpoint),
                &payload,
            )
            .unwrap();

        assert!(applied.accepted);
        assert_eq!(identity.client_id(), Some(0x0000_1234));
        assert_eq!(identity.server_endpoint(), Some(new_endpoint));
        assert!(identity.is_low_id());
    }

    #[test]
    fn unknown_server_does_not_rebind_low_id() {
        let old_server = Ipv4Addr::new(203, 0, 113, 10);
        let mut identity = identity(0x0102_0304, old_server, 4661);
        let original = identity;
        let mut payload = 0x0000_1234_u32.to_le_bytes().to_vec();
        payload.extend_from_slice(
            &u32::from_le_bytes(Ipv4Addr::new(203, 0, 113, 99).octets()).to_le_bytes(),
        );

        let applied = identity
            .apply_client_id_change(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
                Some(SocketAddr::new(IpAddr::V4(old_server), 4661)),
                &payload,
            )
            .unwrap();

        assert!(!applied.accepted);
        assert_eq!(identity, original);
    }

    #[test]
    fn valid_high_id_keeps_prior_route_when_reported_server_is_unknown() {
        let old_server = Ipv4Addr::new(203, 0, 113, 10);
        let peer_ip = Ipv4Addr::new(198, 51, 100, 20);
        let mut identity = identity(0x0000_1234, old_server, 4661);
        let mut payload = u32::from_le_bytes(peer_ip.octets()).to_le_bytes().to_vec();
        payload.extend_from_slice(
            &u32::from_le_bytes(Ipv4Addr::new(203, 0, 113, 99).octets()).to_le_bytes(),
        );

        let applied = identity
            .apply_client_id_change(
                IpAddr::V4(peer_ip),
                Some(SocketAddr::new(IpAddr::V4(old_server), 4661)),
                &payload,
            )
            .unwrap();

        assert!(applied.accepted);
        assert_eq!(
            identity.client_id(),
            Some(u32::from_le_bytes(peer_ip.octets()))
        );
        assert_eq!(
            identity.server_endpoint(),
            Some(SocketAddr::new(IpAddr::V4(old_server), 4661))
        );
        assert!(!identity.is_low_id());
    }

    #[test]
    fn established_unknown_opcode_tolerance_is_protocol_scoped() {
        assert!(tolerates_unknown_established_opcode(OP_EDONKEYPROT));
        assert!(tolerates_unknown_established_opcode(OP_EMULEPROT));
        assert!(!tolerates_unknown_established_opcode(0x01));
    }
}
