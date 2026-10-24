//! Direct UDP callback transmission over the shared Kad/client-UDP socket.
//!
//! `OP_DIRECTCALLBACKREQ` is a LowID connection route, not a periodic source
//! reask optimization. Its sender therefore owns no reask state and remains a
//! separate capability even when source reasking is disabled.

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Result, bail};
use emulebb_kad_dht::DhtNode;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::reachability::{ExternalReachability, ReachabilityRuntimeAuthority};

use super::transport::{ClientUdpSendRole, send_client_udp_datagram};

/// Inputs for [`DirectCallbackSender::dispatch`]: everything needed to encode
/// and address one `OP_DIRECTCALLBACKREQ`.
#[derive(Debug, Clone)]
pub struct DirectCallbackArgs {
    /// The source's Kad UDP endpoint (its eD2k IP + advertised `FT_SOURCEUPORT`).
    pub dest: SocketAddr,
    /// Our externally-advertised eD2k TCP port the source connects back to.
    pub our_tcp_port: u16,
    /// Our eD2k user hash (identifies the connect-back to the source).
    pub our_user_hash: [u8; 16],
    /// Our connect options (`GetMyConnectOptions(true, false)`).
    pub connect_options: u8,
    /// The source's user hash — obfuscation key material.
    pub dest_user_hash: Option<[u8; 16]>,
    /// Whether to obfuscate toward the source (`ShouldReceiveCryptUDPPackets`).
    pub obfuscate: bool,
}

/// Whether the client-UDP transport proved that a direct callback did or did
/// not reach the local datagram socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectCallbackDispatchOutcome {
    Sent,
    NotSent { reason: String },
}

/// Direct-callback-only sender over the shared Kad/client-UDP socket.
#[derive(Clone)]
pub struct DirectCallbackSender {
    dht: DhtNode,
    reachability: ExternalReachability,
}

impl DirectCallbackSender {
    pub fn new(dht: DhtNode, reachability: ExternalReachability) -> Self {
        Self { dht, reachability }
    }

    /// Send one callback request under the callback ticket's absolute deadline.
    ///
    /// A pre-send cancellation, expired deadline, unavailable obfuscation key,
    /// or explicit socket error is proven [`DirectCallbackDispatchOutcome::NotSent`].
    /// Cancellation or deadline expiry while the socket write is in flight is
    /// delivery-ambiguous and therefore returns an error; callers must retain
    /// callback admission authority in that case.
    pub async fn dispatch(
        &self,
        args: DirectCallbackArgs,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<DirectCallbackDispatchOutcome> {
        if cancel.is_cancelled() {
            return Ok(DirectCallbackDispatchOutcome::NotSent {
                reason: "direct callback cancelled before UDP send".to_string(),
            });
        }
        if Instant::now() >= deadline {
            return Ok(DirectCallbackDispatchOutcome::NotSent {
                reason: "direct callback deadline elapsed before UDP send".to_string(),
            });
        }
        let public_ip = self.reachability.get();
        if args.obfuscate && public_ip.is_none() {
            return Ok(DirectCallbackDispatchOutcome::NotSent {
                reason: "direct callback obfuscation requires our public IP".to_string(),
            });
        }

        let send =
            send_direct_callback_req(&self.dht, public_ip.map_or([0; 4], |ip| ip.octets()), args);
        tokio::pin!(send);
        tokio::select! {
            biased;
            outcome = &mut send => Ok(outcome),
            () = cancel.cancelled() => {
                bail!("direct callback cancelled during UDP send; delivery unknown")
            }
            () = tokio::time::sleep_until(deadline.into()) => {
                bail!("direct callback deadline elapsed during UDP send; delivery unknown")
            }
        }
    }
}

/// Originate one `OP_DIRECTCALLBACKREQ` over the shared client-UDP socket (we
/// are a downloader asking a firewalled type-6 source to connect back). Mirrors
/// the oracle `CCS_DIRECTCALLBACK` send: our TCP port + userhash + connect
/// options, obfuscated toward the source when its crypt key is known.
pub(super) async fn send_direct_callback_req(
    dht: &DhtNode,
    our_public_ip: [u8; 4],
    args: DirectCallbackArgs,
) -> DirectCallbackDispatchOutcome {
    let target = super::outbound::OutboundReaskTarget {
        dest_user_hash: args.dest_user_hash.unwrap_or([0u8; 16]),
        our_public_ip,
        obfuscate: args.obfuscate && args.dest_user_hash.is_some(),
    };
    let datagram = super::outbound::build_direct_callback_req_datagram(
        args.our_tcp_port,
        &args.our_user_hash,
        args.connect_options,
        &target,
    );
    match send_client_udp_datagram(
        dht,
        args.dest,
        ClientUdpSendRole::DirectCallbackRequest,
        &datagram,
    )
    .await
    {
        Ok(()) => {
            super::dump::dump_client_udp_send(args.dest, &datagram);
            trace!("ed2k udp: sent OP_DIRECTCALLBACKREQ to {}", args.dest);
            DirectCallbackDispatchOutcome::Sent
        }
        Err(error) => {
            trace!(
                "ed2k udp: OP_DIRECTCALLBACKREQ to {} failed: {error}",
                args.dest
            );
            DirectCallbackDispatchOutcome::NotSent {
                reason: error.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use emulebb_kad_dht::{DhtConfig, DhtNode};
    use emulebb_kad_proto::NodeId;
    use tokio::net::UdpSocket;

    use super::*;

    fn args(dest: SocketAddr, obfuscate: bool) -> DirectCallbackArgs {
        DirectCallbackArgs {
            dest,
            our_tcp_port: 4662,
            our_user_hash: [0x11; 16],
            connect_options: 0x03,
            dest_user_hash: Some([0x22; 16]),
            obfuscate,
        }
    }

    async fn sender(reachability: ExternalReachability) -> DirectCallbackSender {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            node_id: NodeId::from_bytes([0x33; 16]),
            udp_key: 0x4455_6677,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        DirectCallbackSender::new(dht, reachability)
    }

    #[tokio::test]
    async fn sender_emits_plaintext_callback_without_reask_runtime() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dest = receiver.local_addr().unwrap();
        let sender = sender(ReachabilityRuntimeAuthority::new().reader()).await;

        assert_eq!(
            sender
                .dispatch(
                    args(dest, false),
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new(),
                )
                .await
                .unwrap(),
            DirectCallbackDispatchOutcome::Sent
        );

        let mut received = [0_u8; 64];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut received))
                .await
                .unwrap()
                .unwrap();
        let expected = super::super::outbound::build_direct_callback_req_datagram(
            4662,
            &[0x11; 16],
            0x03,
            &super::super::outbound::OutboundReaskTarget {
                dest_user_hash: [0x22; 16],
                our_public_ip: [0; 4],
                obfuscate: false,
            },
        );
        assert_eq!(&received[..len], expected.bytes.as_slice());
    }

    #[tokio::test]
    async fn sender_fails_closed_when_obfuscation_public_ip_is_unknown() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let sender = sender(ReachabilityRuntimeAuthority::new().reader()).await;

        let outcome = sender
            .dispatch(
                args(receiver.local_addr().unwrap(), true),
                Instant::now() + Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            DirectCallbackDispatchOutcome::NotSent { reason }
                if reason.contains("requires our public IP")
        ));
    }

    #[tokio::test]
    async fn sender_classifies_pre_send_stops_as_known_not_sent() {
        let sender = sender(ReachabilityRuntimeAuthority::new().reader()).await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(
            sender
                .dispatch(
                    args(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), false),
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                )
                .await
                .unwrap(),
            DirectCallbackDispatchOutcome::NotSent { reason }
                if reason.contains("cancelled before UDP send")
        ));

        assert!(matches!(
            sender
                .dispatch(
                    args(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), false),
                    Instant::now()
                        .checked_sub(Duration::from_secs(1))
                        .expect("representable past instant"),
                    &CancellationToken::new(),
                )
                .await
                .unwrap(),
            DirectCallbackDispatchOutcome::NotSent { reason }
                if reason.contains("deadline elapsed before UDP send")
        ));
    }
}
