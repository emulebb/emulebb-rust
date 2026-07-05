use super::{DhtNode, contact_helpers::addr_from_contact};
use crate::error::DhtError;
use crate::types::{FirewallCheckHelper, HelloPeerMetadata, parse_hello_peer_metadata};
use emulebb_kad_proto::{KadUdpKey, NodeId, Tag};
use emulebb_kad_routing::{
    Contact, RoutingError, RoutingSplitDeniedReason, RoutingSubnetLimitScope,
};
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, warn};

impl DhtNode {
    /// Snapshot currently known contacts.
    pub async fn routing_contacts(&self) -> Vec<Contact> {
        self.inner.routing_table.lock().await.all_contacts()
    }

    /// Parse a `nodes.dat` payload and upsert its contacts into the routing
    /// table. Returns the number of contacts accepted.
    pub async fn import_nodes_dat(&self, data: &[u8]) -> Result<usize, DhtError> {
        let contacts = crate::bootstrap::parse_nodes_dat(data)?;
        let mut added = 0usize;
        for bc in contacts {
            let mut contact = Contact::new(bc.node_id, bc.ip, bc.udp_port, bc.tcp_port, bc.version);
            contact.udp_key = bc.udp_key;
            if self.add_contact(contact).await.is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Upsert a single contact into the routing table.
    pub async fn add_contact(&self, contact: Contact) -> Result<(), DhtError> {
        let mut contact = contact;
        let addr = addr_from_contact(&contact);
        if contact.udp_key == KadUdpKey::ZERO
            && let Some(known_udp_key) = self.known_peer_key(addr)
        {
            contact.udp_key = known_udp_key;
        }
        self.inner.rpc.register_peer_identity(addr, contact.id);
        self.inner
            .rpc
            .register_peer_version(addr, contact.kad_version);
        if contact.udp_key != KadUdpKey::ZERO {
            self.inner
                .rpc
                .register_peer_key(addr, contact.udp_key.value());
        }
        let contact_id = contact.id;
        let contact_ip = contact.ip;
        let contact_udp_port = contact.udp_port;
        match self.inner.routing_table.lock().await.add_contact(contact) {
            Ok(()) => Ok(()),
            Err(error) => {
                log_routing_rejection(&error, contact_id, contact_ip, contact_udp_port);
                Err(error.into())
            }
        }
    }

    /// Run one oracle small-timer routing-maintenance sweep over the table:
    /// seed expiry windows, drop dead+expired contacts, and return the per-leaf
    /// lowest-quality expired contacts to HELLO-probe (oracle
    /// `CRoutingZone::OnSmallTimer`). Removals are applied inside the lock.
    pub async fn routing_small_timer_maintenance(
        &self,
    ) -> Vec<emulebb_kad_routing::ProbeCandidate> {
        self.inner
            .routing_table
            .lock()
            .await
            .small_timer_maintenance(std::time::SystemTime::now())
            .probes
    }

    /// One random `FindNode` target per leaf zone that passes the oracle
    /// big-timer fill gate (`CRoutingZone::OnBigTimer` -> `RandomLookup`). Used
    /// by the maintenance loop to keep buckets populated.
    pub async fn routing_random_lookup_targets(&self) -> Vec<NodeId> {
        use rand::Rng;
        let table = self.inner.routing_table.lock().await;
        // Create the (non-Send) RNG only after the await so it is never held
        // across a suspension point.
        let mut rng = rand::thread_rng();
        let mut next = || rng.r#gen::<u8>();
        table.random_lookup_targets(&mut next)
    }

    /// Advance a contact's `CheckingType` staleness counter after a maintenance
    /// HELLO probe was sent to it (oracle `CContact::CheckingType`). Returns the
    /// new counter value, or `None` if the contact is gone.
    pub async fn routing_advance_checking_type(&self, id: &NodeId) -> Option<u8> {
        self.inner.routing_table.lock().await.checking_type(id)
    }

    /// Mark a routing contact as IP-verified (three-way handshake / legacy
    /// challenge completed). Mirrors `CRoutingZone::VerifyContact`: the contact
    /// must exist with a matching IP. Returns whether a contact was verified.
    pub async fn verify_contact(&self, id: &NodeId, ip: std::net::Ipv4Addr) -> bool {
        self.inner.routing_table.lock().await.verify_contact(id, ip)
    }

    /// Return the closest known contacts to the target.
    pub async fn closest_contacts(&self, target: &NodeId, limit: usize) -> Vec<Contact> {
        self.inner
            .routing_table
            .lock()
            .await
            .get_closest(target, limit)
    }

    /// Return the closest known contacts to the target, restricted to contacts
    /// whose oracle freshness type is at most `max_type` (oracle
    /// `GetClosestTo(uMaxType, ...)`). Used by the KADEMLIA2_REQ responder.
    pub async fn closest_contacts_max_type(
        &self,
        target: &NodeId,
        limit: usize,
        max_type: u8,
    ) -> Vec<Contact> {
        self.inner
            .routing_table
            .lock()
            .await
            .get_closest_max_type(target, limit, max_type)
    }

    /// Select up to `limit` contacts suitable as Kad UDP firewall-check helpers.
    ///
    /// Mirrors `CUDPFirewallTester::QueryNextClient`: only contacts that support
    /// the UDP firewall check (Kad version > 5, i.e. `>= 6`) and are not
    /// themselves UDP firewalled qualify, and we never test ourselves. We also
    /// require a usable UDP and eD2k TCP port. Returned newest-first so a fresh
    /// lookup's contacts are preferred, matching the oracle's `AddHead` ordering.
    pub async fn firewall_check_helpers(&self, limit: usize) -> Vec<FirewallCheckHelper> {
        if limit == 0 {
            return Vec::new();
        }
        let own_id = self.own_id();
        // The Kad socket is IPv4-only; capture the bound IPv4 to skip ourselves.
        let local_ip = self
            .bind_addr()
            .ok()
            .and_then(|addr| addr.ip().to_string().parse::<std::net::Ipv4Addr>().ok());
        let mut contacts = self.inner.routing_table.lock().await.all_contacts();
        // Newest contacts first (oracle prepends fresh candidates).
        contacts.sort_by_key(|contact| std::cmp::Reverse(contact.created_at));
        contacts
            .into_iter()
            .filter(|contact| {
                contact.kad_version >= 6
                    && !contact.udp_firewalled
                    && contact.udp_port != 0
                    && contact.tcp_port != 0
                    && contact.id != own_id
                    && local_ip != Some(contact.ip)
            })
            .take(limit)
            .map(|contact| FirewallCheckHelper {
                id: contact.id,
                ip: contact.ip,
                udp_port: contact.udp_port,
                tcp_port: contact.tcp_port,
                kad_version: contact.kad_version,
            })
            .collect()
    }

    /// Record a contact learned from a Kad HELLO request or response.
    pub async fn add_contact_from_hello(
        &self,
        from: SocketAddr,
        node_id: NodeId,
        tcp_port: u16,
        version: u8,
        tags: &[Tag],
    ) -> Result<HelloPeerMetadata, DhtError> {
        let mut metadata = parse_hello_peer_metadata(tags);
        if version < 8 {
            metadata.requests_hello_res_ack = false;
        }

        let IpAddr::V4(ip) = from.ip() else {
            return Ok(metadata);
        };

        // Oracle AddContact_KADEMLIA2 (KademliaUDPListener.cpp:510-511): do not
        // add (or update) UDP-firewalled sources to the routing table — they
        // cannot serve as reachable Kad contacts. Still return the parsed
        // metadata so the caller's handshake logic can run.
        if metadata.udp_firewalled {
            debug!(
                target: "kad_routing",
                %node_id,
                contact_ip = %ip,
                "skipping UDP-firewalled Kad contact from HELLO"
            );
            return Ok(metadata);
        }
        let mut contact = Contact::new(
            node_id,
            ip,
            metadata.hello_source_udp_port.unwrap_or(from.port()),
            tcp_port,
            version,
        );
        contact.hello_source_udp_port = metadata.hello_source_udp_port;
        contact.udp_firewalled = metadata.udp_firewalled;
        contact.tcp_firewalled = metadata.tcp_firewalled;
        contact.requests_hello_res_ack = metadata.requests_hello_res_ack;
        if let Some(known_udp_key) = self.known_peer_key(from) {
            contact.udp_key = known_udp_key;
        }

        self.add_contact(contact).await?;
        Ok(metadata)
    }
}

fn log_routing_rejection(
    error: &RoutingError,
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
) {
    match error {
        RoutingError::SubnetLimitExceeded { prefix, scope } => {
            log_subnet_limit_rejection(contact_id, contact_ip, contact_udp_port, *prefix, scope);
        }
        RoutingError::SplitDenied { reason } => {
            log_split_denied_rejection(contact_id, contact_ip, contact_udp_port, reason);
        }
        RoutingError::IpLimitExceeded { .. } => {
            log_ip_limit_rejection(contact_id, contact_ip, contact_udp_port);
        }
        RoutingError::TableFull { max } => {
            log_table_full_rejection(contact_id, contact_ip, contact_udp_port, *max);
        }
    }
}

fn log_subnet_limit_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
    prefix: u8,
    scope: &RoutingSubnetLimitScope,
) {
    warn!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        prefix,
        scope = routing_subnet_scope_label(scope),
        "routing contact rejected by subnet limit"
    );
}

fn log_split_denied_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
    reason: &RoutingSplitDeniedReason,
) {
    warn!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        reason = routing_split_denied_reason_label(reason),
        "routing leaf split denied while inserting contact"
    );
}

fn log_ip_limit_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
) {
    debug!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        "routing contact rejected by duplicate IP limit"
    );
}

fn log_table_full_rejection(
    contact_id: NodeId,
    contact_ip: std::net::Ipv4Addr,
    contact_udp_port: u16,
    max: usize,
) {
    warn!(
        target: "kad_routing",
        contact_id = %contact_id,
        contact_ip = %contact_ip,
        contact_udp_port,
        max,
        "routing table rejected contact because the destination bin is full"
    );
}

fn routing_subnet_scope_label(scope: &RoutingSubnetLimitScope) -> &'static str {
    match scope {
        RoutingSubnetLimitScope::Global => "global",
        RoutingSubnetLimitScope::BinLocal => "bin_local",
    }
}

fn routing_split_denied_reason_label(reason: &RoutingSplitDeniedReason) -> &'static str {
    match reason {
        RoutingSplitDeniedReason::DepthLimit => "depth_limit",
        RoutingSplitDeniedReason::MaxTableSize => "max_table_size",
        RoutingSplitDeniedReason::ZoneIndexCap => "zone_index_cap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DhtConfig;
    use emulebb_kad_proto::{Tag, TagValue, tag_name};

    #[tokio::test]
    async fn hello_contact_uses_advertised_source_udp_port_and_metadata() {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(crate::test_bind_ip()),
                0,
            )),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let node_id = NodeId::from_bytes([0x42; 16]);

        let metadata = dht
            .add_contact_from_hello(
                "198.51.100.22:41002".parse().unwrap(),
                node_id,
                41001,
                10,
                &[
                    Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(42002)),
                    Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x06)),
                ],
            )
            .await
            .unwrap();

        assert_eq!(metadata.hello_source_udp_port, Some(42002));
        assert!(!metadata.udp_firewalled);
        assert!(metadata.tcp_firewalled);
        assert!(metadata.requests_hello_res_ack);
        let contact = dht.routing_contacts().await.pop().unwrap();
        assert_eq!(contact.id, node_id);
        assert_eq!(contact.udp_port, 42002);
        assert_eq!(contact.tcp_port, 41001);
        assert_eq!(contact.hello_source_udp_port, Some(42002));
        assert!(!contact.udp_firewalled);
        assert!(contact.tcp_firewalled);
        assert!(contact.requests_hello_res_ack);
    }

    #[tokio::test]
    async fn hello_skips_udp_firewalled_contact_but_returns_metadata() {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(crate::test_bind_ip()),
                0,
            )),
            ..DhtConfig::default()
        })
        .await
        .unwrap();

        // KADMISCOPTIONS bit0 set => UDP firewalled.
        let metadata = dht
            .add_contact_from_hello(
                "198.51.100.30:42030".parse().unwrap(),
                NodeId::from_bytes([0x55; 16]),
                42031,
                8,
                &[Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x01))],
            )
            .await
            .unwrap();

        assert!(metadata.udp_firewalled);
        // The firewalled peer must NOT be added to the routing table.
        assert!(dht.routing_contacts().await.is_empty());
    }

    #[tokio::test]
    async fn verify_contact_flips_verified_only_on_matching_ip() {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(crate::test_bind_ip()),
                0,
            )),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let node_id = NodeId::from_bytes([0x77; 16]);
        let contact = Contact::new(node_id, "203.0.113.7".parse().unwrap(), 42007, 42008, 8);
        dht.add_contact(contact).await.unwrap();

        // Mismatched IP (spoofed) must not verify.
        assert!(
            !dht.verify_contact(&node_id, "198.51.100.9".parse().unwrap())
                .await
        );
        assert!(!dht.routing_contacts().await[0].verified);

        // Matching IP completes the handshake.
        assert!(
            dht.verify_contact(&node_id, "203.0.113.7".parse().unwrap())
                .await
        );
        assert!(dht.routing_contacts().await[0].verified);
    }

    #[tokio::test]
    async fn firewall_check_helpers_filter_to_supported_open_contacts() {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(crate::test_bind_ip()),
                0,
            )),
            ..DhtConfig::default()
        })
        .await
        .unwrap();

        // Eligible: kad v6, open, real ports.
        let mut good = Contact::new(
            NodeId::from_bytes([0x11; 16]),
            "198.51.100.10".parse().unwrap(),
            42010,
            42011,
            6,
        );
        good.udp_firewalled = false;
        dht.add_contact(good).await.unwrap();

        // Ineligible: kad version too low.
        let old = Contact::new(
            NodeId::from_bytes([0x22; 16]),
            "203.0.113.11".parse().unwrap(),
            42020,
            42021,
            5,
        );
        dht.add_contact(old).await.unwrap();

        // Ineligible: peer is itself UDP firewalled.
        let mut fw = Contact::new(
            NodeId::from_bytes([0x33; 16]),
            "192.0.2.12".parse().unwrap(),
            42030,
            42031,
            8,
        );
        fw.udp_firewalled = true;
        dht.add_contact(fw).await.unwrap();

        // Ineligible: no eD2k TCP port advertised.
        let no_tcp = Contact::new(
            NodeId::from_bytes([0x44; 16]),
            "198.18.0.13".parse().unwrap(),
            42040,
            0,
            8,
        );
        dht.add_contact(no_tcp).await.unwrap();

        let helpers = dht.firewall_check_helpers(8).await;
        assert_eq!(helpers.len(), 1);
        assert_eq!(
            helpers[0].ip,
            "198.51.100.10".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(helpers[0].tcp_port, 42011);

        assert!(dht.firewall_check_helpers(0).await.is_empty());
    }
}
