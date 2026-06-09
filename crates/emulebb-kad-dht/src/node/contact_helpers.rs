use emulebb_kad_routing::{Contact, RoutingTable};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

pub(super) fn addr_from_contact(contact: &Contact) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port)
}

/// Mirrors the oracle's higher punishment path for massive request floods by
/// expiring the matching routing-table contact when we can identify one.
pub(super) async fn expire_contact_for_massive_flood(
    routing_table: &Arc<Mutex<RoutingTable>>,
    addr: SocketAddr,
) {
    let IpAddr::V4(ip) = addr.ip() else {
        return;
    };
    let mut routing_table = routing_table.lock().await;
    let contact_id = routing_table
        .all_contacts()
        .into_iter()
        .find(|contact| contact.ip == ip && contact.udp_port == addr.port())
        .map(|contact| contact.id);
    if let Some(contact_id) = contact_id {
        let _ = routing_table.remove(&contact_id);
        warn!(
            "expired routing contact after massive Kad request flood from {}",
            addr
        );
    }
}

pub(super) fn bootstrap_ready_with_contacts(
    min_ready_contacts: usize,
    routing_contacts: usize,
) -> bool {
    routing_contacts >= min_ready_contacts.max(1)
}

#[cfg(test)]
mod tests {
    use super::bootstrap_ready_with_contacts;

    #[test]
    fn bootstrap_log_messages_are_ascii_only() {
        assert!(
            "bootstrap response from {addr} - routing table now {contacts} contacts".is_ascii()
        );
        assert!("bootstrap complete - routing table has {contacts} contacts".is_ascii());
    }

    #[test]
    fn bootstrap_ready_threshold_is_never_zero() {
        assert!(bootstrap_ready_with_contacts(0, 1));
        assert!(!bootstrap_ready_with_contacts(0, 0));
    }

    #[test]
    fn bootstrap_ready_threshold_honors_configured_contact_floor() {
        assert!(!bootstrap_ready_with_contacts(3, 2));
        assert!(bootstrap_ready_with_contacts(3, 3));
    }
}
