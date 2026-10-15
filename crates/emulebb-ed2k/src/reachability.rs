//! `ExternalReachability` — the single per-instance source of truth for how this
//! client is reachable from the outside: our public IPv4 and the externally-mapped
//! eD2k TCP + UDP ports. Read at send time by every hello/login-encode site, so a
//! value learned after startup (server `OP_IDCHANGE`, a STUN probe, a UPnP mapping
//! appearing or being remapped on lease renewal) is reflected in subsequent
//! advertisements without snapshotting it at startup.
//!
//! This consolidates the previously-scattered state (`SharedPublicIp` + the
//! process-wide advertised-port statics) that let the reask/HighID reachability
//! bugs slip in: a site could advertise an internal/stale value while the truth
//! lived elsewhere. One cheaply-clonable `Arc` cell, threaded where needed, owns
//! an atomically replaced state value so readers can take a coherent snapshot.
//!
//! Semantics mirror eMule:
//! - **Public IP** (`Emule.cpp` `GetPublicIP`/`SetPublicIP`): the obfuscation key
//!   material for client UDP (`EncryptSendClient`). Server and fallback probes
//!   own independent evidence slots; the server slot wins while present and can
//!   be invalidated without erasing a concurrently refreshed STUN/Kad value.
//! - **Ports**: a NAT/UPnP gateway may grant external ports different from the
//!   internal sockets; advertise the external port so peers/servers can reach us
//!   for incoming TCP + HighID callback (TCP) and locate us for UDP source-reask
//!   by `(ip, udp_port)` (UDP). [`advertised_tcp_port`]/[`advertised_udp_port`]
//!   return the learned external port when known, else the given internal port.

use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::RwLock;

/// Immutable point-in-time view of all external reachability evidence.
///
/// Copy this once when one protocol message depends on more than one field. The
/// copy remains stable even if another task publishes a newer state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReachabilitySnapshot {
    server_public_ip: Option<Ipv4Addr>,
    fallback_public_ip: Option<Ipv4Addr>,
    nat_mapped_tcp_port: Option<u16>,
    nat_mapped_udp_port: Option<u16>,
    /// Kept separately so expiring stale peer verification reveals, rather than
    /// destroys, a concurrently refreshed NAT mapping.
    peer_confirmed_udp_port: Option<u16>,
}

/// Effective external ports derived from one [`ReachabilitySnapshot`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvertisedPorts {
    pub tcp: u16,
    pub udp: u16,
}

impl ReachabilitySnapshot {
    /// Current public IPv4, preferring live server evidence over fallback probes.
    pub fn public_ip(self) -> Option<Ipv4Addr> {
        self.server_public_ip.or(self.fallback_public_ip)
    }

    /// Octets `a.b.c.d` for obfuscation key material; `[0,0,0,0]` when unknown.
    pub fn octets(self) -> [u8; 4] {
        self.public_ip().map_or([0, 0, 0, 0], |ip| ip.octets())
    }

    /// Whether a public IP is known (HighID established).
    pub fn is_known(self) -> bool {
        self.public_ip().is_some()
    }

    /// Whether the external UDP port has been confirmed by a remote peer.
    pub fn udp_port_is_peer_confirmed(self) -> bool {
        self.peer_confirmed_udp_port.is_some()
    }

    /// The eD2k TCP port to advertise: the learned external port when known, else
    /// the given internal socket port (hello `tcp_port` / server login port).
    pub fn advertised_tcp_port(self, internal_port: u16) -> u16 {
        self.nat_mapped_tcp_port.unwrap_or(internal_port)
    }

    /// The eD2k UDP port to advertise: the learned external port when known, else
    /// the given internal socket port (`CT_EMULE_UDPPORTS` / `ET_UDPPORT`).
    pub fn advertised_udp_port(self, internal_port: u16) -> u16 {
        self.peer_confirmed_udp_port
            .or(self.nat_mapped_udp_port)
            .unwrap_or(internal_port)
    }

    /// Derive both advertised ports from this one point-in-time view.
    pub fn advertised_ports(
        self,
        internal_tcp_port: u16,
        internal_udp_port: u16,
    ) -> AdvertisedPorts {
        AdvertisedPorts {
            tcp: self.advertised_tcp_port(internal_tcp_port),
            udp: self.advertised_udp_port(internal_udp_port),
        }
    }
}

/// Cheaply-clonable handle to this client's external reachability facts.
#[derive(Clone, Debug)]
pub struct ExternalReachability {
    inner: Arc<RwLock<ReachabilityState>>,
}

/// Root capability that creates runtime-scoped publication generations.
///
/// Keep this authority with the lifecycle owner. Data-plane consumers should
/// receive only [`ExternalReachability`] readers or generation-fenced writers.
#[derive(Debug, Default)]
pub struct ReachabilityRuntimeAuthority {
    inner: Arc<RwLock<ReachabilityState>>,
}

#[derive(Default, Debug)]
struct ReachabilityState {
    snapshot: ReachabilitySnapshot,
    active_runtime_generation: Option<u64>,
    active_server_generation: Option<u64>,
    next_runtime_generation: u64,
    next_server_generation: u64,
}

/// Outcome of a generation-fenced reachability mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReachabilityUpdate {
    Changed,
    Unchanged,
    RejectedStale,
}

/// Non-clonable ownership token for one installed network runtime.
#[derive(Debug)]
pub struct ReachabilityRuntimeLease {
    inner: Arc<RwLock<ReachabilityState>>,
    generation: Option<u64>,
}

/// Cloneable, generation-fenced writer for runtime-level NAT, STUN, and Kad facts.
#[derive(Clone, Debug)]
pub struct RuntimeReachabilityWriter {
    inner: Arc<RwLock<ReachabilityState>>,
    runtime_generation: u64,
}

/// Non-clonable ownership token for one pending or active server session.
#[derive(Debug)]
pub struct ServerReachabilityLease {
    inner: Arc<RwLock<ReachabilityState>>,
    runtime_generation: u64,
    server_generation: Option<u64>,
}

/// Cloneable writer that can publish only while its server session is active.
#[derive(Clone, Debug)]
pub struct ServerReachabilityWriter {
    inner: Arc<RwLock<ReachabilityState>>,
    runtime_generation: u64,
    server_generation: u64,
}

impl ExternalReachability {
    /// Copy one coherent point-in-time view of every reachability fact.
    pub fn snapshot(&self) -> ReachabilitySnapshot {
        self.inner.read().snapshot
    }

    /// Current public IPv4, preferring live server evidence over fallback probes.
    pub fn get(&self) -> Option<Ipv4Addr> {
        self.snapshot().public_ip()
    }

    /// Octets `a.b.c.d` for obfuscation key material; `[0,0,0,0]` when unknown.
    pub fn octets(&self) -> [u8; 4] {
        self.snapshot().octets()
    }

    /// Whether a public IP is known (HighID established).
    pub fn is_known(&self) -> bool {
        self.snapshot().is_known()
    }

    /// Whether the external UDP port has been confirmed by a remote peer.
    #[must_use]
    pub fn udp_port_is_peer_confirmed(&self) -> bool {
        self.snapshot().udp_port_is_peer_confirmed()
    }

    /// The eD2k TCP port to advertise: the learned external port when known, else
    /// the given internal socket port (hello `tcp_port` / server login port).
    pub fn advertised_tcp_port(&self, internal_port: u16) -> u16 {
        self.snapshot().advertised_tcp_port(internal_port)
    }

    /// The eD2k UDP port to advertise: the learned external port when known, else
    /// the given internal socket port (`CT_EMULE_UDPPORTS` / `ET_UDPPORT`).
    pub fn advertised_udp_port(&self, internal_port: u16) -> u16 {
        self.snapshot().advertised_udp_port(internal_port)
    }
}

impl ReachabilityRuntimeAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a read-only handle for data-plane consumers.
    pub fn reader(&self) -> ExternalReachability {
        ExternalReachability {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Starts a fresh ownership generation and atomically revokes older facts.
    pub fn begin_runtime(&self) -> ReachabilityRuntimeLease {
        let mut state = self.inner.write();
        state.next_runtime_generation = state
            .next_runtime_generation
            .checked_add(1)
            .expect("reachability runtime generation exhausted");
        let generation = state.next_runtime_generation;
        state.active_runtime_generation = Some(generation);
        state.active_server_generation = None;
        state.snapshot = ReachabilitySnapshot::default();
        ReachabilityRuntimeLease {
            inner: Arc::clone(&self.inner),
            generation: Some(generation),
        }
    }
}

impl ReachabilityRuntimeLease {
    /// Issues a cloneable writer bound to this runtime generation.
    pub fn writer(&self) -> RuntimeReachabilityWriter {
        RuntimeReachabilityWriter {
            inner: Arc::clone(&self.inner),
            runtime_generation: self
                .generation
                .expect("retired reachability runtime lease cannot issue writers"),
        }
    }

    /// Invalidates this runtime before its tasks begin retirement.
    pub fn retire(&mut self) -> ReachabilityUpdate {
        let Some(generation) = self.generation.take() else {
            return ReachabilityUpdate::Unchanged;
        };
        let mut state = self.inner.write();
        if state.active_runtime_generation != Some(generation) {
            return ReachabilityUpdate::RejectedStale;
        }
        let changed = state.snapshot != ReachabilitySnapshot::default();
        state.active_runtime_generation = None;
        state.active_server_generation = None;
        state.snapshot = ReachabilitySnapshot::default();
        update_outcome(changed)
    }
}

impl Drop for ReachabilityRuntimeLease {
    fn drop(&mut self) {
        self.retire();
    }
}

impl RuntimeReachabilityWriter {
    /// Allocates a pending server generation owned by this runtime.
    pub fn begin_server_session(&self) -> Option<ServerReachabilityLease> {
        let mut state = self.inner.write();
        if state.active_runtime_generation != Some(self.runtime_generation) {
            return None;
        }
        state.next_server_generation = state
            .next_server_generation
            .checked_add(1)
            .expect("reachability server generation exhausted");
        Some(ServerReachabilityLease {
            inner: Arc::clone(&self.inner),
            runtime_generation: self.runtime_generation,
            server_generation: Some(state.next_server_generation),
        })
    }

    pub fn set_fallback_public_ip(&self, ip: Ipv4Addr) -> ReachabilityUpdate {
        self.update(|snapshot| snapshot.fallback_public_ip = Some(ip))
    }

    pub fn set_nat_mapped_ports(
        &self,
        tcp_port: Option<u16>,
        udp_port: Option<u16>,
    ) -> ReachabilityUpdate {
        self.update(|snapshot| {
            snapshot.nat_mapped_tcp_port = nonzero_port(tcp_port);
            snapshot.nat_mapped_udp_port = nonzero_port(udp_port);
        })
    }

    pub fn set_peer_confirmed_udp_port(&self, port: u16) -> ReachabilityUpdate {
        self.update(|snapshot| {
            if let Some(port) = nonzero_port(Some(port)) {
                snapshot.peer_confirmed_udp_port = Some(port);
            }
        })
    }

    pub fn clear_peer_confirmed_udp_port(&self) -> ReachabilityUpdate {
        self.update(|snapshot| snapshot.peer_confirmed_udp_port = None)
    }

    fn update(&self, apply: impl FnOnce(&mut ReachabilitySnapshot)) -> ReachabilityUpdate {
        let mut state = self.inner.write();
        if state.active_runtime_generation != Some(self.runtime_generation) {
            return ReachabilityUpdate::RejectedStale;
        }
        let before = state.snapshot;
        apply(&mut state.snapshot);
        update_outcome(state.snapshot != before)
    }
}

impl ServerReachabilityLease {
    /// Issues the writer carried by this server attempt.
    pub fn writer(&self) -> ServerReachabilityWriter {
        ServerReachabilityWriter {
            inner: Arc::clone(&self.inner),
            runtime_generation: self.runtime_generation,
            server_generation: self
                .server_generation
                .expect("retired server reachability lease cannot issue writers"),
        }
    }

    /// Activates this session and atomically revokes prior server evidence.
    pub fn activate(&mut self) -> ReachabilityUpdate {
        let Some(server_generation) = self.server_generation else {
            return ReachabilityUpdate::RejectedStale;
        };
        let mut state = self.inner.write();
        if state.active_runtime_generation != Some(self.runtime_generation) {
            return ReachabilityUpdate::RejectedStale;
        }
        let changed = state.active_server_generation != Some(server_generation)
            || state.snapshot.server_public_ip.is_some();
        state.active_server_generation = Some(server_generation);
        state.snapshot.server_public_ip = None;
        update_outcome(changed)
    }

    /// Retires this session without disturbing a newer active generation.
    pub fn retire(&mut self) -> ReachabilityUpdate {
        let Some(server_generation) = self.server_generation.take() else {
            return ReachabilityUpdate::Unchanged;
        };
        let mut state = self.inner.write();
        if state.active_runtime_generation != Some(self.runtime_generation)
            || state.active_server_generation != Some(server_generation)
        {
            return ReachabilityUpdate::RejectedStale;
        }
        let changed = state.snapshot.server_public_ip.take().is_some();
        state.active_server_generation = None;
        update_outcome(changed)
    }
}

impl Drop for ServerReachabilityLease {
    fn drop(&mut self) {
        self.retire();
    }
}

impl ServerReachabilityWriter {
    pub fn set_server_public_ip(&self, ip: Ipv4Addr) -> ReachabilityUpdate {
        self.update(|snapshot| snapshot.server_public_ip = Some(ip))
    }

    pub fn clear_server_public_ip(&self) -> ReachabilityUpdate {
        self.update(|snapshot| snapshot.server_public_ip = None)
    }

    fn update(&self, apply: impl FnOnce(&mut ReachabilitySnapshot)) -> ReachabilityUpdate {
        let mut state = self.inner.write();
        if state.active_runtime_generation != Some(self.runtime_generation)
            || state.active_server_generation != Some(self.server_generation)
        {
            return ReachabilityUpdate::RejectedStale;
        }
        let before = state.snapshot;
        apply(&mut state.snapshot);
        update_outcome(state.snapshot != before)
    }
}

fn update_outcome(changed: bool) -> ReachabilityUpdate {
    if changed {
        ReachabilityUpdate::Changed
    } else {
        ReachabilityUpdate::Unchanged
    }
}

fn nonzero_port(port: Option<u16>) -> Option<u16> {
    port.filter(|port| *port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachability_fixture() -> (ReachabilityRuntimeAuthority, ExternalReachability) {
        let authority = ReachabilityRuntimeAuthority::new();
        let reachability = authority.reader();
        (authority, reachability)
    }

    fn runtime_writer(
        authority: &ReachabilityRuntimeAuthority,
    ) -> (ReachabilityRuntimeLease, RuntimeReachabilityWriter) {
        let lease = authority.begin_runtime();
        let writer = lease.writer();
        (lease, writer)
    }

    fn active_server_writer(
        runtime_writer: &RuntimeReachabilityWriter,
    ) -> (ServerReachabilityLease, ServerReachabilityWriter) {
        let mut lease = runtime_writer.begin_server_session().unwrap();
        assert_eq!(lease.activate(), ReachabilityUpdate::Changed);
        let writer = lease.writer();
        (lease, writer)
    }

    #[test]
    fn public_ip_unknown_before_runtime_publication() {
        let r = ReachabilityRuntimeAuthority::new().reader();
        assert!(!r.is_known());
        assert_eq!(r.get(), None);
        assert_eq!(r.octets(), [0, 0, 0, 0]);
    }

    #[test]
    fn server_evidence_overrides_independently_refreshed_fallback() {
        let (authority, r) = reachability_fixture();
        let (_runtime, runtime_writer) = runtime_writer(&authority);
        assert_eq!(
            runtime_writer.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 1)),
            ReachabilityUpdate::Changed
        );
        assert_eq!(
            runtime_writer.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 1)),
            ReachabilityUpdate::Unchanged
        );
        assert_eq!(r.get(), Some(Ipv4Addr::new(198, 51, 100, 1)));
        let (mut server, server_writer) = active_server_writer(&runtime_writer);
        server_writer.set_server_public_ip(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(r.octets(), [203, 0, 113, 9]);
        runtime_writer.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(r.octets(), [203, 0, 113, 9]);
        assert_eq!(server.retire(), ReachabilityUpdate::Changed);
        assert_eq!(r.get(), Some(Ipv4Addr::new(198, 51, 100, 2)));
        assert_eq!(server.retire(), ReachabilityUpdate::Unchanged);
    }

    #[test]
    fn ports_fall_back_to_internal_until_learned() {
        let (authority, r) = reachability_fixture();
        let (_runtime, writer) = runtime_writer(&authority);
        assert_eq!(r.advertised_tcp_port(4662), 4662);
        assert_eq!(r.advertised_udp_port(4672), 4672);
        writer.set_nat_mapped_ports(Some(45000), Some(51000));
        assert_eq!(r.advertised_tcp_port(4662), 45000);
        assert_eq!(r.advertised_udp_port(4672), 51000);
        writer.set_nat_mapped_ports(Some(45000), None);
        assert_eq!(r.advertised_udp_port(4672), 4672);
    }

    #[test]
    fn peer_confirmed_udp_port_takes_precedence_over_upnp() {
        let (authority, r) = reachability_fixture();
        let (_runtime, writer) = runtime_writer(&authority);
        // UPnP-derived value applies while no peer confirmation is in force.
        writer.set_nat_mapped_ports(None, Some(45000));
        assert_eq!(r.advertised_udp_port(4672), 45000);
        assert!(!r.udp_port_is_peer_confirmed());
        // A peer-confirmed port pins the value.
        writer.set_peer_confirmed_udp_port(51000);
        assert!(r.udp_port_is_peer_confirmed());
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // Subsequent UPnP syncs are retained but cannot supersede it.
        writer.set_nat_mapped_ports(None, Some(46000));
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // A zero peer confirmation is a no-op.
        writer.set_peer_confirmed_udp_port(0);
        assert_eq!(r.advertised_udp_port(4672), 51000);
        // Expiring the peer evidence reveals the latest UPnP mapping.
        assert_eq!(
            writer.clear_peer_confirmed_udp_port(),
            ReachabilityUpdate::Changed
        );
        assert!(!r.udp_port_is_peer_confirmed());
        assert_eq!(r.advertised_udp_port(4672), 46000);
        assert_eq!(
            writer.clear_peer_confirmed_udp_port(),
            ReachabilityUpdate::Unchanged
        );
    }

    #[test]
    fn runtime_retirement_revokes_every_owned_fact() {
        let (authority, r) = reachability_fixture();
        let (mut runtime, runtime_writer) = runtime_writer(&authority);
        let (_server, server_writer) = active_server_writer(&runtime_writer);
        server_writer.set_server_public_ip(Ipv4Addr::new(203, 0, 113, 9));
        runtime_writer.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 2));
        runtime_writer.set_nat_mapped_ports(Some(45000), Some(46000));
        runtime_writer.set_peer_confirmed_udp_port(51000);

        assert_eq!(runtime.retire(), ReachabilityUpdate::Changed);

        assert_eq!(r.get(), None);
        assert_eq!(r.advertised_tcp_port(4662), 4662);
        assert_eq!(r.advertised_udp_port(4672), 4672);
        assert!(!r.udp_port_is_peer_confirmed());
    }

    #[test]
    fn clones_share_one_cell() {
        let (authority, a) = reachability_fixture();
        let b = a.clone();
        let (_runtime, runtime_writer) = runtime_writer(&authority);
        let (_server, server_writer) = active_server_writer(&runtime_writer);
        server_writer.set_server_public_ip(Ipv4Addr::new(192, 0, 2, 5));
        runtime_writer.set_nat_mapped_ports(None, Some(40000));
        assert_eq!(b.get(), Some(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(b.advertised_udp_port(4672), 40000);
    }

    #[test]
    fn snapshots_remain_stable_after_new_evidence_is_published() {
        let (authority, reachability) = reachability_fixture();
        let (_runtime, runtime_writer) = runtime_writer(&authority);
        runtime_writer.set_fallback_public_ip(Ipv4Addr::new(192, 0, 2, 5));
        runtime_writer.set_nat_mapped_ports(Some(45000), Some(46000));
        let before = reachability.snapshot();

        let (_server, server_writer) = active_server_writer(&runtime_writer);
        server_writer.set_server_public_ip(Ipv4Addr::new(198, 51, 100, 9));
        runtime_writer.set_nat_mapped_ports(Some(55000), Some(56000));

        assert_eq!(before.public_ip(), Some(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(before.advertised_tcp_port(4662), 45000);
        assert_eq!(before.advertised_udp_port(4672), 46000);
        let after = reachability.snapshot();
        assert_eq!(after.public_ip(), Some(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(after.advertised_tcp_port(4662), 55000);
        assert_eq!(after.advertised_udp_port(4672), 56000);
    }

    #[test]
    fn advertised_port_pairs_come_from_one_snapshot() {
        let (authority, reachability) = reachability_fixture();
        let (_runtime, writer) = runtime_writer(&authority);
        writer.set_nat_mapped_ports(Some(45000), Some(46000));
        let before = reachability.snapshot();

        writer.set_nat_mapped_ports(Some(55000), None);

        assert_eq!(
            before.advertised_ports(4662, 4672),
            AdvertisedPorts {
                tcp: 45000,
                udp: 46000,
            }
        );
        assert_eq!(
            reachability.snapshot().advertised_ports(4662, 4672),
            AdvertisedPorts {
                tcp: 55000,
                udp: 4672,
            }
        );
    }

    #[test]
    fn retired_runtime_writer_cannot_mutate_or_clear_new_generation() {
        let (authority, reachability) = reachability_fixture();
        let first_lease = authority.begin_runtime();
        let first_writer = first_lease.writer();
        assert_eq!(
            first_writer.set_fallback_public_ip(Ipv4Addr::new(192, 0, 2, 1)),
            ReachabilityUpdate::Changed
        );

        let mut second_lease = authority.begin_runtime();
        let second_writer = second_lease.writer();
        assert_eq!(
            second_writer.set_nat_mapped_ports(Some(45_000), Some(46_000)),
            ReachabilityUpdate::Changed
        );
        assert_eq!(
            first_writer.set_fallback_public_ip(Ipv4Addr::new(192, 0, 2, 2)),
            ReachabilityUpdate::RejectedStale
        );
        assert_eq!(
            first_writer.clear_peer_confirmed_udp_port(),
            ReachabilityUpdate::RejectedStale
        );

        drop(first_lease);
        assert_eq!(reachability.advertised_tcp_port(4662), 45_000);
        assert_eq!(reachability.advertised_udp_port(4672), 46_000);
        assert_eq!(second_lease.retire(), ReachabilityUpdate::Changed);
        assert_eq!(reachability.snapshot(), ReachabilitySnapshot::default());
    }

    #[test]
    fn stale_server_writer_cannot_overwrite_or_clear_new_session() {
        let (authority, reachability) = reachability_fixture();
        let runtime_lease = authority.begin_runtime();
        let runtime_writer = runtime_lease.writer();
        let mut first_server = runtime_writer.begin_server_session().unwrap();
        let first_writer = first_server.writer();
        assert_eq!(
            first_writer.set_server_public_ip(Ipv4Addr::new(192, 0, 2, 1)),
            ReachabilityUpdate::RejectedStale
        );
        assert_eq!(first_server.activate(), ReachabilityUpdate::Changed);
        assert_eq!(
            first_writer.set_server_public_ip(Ipv4Addr::new(192, 0, 2, 1)),
            ReachabilityUpdate::Changed
        );

        let mut second_server = runtime_writer.begin_server_session().unwrap();
        let second_writer = second_server.writer();
        assert_eq!(second_server.activate(), ReachabilityUpdate::Changed);
        assert_eq!(
            second_writer.set_server_public_ip(Ipv4Addr::new(198, 51, 100, 2)),
            ReachabilityUpdate::Changed
        );
        assert_eq!(
            first_writer.set_server_public_ip(Ipv4Addr::new(203, 0, 113, 3)),
            ReachabilityUpdate::RejectedStale
        );
        assert_eq!(
            first_writer.clear_server_public_ip(),
            ReachabilityUpdate::RejectedStale
        );
        assert_eq!(first_server.retire(), ReachabilityUpdate::RejectedStale);
        assert_eq!(reachability.get(), Some(Ipv4Addr::new(198, 51, 100, 2)));

        drop(second_server);
        assert_eq!(reachability.get(), None);
    }
}
