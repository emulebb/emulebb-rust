//! Test-only egress-audit recorder for the RUST-FEAT-005 dynamic leak test.
//!
//! When the `egress-audit` cargo feature is on, [`record`] captures — for every
//! P2P socket that passes through [`super::pin_egress_to_interface`] — its bound
//! local address, its transport (TCP/UDP), and the interface index it was pinned
//! to (`None` when no pin was applied). A process-global recorder lets the leak
//! test OBSERVE, at the socket layer, that no P2P socket is ever bound or pinned
//! off the tunnel (and that when the tunnel is down, no P2P socket opens at all).
//!
//! This is portable (no packet capture, no privileged netns), deterministic, and
//! never present in a release build: [`record`] is an inlined no-op unless the
//! feature is enabled, and `tools/check_rust_client_policy.py` rejects the
//! feature appearing in the daemon/default feature set.

#[cfg(feature = "egress-audit")]
pub use enabled::{EgressProto, EgressRecord, record, reset, snapshot};

/// No-op when the feature is off: zero cost, and the P2P socket paths need no
/// conditional compilation at the call site.
#[cfg(not(feature = "egress-audit"))]
#[inline(always)]
pub fn record(_sock: &socket2::SockRef<'_>, _pinned_if_index: Option<u32>) {}

#[cfg(feature = "egress-audit")]
mod enabled {
    use std::net::SocketAddr;
    use std::sync::{Mutex, OnceLock};

    use socket2::SockRef;

    /// Transport of an audited P2P socket.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EgressProto {
        Tcp,
        Udp,
        Other,
    }

    /// One observed P2P socket: where it is bound and what interface its egress
    /// was pinned to.
    #[derive(Debug, Clone)]
    pub struct EgressRecord {
        pub proto: EgressProto,
        pub local: Option<SocketAddr>,
        /// The interface index egress was pinned to, or `None` when no pin was
        /// applied (a potential leak the test flags).
        pub pinned_if_index: Option<u32>,
    }

    fn recorder() -> &'static Mutex<Vec<EgressRecord>> {
        static RECORDER: OnceLock<Mutex<Vec<EgressRecord>>> = OnceLock::new();
        RECORDER.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn lock() -> std::sync::MutexGuard<'static, Vec<EgressRecord>> {
        recorder()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record one P2P socket's bind + pin. Called at the single socket chokepoint
    /// so every eD2K TCP / Kad UDP / STUN / firewall-probe socket is captured.
    pub fn record(sock: &SockRef<'_>, pinned_if_index: Option<u32>) {
        let proto = match sock.r#type() {
            Ok(socket2::Type::STREAM) => EgressProto::Tcp,
            Ok(socket2::Type::DGRAM) => EgressProto::Udp,
            _ => EgressProto::Other,
        };
        let local = sock.local_addr().ok().and_then(|addr| addr.as_socket());
        lock().push(EgressRecord {
            proto,
            local,
            pinned_if_index,
        });
    }

    /// Snapshot of every P2P socket recorded since the last [`reset`].
    #[must_use]
    pub fn snapshot() -> Vec<EgressRecord> {
        lock().clone()
    }

    /// Clear the recorder (call at the start of each leak-test scenario).
    pub fn reset() {
        lock().clear();
    }
}
