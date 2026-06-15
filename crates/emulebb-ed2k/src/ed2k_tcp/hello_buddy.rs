//! Process-wide buddy hello snapshot, the Rust analogue of the oracle
//! `BuddyHelloSnapshot` (`BaseClientFriendBuddySeams.h`) built from
//! `theApp.clientlist->GetBuddy()` while serializing the hello tag set.

use std::net::Ipv4Addr;
use std::sync::Mutex;

/// Buddy endpoint a firewalled client advertises in its hello so peers can reach
/// it through the buddy's UDP callback relay (`buddySnapshot.dwBuddyIP` /
/// `nBuddyPort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloBuddySnapshot {
    /// Buddy IPv4 address (eMule `CUpDownClient::GetIP()`).
    pub ip: Ipv4Addr,
    /// Buddy UDP port (eMule `CUpDownClient::GetUDPPort()`).
    pub udp_port: u16,
}

/// Process-wide buddy hello snapshot, mirroring the oracle `BuddyHelloSnapshot`
/// built from `theApp.clientlist->GetBuddy()` at hello-serialize time. `Some`
/// only while we are firewalled AND hold an outgoing buddy: core sets it when a
/// Kad buddy is acquired and clears it when the buddy is dropped (which it does
/// as soon as we are no longer firewalled), so its presence is exactly the
/// oracle `bShouldAdvertise = IsFirewalled() && hasBuddy`.
static HELLO_BUDDY_SNAPSHOT: Mutex<Option<HelloBuddySnapshot>> = Mutex::new(None);

/// Publish (or clear with `None`) the buddy endpoint advertised in subsequent
/// hellos. Called by core from the Kad buddy subsystem when the outgoing buddy
/// is acquired or released.
pub fn set_hello_buddy_snapshot(snapshot: Option<HelloBuddySnapshot>) {
    *HELLO_BUDDY_SNAPSHOT
        .lock()
        .expect("hello buddy snapshot mutex poisoned") = snapshot;
}

/// Read the current buddy hello snapshot for the hello tag builder.
pub(super) fn hello_buddy_snapshot() -> Option<HelloBuddySnapshot> {
    *HELLO_BUDDY_SNAPSHOT
        .lock()
        .expect("hello buddy snapshot mutex poisoned")
}
