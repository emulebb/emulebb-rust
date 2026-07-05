//! eMule-style low-level socket parameters for the P2P data-plane sockets,
//! shared by the Kad UDP transport here and the eD2k TCP sockets (via re-export).
//!
//! Mirrors eMuleBB's Windows socket setup:
//! - **`IP_UNICAST_IF` egress pinning** to the VPN/tunnel interface
//!   (eMule `ApplyConfiguredIpv4UnicastInterface` / `BindInterfaceSocketSeams`),
//!   so split-tunnel routing cannot leak P2P traffic onto the LAN — applied via
//!   socket2's `bind_device_by_index_v4` (portable; Windows uses `IP_UNICAST_IF`).
//! - **Enlarged UDP receive buffer** (eMule `kBroadbandUdpReceiveBufferBytes`)
//!   so bursts of UDP packets are not dropped.

use std::io;
use std::num::NonZeroU32;

use socket2::SockRef;

pub mod egress_audit;

/// 1 MiB UDP receive buffer, matching eMule's `kBroadbandUdpReceiveBufferBytes`
/// (the OS default is too small and drops bursts of inbound UDP packets).
pub const P2P_UDP_RECV_BUFFER_BYTES: usize = 1024 * 1024;

/// Pin a socket's IPv4 egress to `if_index` (`IP_UNICAST_IF`). This is the solid
/// VPN-binding guarantee: even with the OS routing table preferring the LAN,
/// outbound P2P packets leave via the tunnel interface. Returns an error if the
/// option cannot be applied (callers under VPN-guard enforcement should fail
/// closed rather than risk a leak). A `None`/zero index is a no-op (no tunnel
/// interface resolved → plain bind).
///
/// socket2 only implements `bind_device_by_index_v4` on Unix, so on Windows we
/// issue the raw `setsockopt(IPPROTO_IP, IP_UNICAST_IF, htonl(index))` exactly as
/// eMuleBB does (`BindInterfaceSocketSeams::ApplyIpv4UnicastInterfaceOption`).
#[cfg(windows)]
pub fn pin_egress_to_interface(sock: SockRef<'_>, if_index: Option<u32>) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, setsockopt};

    let applied = match if_index.and_then(NonZeroU32::new) {
        None => None,
        Some(index) => {
            // IP_UNICAST_IF takes the interface index in network byte order.
            let net_index = index.get().to_be();
            let raw = sock.as_raw_socket() as usize;
            let ret = unsafe {
                setsockopt(
                    raw,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    (&raw const net_index).cast::<u8>(),
                    size_of::<u32>() as i32,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            Some(index.get())
        }
    };
    egress_audit::record(&sock, applied);
    Ok(())
}

#[cfg(not(windows))]
pub fn pin_egress_to_interface(sock: SockRef<'_>, if_index: Option<u32>) -> io::Result<()> {
    let applied = match if_index.and_then(NonZeroU32::new) {
        None => None,
        Some(index) => {
            sock.bind_device_by_index_v4(Some(index))?;
            Some(index.get())
        }
    };
    egress_audit::record(&sock, applied);
    Ok(())
}

/// Apply eMule's P2P socket parameters: egress-pin to the tunnel interface (when
/// `if_index` is known) and, for UDP, enlarge the receive buffer. The receive
/// buffer is best-effort (eMule logs + continues if the OS clamps it); egress
/// pinning propagates its error so the caller can fail closed.
pub fn apply_p2p_socket_options(
    sock: SockRef<'_>,
    if_index: Option<u32>,
    udp: bool,
) -> io::Result<()> {
    if udp {
        // Best-effort, like eMule (warn + continue if Windows clamps it).
        let _ = sock.set_recv_buffer_size(P2P_UDP_RECV_BUFFER_BYTES);
    }
    pin_egress_to_interface(sock, if_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};

    // LAN test binds use X_LOCAL_IP, never loopback (the VPN split tunnel breaks
    // 127.0.0.1 -> os error 10049). CI exports X_LOCAL_IP=127.0.0.1.
    fn test_bind_ip() -> Ipv4Addr {
        std::env::var("X_LOCAL_IP")
            .expect("X_LOCAL_IP must be set for socket-binding tests (loopback is broken here)")
            .parse()
            .expect("X_LOCAL_IP must be an IPv4 address")
    }

    #[test]
    fn udp_options_enlarge_recv_buffer_and_no_pin_is_noop() {
        let sock = UdpSocket::bind((test_bind_ip(), 0)).expect("bind udp");
        let sref = SockRef::from(&sock);
        // None index => egress pinning is a no-op (plain bind), still Ok.
        apply_p2p_socket_options(sref, None, true).expect("apply udp options");
        let sref = SockRef::from(&sock);
        let applied = sref.recv_buffer_size().expect("read recv buffer");
        // The OS typically grants >= requested (often doubled); never less than a
        // healthy floor well above the tiny default.
        assert!(
            applied >= 256 * 1024,
            "recv buffer should be enlarged, got {applied}"
        );
    }

    #[test]
    fn pin_to_zero_or_none_index_is_noop() {
        let sock = UdpSocket::bind((test_bind_ip(), 0)).expect("bind udp");
        pin_egress_to_interface(SockRef::from(&sock), None).expect("none is noop");
        pin_egress_to_interface(SockRef::from(&sock), Some(0)).expect("zero is noop");
    }
}
