//! RFC 5389 STUN Binding probe for active UDP egress verification.
//!
//! This mirrors the libtorrent fork's `aux::stun_probe` (`src/stun.cpp`): it
//! sends a single STUN Binding Request to a public STUN server over UDP and
//! reports the reflexive (server-observed, public) address from the response's
//! `XOR-MAPPED-ADDRESS` attribute.
//!
//! The point is leak detection that the TCP/HTTP public-IP path cannot give:
//! the probe socket is egress-pinned to the same interface as the eD2k/Kad data
//! plane (`IP_UNICAST_IF`, via [`pin_egress_to_interface`]), so the reflexive
//! address reflects the *actual* UDP egress (e.g. the VPN tunnel). A probe bound
//! to an unspecified address (`0.0.0.0`) takes the OS default route — useful as
//! a "clear" baseline to compare against the pinned probe.
//!
//! IPv4-only, matching the rest of emulebb-rust (IPv6 is deferred). This is a
//! standalone primitive; it is not yet wired into a periodic loop (neither is the
//! libtorrent counterpart).
//!
//! [`pin_egress_to_interface`]: emulebb_kad_dht::socket_opts::pin_egress_to_interface

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rand::RngCore;
use tokio::net::UdpSocket;

use crate::networking::resolve_bind_if_index;

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_FAMILY_IPV4: u8 = 0x01;
const STUN_HEADER_LEN: usize = 20;

/// Default probe timeout, matching libtorrent's `stun_probe` (5 seconds).
pub const DEFAULT_STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// Send one STUN Binding Request to `server` from a socket bound to `bind_ip`
/// and return the reflexive public IPv4 the server observed.
///
/// `bind_ip` should be the resolved data-plane bind address (the VPN tunnel IP)
/// so the probe is egress-pinned exactly like the eD2k/Kad sockets; pass an
/// unspecified address (`0.0.0.0`) for a default-route baseline probe. The
/// egress pin is a no-op when `bind_ip` does not resolve to a local interface
/// index (which includes the unspecified address).
///
/// Returns an error on bind/send failure, on timeout, or if the response is not
/// a valid STUN Binding Success carrying an IPv4 mapped address.
pub async fn stun_probe(
    server: SocketAddrV4,
    bind_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<Ipv4Addr> {
    let mut txid = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut txid);
    let request = build_request(&txid);

    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .await
        .with_context(|| format!("failed to bind STUN probe socket on {bind_ip}"))?;
    // Egress-pin to the tunnel interface (IP_UNICAST_IF) so the reflexive address
    // reflects the real UDP egress — solid VPN binding, identical to the eD2k/Kad
    // data-plane sockets. No-op for an unspecified/default-route bind.
    emulebb_kad_dht::socket_opts::pin_egress_to_interface(
        socket2::SockRef::from(&socket),
        resolve_bind_if_index(bind_ip),
    )
    .with_context(|| format!("failed to pin STUN probe egress for {bind_ip}"))?;

    socket
        .send_to(&request, server)
        .await
        .with_context(|| format!("failed to send STUN binding request to {server}"))?;

    let mut buf = [0u8; 1500];
    let received = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .with_context(|| format!("STUN binding request to {server} timed out"))?;
    let (len, _from) = received
        .with_context(|| format!("failed to receive STUN response from {server}"))?;

    parse_response(&buf[..len], &txid)
        .with_context(|| format!("invalid STUN binding response from {server}"))
}

/// Build the 20-byte STUN Binding Request: type, zero length, magic cookie, and
/// the 96-bit transaction id (no attributes).
fn build_request(txid: &[u8; 12]) -> [u8; STUN_HEADER_LEN] {
    let mut req = [0u8; STUN_HEADER_LEN];
    req[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // bytes 2..4 (message length) stay 0 — the request carries no attributes.
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(txid);
    req
}

/// Parse a STUN Binding Success response and extract the reflexive IPv4 address
/// from its `XOR-MAPPED-ADDRESS` (preferred) or legacy `MAPPED-ADDRESS`
/// attribute. IPv6 mapped addresses are skipped (project is IPv4-only).
fn parse_response(buf: &[u8], txid: &[u8; 12]) -> Result<Ipv4Addr> {
    if buf.len() < STUN_HEADER_LEN {
        bail!("response too short ({} bytes)", buf.len());
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != STUN_BINDING_SUCCESS {
        bail!("not a STUN binding success response");
    }
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != STUN_MAGIC_COOKIE {
        bail!("bad STUN magic cookie");
    }
    if &buf[8..20] != txid {
        bail!("STUN transaction id mismatch");
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let total = buf.len().min(STUN_HEADER_LEN + msg_len);
    let mut pos = STUN_HEADER_LEN;
    while pos + 4 <= total {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let alen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let vpos = pos + 4;
        if vpos + alen > total {
            break;
        }

        if (attr_type == ATTR_XOR_MAPPED_ADDRESS || attr_type == ATTR_MAPPED_ADDRESS) && alen >= 8 {
            // value layout: reserved(1) family(1) port(2) address(4 for IPv4)
            let family = buf[vpos + 1];
            if family == STUN_FAMILY_IPV4 {
                let mut addr =
                    u32::from_be_bytes([buf[vpos + 4], buf[vpos + 5], buf[vpos + 6], buf[vpos + 7]]);
                if attr_type == ATTR_XOR_MAPPED_ADDRESS {
                    addr ^= STUN_MAGIC_COOKIE;
                }
                return Ok(Ipv4Addr::from(addr));
            }
            // family 0x02 (IPv6): intentionally skipped, IPv4-only client.
        }
        // attributes are padded to a 4-byte boundary
        pos = vpos + ((alen + 3) & !3);
    }
    bail!("no IPv4 mapped-address attribute in response")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    #[test]
    fn build_request_has_correct_header() {
        let req = build_request(&TXID);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        // no attributes -> message length 0
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &TXID);
    }

    /// Build a Binding Success response carrying a single mapped-address
    /// attribute (xor-encoded when `xor` is set) for `ip:port`.
    fn success_response(ip: Ipv4Addr, port: u16, xor: bool, txid: &[u8; 12]) -> Vec<u8> {
        let attr_type = if xor {
            ATTR_XOR_MAPPED_ADDRESS
        } else {
            ATTR_MAPPED_ADDRESS
        };
        let (enc_port, enc_addr) = if xor {
            (
                port ^ (STUN_MAGIC_COOKIE >> 16) as u16,
                u32::from(ip) ^ STUN_MAGIC_COOKIE,
            )
        } else {
            (port, u32::from(ip))
        };

        let mut attr = Vec::new();
        attr.push(0x00); // reserved
        attr.push(STUN_FAMILY_IPV4); // family
        attr.extend_from_slice(&enc_port.to_be_bytes());
        attr.extend_from_slice(&enc_addr.to_be_bytes());

        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16 + 4).to_be_bytes()); // attr header + value
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&attr_type.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&attr);
        msg
    }

    #[test]
    fn parses_xor_mapped_address() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let msg = success_response(ip, 51413, true, &TXID);
        assert_eq!(parse_response(&msg, &TXID).unwrap(), ip);
    }

    #[test]
    fn parses_legacy_mapped_address() {
        let ip = Ipv4Addr::new(198, 51, 100, 42);
        let msg = success_response(ip, 4662, false, &TXID);
        assert_eq!(parse_response(&msg, &TXID).unwrap(), ip);
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let msg = success_response(Ipv4Addr::new(203, 0, 113, 7), 1234, true, &TXID);
        let mut wrong = TXID;
        wrong[0] ^= 0xff;
        assert!(parse_response(&msg, &wrong).is_err());
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let mut msg = success_response(Ipv4Addr::new(203, 0, 113, 7), 1234, true, &TXID);
        msg[4] ^= 0xff;
        assert!(parse_response(&msg, &TXID).is_err());
    }

    #[test]
    fn rejects_non_success_type() {
        let mut msg = success_response(Ipv4Addr::new(203, 0, 113, 7), 1234, true, &TXID);
        msg[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        assert!(parse_response(&msg, &TXID).is_err());
    }

    #[test]
    fn rejects_short_response() {
        assert!(parse_response(&[0u8; 8], &TXID).is_err());
    }

    #[test]
    fn skips_ipv6_attribute_and_reports_missing() {
        // A success response whose only mapped-address attribute is IPv6 must be
        // reported as "no IPv4 address" rather than mis-parsed.
        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(24u16).to_be_bytes()); // attr header(4) + value(20)
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&TXID);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&(20u16).to_be_bytes());
        msg.push(0x00); // reserved
        msg.push(0x02); // family = IPv6
        msg.extend_from_slice(&[0u8; 2]); // port
        msg.extend_from_slice(&[0u8; 16]); // 128-bit address
        assert!(parse_response(&msg, &TXID).is_err());
    }
}
