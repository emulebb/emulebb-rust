//! Safe IPv4 ownership wrapper around the shared eMuleBB libpcpnatpmp fork.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    os::raw::c_void,
    ptr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use emulebb_pcpnatpmp_sys as sys;

const AF_INET: u16 = 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// PCP server selection for one client context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSelection {
    /// Discover default gateways, restricted to the route that uses the source IP.
    Automatic,
    /// Use one explicit PCP/NAT-PMP server after validating its selected route.
    Explicit(SocketAddrV4),
}

/// Transport protocol requested by a PCP MAP or NAT-PMP mapping operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    const fn number(self) -> u8 {
        match self {
            Self::Tcp => IPPROTO_TCP,
            Self::Udp => IPPROTO_UDP,
        }
    }
}

/// Protocol version negotiated with the selected gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    PcpV2,
    PcpV1,
    NatPmpV0,
}

impl ProtocolVersion {
    /// Stable diagnostic and REST token for this protocol version.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PcpV2 => "pcp_v2",
            Self::PcpV1 => "pcp_v1",
            Self::NatPmpV0 => "nat_pmp_v0",
        }
    }
}

/// Desired port mapping sent to a PCP or NAT-PMP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRequest {
    pub internal_addr: SocketAddrV4,
    pub protocol: TransportProtocol,
    pub preferred_external_port: u16,
    pub lifetime_secs: u32,
}

/// Confirmed mapping returned by a PCP or NAT-PMP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingInfo {
    pub server_ip: Ipv4Addr,
    pub internal_addr: SocketAddrV4,
    pub external_addr: SocketAddrV4,
    pub protocol: TransportProtocol,
    pub lifetime_secs: u32,
    pub protocol_version: ProtocolVersion,
    pub result_code: u8,
}

struct ActiveFlow {
    raw: *mut sys::pcp_flow_t,
    request: MappingRequest,
}

/// Thread-confined libpcpnatpmp client context and its active flows.
pub struct Client {
    raw: *mut sys::pcp_ctx_t,
    flows: Vec<ActiveFlow>,
}

impl Client {
    /// Creates a route-filtered PCP/NAT-PMP client for `source_ip`.
    pub fn new(source_ip: Ipv4Addr, selection: ServerSelection) -> Result<Self> {
        winsock_startup()?;
        let mut source = sockaddr(SocketAddrV4::new(source_ip, 0));
        let autodiscovery = match selection {
            ServerSelection::Automatic => sys::ENABLE_AUTODISCOVERY,
            ServerSelection::Explicit(_) => sys::DISABLE_AUTODISCOVERY,
        };
        // SAFETY: `source` is a live sockaddr_in for the duration of the call,
        // the default socket vtable is selected with null, and ownership of the
        // returned context is transferred to this Client.
        let raw = unsafe {
            sys::pcp_init_for_source(
                autodiscovery,
                ptr::null_mut(),
                (&mut source as *mut sys::sockaddr_in).cast::<c_void>(),
            )
        };
        if raw.is_null() {
            bail!("libpcpnatpmp failed to initialize a client context");
        }

        let client = Self {
            raw,
            flows: Vec::new(),
        };
        if let ServerSelection::Explicit(endpoint) = selection {
            let mut server = sockaddr(endpoint);
            // SAFETY: context and sockaddr pointers are valid for this call.
            let result = unsafe {
                sys::pcp_add_server_for_source(
                    client.raw,
                    (&mut server as *mut sys::sockaddr_in).cast::<c_void>(),
                    sys::PCP_MAX_SUPPORTED_VERSION,
                    (&mut source as *mut sys::sockaddr_in).cast::<c_void>(),
                )
            };
            if result < 0 {
                if result == sys::PCP_ERR_ROUTE_MISMATCH {
                    bail!(
                        "PCP server {endpoint} is not reachable through configured source {source_ip}"
                    );
                }
                bail!("libpcpnatpmp rejected PCP server {endpoint} with code {result}");
            }
        }
        Ok(client)
    }

    /// Creates one mapping and retains its flow for renewal and deletion.
    pub fn map(&mut self, request: MappingRequest, timeout: Duration) -> Result<MappingInfo> {
        let mut source = sockaddr(request.internal_addr);
        let mut suggested_external = sockaddr(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            request.preferred_external_port,
        ));
        // SAFETY: context and sockaddr pointers stay live for the call. The
        // returned flow is owned by this Client until deletion or termination.
        let flow = unsafe {
            sys::pcp_new_flow(
                self.raw,
                (&mut source as *mut sys::sockaddr_in).cast::<c_void>(),
                ptr::null_mut(),
                (&mut suggested_external as *mut sys::sockaddr_in).cast::<c_void>(),
                request.protocol.number(),
                request.lifetime_secs,
                ptr::null_mut(),
            )
        };
        if flow.is_null() {
            bail!("no route-matching PCP/NAT-PMP server was discovered");
        }

        let result = wait_for_mapping(flow, request.protocol, timeout);
        match result {
            Ok(info) => {
                self.flows.push(ActiveFlow { raw: flow, request });
                Ok(info)
            }
            Err(error) => {
                cleanup_flow(flow, Duration::from_millis(250));
                Err(error)
            }
        }
    }

    /// Renews all retained mappings and returns their latest confirmed state.
    pub fn renew_all(&mut self, lifetime_secs: u32, timeout: Duration) -> Result<Vec<MappingInfo>> {
        let mut renewed = Vec::with_capacity(self.flows.len());
        for flow in &mut self.flows {
            flow.request.lifetime_secs = lifetime_secs;
            // SAFETY: every flow remains owned by this live context.
            unsafe { sys::pcp_flow_set_lifetime(flow.raw, lifetime_secs) };
            renewed.push(wait_for_mapping(flow.raw, flow.request.protocol, timeout)?);
        }
        Ok(renewed)
    }

    /// Deletes every retained mapping and releases its native flow.
    pub fn release_all(&mut self, timeout: Duration) {
        for flow in self.flows.drain(..).rev() {
            cleanup_flow(flow.raw, timeout);
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: Client uniquely owns the context. `close_flows=1` makes an
        // interrupted worker perform one final best-effort delete pulse before
        // libpcpnatpmp releases all flows, sockets, servers, and the context.
        unsafe { sys::pcp_terminate(self.raw, 1) };
        self.raw = ptr::null_mut();
        self.flows.clear();
    }
}

fn wait_for_mapping(
    flow: *mut sys::pcp_flow_t,
    protocol: TransportProtocol,
    timeout: Duration,
) -> Result<MappingInfo> {
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: the flow is owned by the caller's live Client context.
    let state = unsafe { sys::pcp_wait(flow, timeout_ms, 1) };
    let infos = flow_info(flow)?;
    if let Some(info) = infos
        .iter()
        .find(|info| info.result == sys::PCP_STATE_SUCCEEDED)
    {
        return mapping_info(info, protocol);
    }

    let result_codes = infos
        .iter()
        .map(|info| info.pcp_result_code.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let state_name = match state {
        sys::PCP_STATE_PROCESSING => "timed out",
        sys::PCP_STATE_PARTIAL_RESULT => "returned only partial results",
        sys::PCP_STATE_SHORT_LIFETIME_ERROR => "rejected the requested lifetime",
        sys::PCP_STATE_FAILED => "failed",
        other => return Err(anyhow!("libpcpnatpmp returned unknown flow state {other}")),
    };
    bail!(
        "PCP/NAT-PMP mapping {state_name}; gateway result codes: {}",
        if result_codes.is_empty() {
            "none"
        } else {
            &result_codes
        }
    )
}

fn flow_info(flow: *mut sys::pcp_flow_t) -> Result<Vec<sys::pcp_flow_info_t>> {
    let mut count = 0_usize;
    // SAFETY: the flow is live and `count` is writable. The returned array is
    // copied before being released with the matching fork API.
    let raw = unsafe { sys::pcp_flow_get_info(flow, &mut count) };
    if raw.is_null() {
        bail!("libpcpnatpmp did not return flow diagnostics");
    }
    // SAFETY: libpcpnatpmp returned `count` initialized contiguous elements.
    let infos = unsafe { std::slice::from_raw_parts(raw, count) }.to_vec();
    // SAFETY: `raw` is the allocation returned by pcp_flow_get_info and has not
    // previously been released.
    unsafe { sys::pcp_free_flow_info(raw) };
    Ok(infos)
}

fn mapping_info(info: &sys::pcp_flow_info_t, protocol: TransportProtocol) -> Result<MappingInfo> {
    let protocol_version = match info.pcp_version {
        2 => ProtocolVersion::PcpV2,
        1 => ProtocolVersion::PcpV1,
        0 => ProtocolVersion::NatPmpV0,
        other => bail!("gateway negotiated unsupported PCP version {other}"),
    };
    let server_ip = ipv4_from_in6(info.pcp_server_ip)
        .context("PCP server address was not an IPv4-mapped address")?;
    let internal_ip = ipv4_from_in6(info.int_ip)
        .context("PCP internal address was not an IPv4-mapped address")?;
    let external_ip = ipv4_from_in6(info.ext_ip).context("PCP external address was not IPv4")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let lifetime_secs = u32::try_from(
        info.recv_lifetime_end
            .saturating_sub(i64::try_from(now).unwrap_or(i64::MAX)),
    )
    .unwrap_or_default();

    Ok(MappingInfo {
        server_ip,
        internal_addr: SocketAddrV4::new(internal_ip, u16::from_be(info.int_port)),
        external_addr: SocketAddrV4::new(external_ip, u16::from_be(info.ext_port)),
        protocol,
        lifetime_secs,
        protocol_version,
        result_code: info.pcp_result_code,
    })
}

fn cleanup_flow(flow: *mut sys::pcp_flow_t, timeout: Duration) {
    // SAFETY: the flow is live and uniquely owned by the caller.
    unsafe {
        sys::pcp_close_flow(flow);
        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let _ = sys::pcp_wait(flow, timeout_ms, 1);
        sys::pcp_delete_flow(flow);
    }
}

fn sockaddr(endpoint: SocketAddrV4) -> sys::sockaddr_in {
    sys::sockaddr_in {
        sin_family: AF_INET,
        sin_port: endpoint.port().to_be(),
        sin_addr: sys::in_addr {
            s_addr: u32::from_ne_bytes(endpoint.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn ipv4_from_in6(address: sys::in6_addr) -> Option<Ipv4Addr> {
    let bytes = address.bytes;
    if bytes[..10] == [0; 10] && bytes[10..12] == [0xff, 0xff] {
        return Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
    }
    if bytes[..12] == [0; 12] {
        return Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
    }
    None
}

#[cfg(windows)]
fn winsock_startup() -> Result<()> {
    use std::sync::OnceLock;

    static STARTUP: OnceLock<bool> = OnceLock::new();
    let started = *STARTUP.get_or_init(|| {
        // SAFETY: libpcpnatpmp exposes a process-wide WSAStartup wrapper. We
        // intentionally retain the matching Winsock reference for process life.
        unsafe { sys::pcp_win_sock_startup() == 0 }
    });
    if started {
        Ok(())
    } else {
        bail!("libpcpnatpmp failed to initialize Winsock")
    }
}

#[cfg(not(windows))]
fn winsock_startup() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Client, MappingRequest, ProtocolVersion, ServerSelection, TransportProtocol, ipv4_from_in6,
        sockaddr,
    };
    use emulebb_pcpnatpmp_sys::in6_addr;
    use std::{
        net::{Ipv4Addr, SocketAddrV4, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    #[test]
    fn sockaddr_preserves_ipv4_network_bytes_and_port() {
        let address = sockaddr(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 5351));
        assert_eq!(address.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 7]);
        assert_eq!(u16::from_be(address.sin_port), 5351);
    }

    #[test]
    fn ipv4_mapped_address_is_decoded() {
        let mut bytes = [0_u8; 16];
        bytes[10..12].copy_from_slice(&[0xff, 0xff]);
        bytes[12..].copy_from_slice(&[198, 51, 100, 9]);
        assert_eq!(
            ipv4_from_in6(in6_addr { bytes }),
            Some(Ipv4Addr::new(198, 51, 100, 9))
        );
    }

    #[test]
    fn deterministic_server_proves_pcp_v2_mapping() {
        with_mock_server(MockProtocol::PcpV2, |endpoint| {
            let mut client =
                Client::new(Ipv4Addr::LOCALHOST, ServerSelection::Explicit(endpoint)).unwrap();
            let info = client
                .map(mapping_request(), Duration::from_secs(2))
                .unwrap();

            assert_eq!(info.protocol_version, ProtocolVersion::PcpV2);
            assert_eq!(info.server_ip, Ipv4Addr::LOCALHOST);
            assert_eq!(*info.external_addr.ip(), Ipv4Addr::new(203, 0, 113, 9));
            assert_eq!(info.external_addr.port(), 41_000);
            client.release_all(Duration::from_millis(250));
        });
    }

    #[test]
    fn deterministic_server_proves_nat_pmp_v0_fallback() {
        with_mock_server(MockProtocol::NatPmpV0, |endpoint| {
            let mut client =
                Client::new(Ipv4Addr::LOCALHOST, ServerSelection::Explicit(endpoint)).unwrap();
            let info = client
                .map(mapping_request(), Duration::from_secs(2))
                .unwrap();

            assert_eq!(info.protocol_version, ProtocolVersion::NatPmpV0);
            assert_eq!(*info.external_addr.ip(), Ipv4Addr::new(203, 0, 113, 9));
            assert_eq!(info.external_addr.port(), 41_000);
            client.release_all(Duration::from_millis(250));
        });
    }

    fn mapping_request() -> MappingRequest {
        MappingRequest {
            internal_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41_000),
            protocol: TransportProtocol::Udp,
            preferred_external_port: 41_000,
            lifetime_secs: 120,
        }
    }

    #[derive(Clone, Copy)]
    enum MockProtocol {
        PcpV2,
        NatPmpV0,
    }

    fn with_mock_server(test_protocol: MockProtocol, test: impl FnOnce(SocketAddrV4)) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let endpoint = match socket.local_addr().unwrap() {
            std::net::SocketAddr::V4(endpoint) => endpoint,
            std::net::SocketAddr::V6(_) => unreachable!(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut buffer = [0_u8; 1100];
            while !thread_stop.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buffer) {
                    Ok((size, peer)) => {
                        let response = mock_response(test_protocol, &buffer[..size]);
                        if !response.is_empty() {
                            socket.send_to(&response, peer).unwrap();
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => panic!("mock PCP server receive failed: {error}"),
                }
            }
        });

        test(endpoint);
        stop.store(true, Ordering::Relaxed);
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .send_to(&[0], endpoint)
            .unwrap();
        worker.join().unwrap();
    }

    fn mock_response(test_protocol: MockProtocol, request: &[u8]) -> Vec<u8> {
        match test_protocol {
            MockProtocol::PcpV2 => pcp_v2_response(request),
            MockProtocol::NatPmpV0 => nat_pmp_response(request),
        }
    }

    fn pcp_v2_response(request: &[u8]) -> Vec<u8> {
        if request.len() < 60 || request[0] != 2 {
            return Vec::new();
        }
        let mut response = request.to_vec();
        response[1] |= 0x80;
        response[2] = 0;
        response[3] = 0;
        response[4..8].copy_from_slice(&request[4..8]);
        response[8..12].copy_from_slice(&1_u32.to_be_bytes());
        response[12..24].fill(0);
        response[44..60].fill(0);
        response[54..56].copy_from_slice(&[0xff, 0xff]);
        response[56..60].copy_from_slice(&[203, 0, 113, 9]);
        response
    }

    fn nat_pmp_response(request: &[u8]) -> Vec<u8> {
        if request.len() >= 24 && request[0] == 2 {
            let mut response = vec![0_u8; 8];
            response[0] = 0;
            response[1] = request[1] | 0x80;
            response[2..4].copy_from_slice(&1_u16.to_be_bytes());
            response[4..8].copy_from_slice(&1_u32.to_be_bytes());
            return response;
        }
        if request.len() == 2 && request[0] == 0 && request[1] == 0 {
            let mut response = vec![0_u8; 12];
            response[1] = 0x80;
            response[4..8].copy_from_slice(&1_u32.to_be_bytes());
            response[8..12].copy_from_slice(&[203, 0, 113, 9]);
            return response;
        }
        if request.len() == 12 && request[0] == 0 && matches!(request[1], 1 | 2) {
            let mut response = vec![0_u8; 16];
            response[1] = request[1] | 0x80;
            response[4..8].copy_from_slice(&1_u32.to_be_bytes());
            response[8..12].copy_from_slice(&request[4..8]);
            response[12..16].copy_from_slice(&request[8..12]);
            return response;
        }
        Vec::new()
    }
}
