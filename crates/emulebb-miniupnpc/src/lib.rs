use std::{
    ffi::{CStr, CString},
    net::IpAddr,
    os::raw::{c_char, c_int},
    path::PathBuf,
    ptr,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use emulebb_miniupnpc_sys as sys;
use tracing::debug;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{WSACleanup, WSADATA, WSAStartup};

const DEFAULT_TTL: u8 = 2;
const DEFAULT_DEVICE_TYPES: [&str; 6] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "upnp:rootdevice",
];
const LANADDR_CAPACITY: usize = 64;
const WANADDR_CAPACITY: usize = 64;
const EXTERNAL_IP_CAPACITY: usize = 64;
const MAPPING_CLIENT_CAPACITY: usize = 16;
const MAPPING_PORT_CAPACITY: usize = 6;
const MAPPING_DESC_CAPACITY: usize = 80;
const MAPPING_ENABLED_CAPACITY: usize = 4;
const MAPPING_LEASE_CAPACITY: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceSearchTarget {
    InternetGatewayDeviceV2,
    WanIpConnectionV2,
    InternetGatewayDeviceV1,
    WanIpConnectionV1,
    WanPppConnectionV1,
    RootDevice,
    SsdpAll,
    Custom(String),
}

impl DeviceSearchTarget {
    fn as_str(&self) -> &str {
        match self {
            Self::InternetGatewayDeviceV2 => "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
            Self::WanIpConnectionV2 => "urn:schemas-upnp-org:service:WANIPConnection:2",
            Self::InternetGatewayDeviceV1 => "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            Self::WanIpConnectionV1 => "urn:schemas-upnp-org:service:WANIPConnection:1",
            Self::WanPppConnectionV1 => "urn:schemas-upnp-org:service:WANPPPConnection:1",
            Self::RootDevice => "upnp:rootdevice",
            Self::SsdpAll => "ssdp:all",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryOptions {
    pub timeout: Duration,
    pub multicast_interface: Option<String>,
    pub minissdpd_socket: Option<PathBuf>,
    pub local_port: Option<u16>,
    pub ipv6: bool,
    pub ttl: u8,
    pub search_targets: Vec<DeviceSearchTarget>,
    pub search_all_types: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            multicast_interface: None,
            minissdpd_socket: None,
            local_port: None,
            ipv6: false,
            ttl: DEFAULT_TTL,
            search_targets: default_search_targets(),
            search_all_types: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub description_url: String,
    pub search_target: Option<String>,
    pub usn: Option<String>,
    pub scope_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayStatus {
    Connected,
    PrivateIp,
    Disconnected,
    UnknownDevice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub devices: Vec<DiscoveredDevice>,
    pub gateway: Option<GatewaySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySummary {
    pub status: GatewayStatus,
    pub root_description_url: String,
    pub control_url: String,
    pub service_type: String,
    pub local_ip: Option<String>,
    pub gateway_ip: Option<String>,
    pub external_ip: Option<String>,
}

pub struct Gateway {
    summary: GatewaySummary,
    urls: sys::UPNPUrls,
    data: sys::IGDdatas,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMappingEntry {
    /// LAN client currently bound to the external port.
    pub internal_client: String,
    /// LAN port currently bound to the external port.
    pub internal_port: u16,
    /// Router-side description when one is exposed by the IGD.
    pub description: Option<String>,
    /// Whether the mapping is enabled when reported by the IGD.
    pub enabled: Option<bool>,
    /// Remaining lease duration in seconds when reported by the IGD.
    pub lease_duration_secs: Option<u32>,
}

/// Error returned by [`Gateway::add_port_mapping`]. When the IGD rejects the
/// mapping, `code` holds the raw miniupnpc/SOAP result code (e.g. `718`, `725`,
/// `606`) and `description` its decoded text, so the real refusal reason is
/// logged instead of a generic "failed to add" message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddPortMappingError {
    /// Raw miniupnpc/IGD result code, when the failure originated from the IGD.
    pub code: Option<c_int>,
    /// Decoded description of the failure.
    pub description: String,
}

impl AddPortMappingError {
    fn igd(status: c_int) -> Self {
        Self {
            code: Some(status),
            description: upnp_error_string(status),
        }
    }

    fn setup(error: anyhow::Error) -> Self {
        Self {
            code: None,
            description: error.to_string(),
        }
    }

    /// Returns true when the IGD reported `725 OnlyPermanentLeasesSupported`.
    #[must_use]
    pub fn is_only_permanent_leases_supported(&self) -> bool {
        self.code == Some(725)
    }

    /// Returns true when the IGD reported `718 ConflictInMappingEntry`.
    #[must_use]
    pub fn is_conflict_in_mapping_entry(&self) -> bool {
        self.code == Some(718)
    }
}

impl std::fmt::Display for AddPortMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(
                f,
                "UPNP_AddPortMapping failed: IGD result code {code} ({})",
                self.description
            ),
            None => write!(f, "UPNP_AddPortMapping failed: {}", self.description),
        }
    }
}

impl std::error::Error for AddPortMappingError {}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("summary", &self.summary)
            .finish()
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        unsafe {
            sys::FreeUPNPUrls(&mut self.urls);
        }
    }
}

impl Gateway {
    pub fn summary(&self) -> &GatewaySummary {
        &self.summary
    }

    pub fn root_description_url(&self) -> &str {
        &self.summary.root_description_url
    }

    pub fn control_url(&self) -> &str {
        &self.summary.control_url
    }

    pub fn service_type(&self) -> &str {
        &self.summary.service_type
    }

    pub fn status(&self) -> GatewayStatus {
        self.summary.status
    }

    pub fn local_ip(&self) -> Option<&str> {
        self.summary.local_ip.as_deref()
    }

    pub fn gateway_ip(&self) -> Option<&str> {
        self.summary.gateway_ip.as_deref()
    }

    pub fn external_ip(&self) -> Option<&str> {
        self.summary.external_ip.as_deref()
    }

    pub fn fetch_external_ip(&self) -> Result<Option<String>> {
        let _winsock = WinsockGuard::init()?;
        external_ip_from_raw(&self.urls, &self.data)
    }

    /// Adds (or replaces) an IGD port mapping, mirroring eMuleBB MFC's
    /// `CUPnPImplMiniLib::OpenPort` call shape: `remoteHost` is always `NULL`
    /// (not an empty string) and `leaseDuration` is `NULL` when
    /// `lease_duration_secs` is `None` (indefinite/permanent lease). Restrictive
    /// IGDs (e.g. the hide.me VPN gateway) reject finite leases with `725`, so
    /// MFC-parity callers pass `None`. On failure the [`AddPortMappingError`]
    /// carries the raw IGD result code and description.
    pub fn add_port_mapping(
        &self,
        external_port: u16,
        internal_port: u16,
        internal_ip: &str,
        description: &str,
        protocol: &str,
        lease_duration_secs: Option<u32>,
    ) -> Result<(), AddPortMappingError> {
        let _winsock = WinsockGuard::init().map_err(AddPortMappingError::setup)?;
        let control_url = c_string(&self.summary.control_url, "control_url")
            .map_err(AddPortMappingError::setup)?;
        let service_type = c_string(&self.summary.service_type, "service_type")
            .map_err(AddPortMappingError::setup)?;
        let external_port = CString::new(external_port.to_string()).unwrap();
        let internal_port = CString::new(internal_port.to_string()).unwrap();
        let internal_ip =
            c_string(internal_ip, "internal_ip").map_err(AddPortMappingError::setup)?;
        let description =
            c_string(description, "description").map_err(AddPortMappingError::setup)?;
        let protocol = c_string(protocol, "protocol").map_err(AddPortMappingError::setup)?;
        // MFC passes remoteHost=NULL and leaseDuration=NULL (indefinite). Mirror
        // that exactly: a real null pointer, never an empty CString.
        let lease_duration =
            lease_duration_secs.map(|secs| CString::new(secs.to_string()).unwrap());

        let status = unsafe {
            sys::UPNP_AddPortMapping(
                control_url.as_ptr(),
                service_type.as_ptr(),
                external_port.as_ptr(),
                internal_port.as_ptr(),
                internal_ip.as_ptr(),
                description.as_ptr(),
                protocol.as_ptr(),
                ptr::null(),
                lease_duration
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
            )
        };
        if status == sys::UPNPCOMMAND_SUCCESS {
            return Ok(());
        }
        Err(AddPortMappingError::igd(status))
    }

    pub fn delete_port_mapping(&self, external_port: u16, protocol: &str) -> Result<()> {
        let _winsock = WinsockGuard::init()?;
        let control_url = c_string(&self.summary.control_url, "control_url")?;
        let service_type = c_string(&self.summary.service_type, "service_type")?;
        let external_port = CString::new(external_port.to_string()).unwrap();
        let protocol = c_string(protocol, "protocol")?;
        let remote_host = CString::new("").unwrap();

        let status = unsafe {
            sys::UPNP_DeletePortMapping(
                control_url.as_ptr(),
                service_type.as_ptr(),
                external_port.as_ptr(),
                protocol.as_ptr(),
                remote_host.as_ptr(),
            )
        };
        ensure_command_success("UPNP_DeletePortMapping", status)
    }

    /// Reads the current IGD mapping for a specific external port and protocol.
    pub fn get_specific_port_mapping(
        &self,
        external_port: u16,
        protocol: &str,
    ) -> Result<Option<PortMappingEntry>> {
        let _winsock = WinsockGuard::init()?;
        let control_url = c_string(&self.summary.control_url, "control_url")?;
        let service_type = c_string(&self.summary.service_type, "service_type")?;
        let external_port = CString::new(external_port.to_string()).unwrap();
        let protocol = c_string(protocol, "protocol")?;
        let remote_host = CString::new("").unwrap();
        let mut internal_client = [0 as c_char; MAPPING_CLIENT_CAPACITY];
        let mut internal_port = [0 as c_char; MAPPING_PORT_CAPACITY];
        let mut description = [0 as c_char; MAPPING_DESC_CAPACITY];
        let mut enabled = [0 as c_char; MAPPING_ENABLED_CAPACITY];
        let mut lease_duration = [0 as c_char; MAPPING_LEASE_CAPACITY];

        let status = unsafe {
            sys::UPNP_GetSpecificPortMappingEntry(
                control_url.as_ptr(),
                service_type.as_ptr(),
                external_port.as_ptr(),
                protocol.as_ptr(),
                remote_host.as_ptr(),
                internal_client.as_mut_ptr(),
                internal_port.as_mut_ptr(),
                description.as_mut_ptr(),
                enabled.as_mut_ptr(),
                lease_duration.as_mut_ptr(),
            )
        };

        if status == sys::UPNPCOMMAND_SUCCESS {
            let internal_client = buffer_to_string(&internal_client)
                .ok_or_else(|| anyhow!("miniupnpc did not return an internal client"))?;
            let internal_port = buffer_to_string(&internal_port)
                .ok_or_else(|| anyhow!("miniupnpc did not return an internal port"))?
                .parse()
                .context("miniupnpc returned an invalid internal port")?;
            return Ok(Some(PortMappingEntry {
                internal_client,
                internal_port,
                description: buffer_to_string(&description),
                enabled: buffer_to_string(&enabled).map(|value| value == "1"),
                lease_duration_secs: buffer_to_string(&lease_duration)
                    .map(|value| {
                        value
                            .parse()
                            .context("miniupnpc returned an invalid lease duration")
                    })
                    .transpose()?,
            }));
        }

        if status == sys::UPNPERR_NO_SUCH_ENTRY_IN_ARRAY {
            return Ok(None);
        }

        bail!(
            "UPNP_GetSpecificPortMappingEntry failed: {}",
            upnp_error_string(status)
        )
    }
}

pub fn default_search_targets() -> Vec<DeviceSearchTarget> {
    vec![
        DeviceSearchTarget::InternetGatewayDeviceV2,
        DeviceSearchTarget::WanIpConnectionV2,
        DeviceSearchTarget::InternetGatewayDeviceV1,
        DeviceSearchTarget::WanIpConnectionV1,
        DeviceSearchTarget::WanPppConnectionV1,
        DeviceSearchTarget::RootDevice,
    ]
}

pub fn discover(options: &DiscoveryOptions) -> Result<(DiscoveryResult, Option<Gateway>)> {
    let _winsock = WinsockGuard::init()?;
    let multicast_interface = options
        .multicast_interface
        .as_deref()
        .map(|value| c_string(value, "multicast_interface"))
        .transpose()?;
    let minissdpd_socket = minissdpd_socket_cstring(options.minissdpd_socket.as_ref())?;
    let device_types = build_device_type_list(&options.search_targets)?;
    let mut error = sys::UPNPDISCOVER_UNKNOWN_ERROR;
    let delay_ms = duration_to_millis(options.timeout)?;
    let local_port = options
        .local_port
        .map(c_int::from)
        .unwrap_or(sys::UPNP_LOCAL_PORT_ANY);

    debug!(
        "miniupnpc discover delay_ms={} multicast_if={:?} minissdpd_socket={:?} local_port={} ipv6={} ttl={} search_all_types={} device_types={:?}",
        delay_ms,
        options.multicast_interface,
        options.minissdpd_socket,
        local_port,
        options.ipv6,
        options.ttl,
        options.search_all_types,
        options
            .search_targets
            .iter()
            .map(DeviceSearchTarget::as_str)
            .collect::<Vec<_>>()
    );

    let raw_devlist = unsafe {
        sys::upnpDiscoverDevices(
            device_types.pointers.as_ptr(),
            delay_ms,
            multicast_interface
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
            minissdpd_socket
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
            local_port,
            if options.ipv6 { 1 } else { 0 },
            options.ttl,
            &mut error,
            if options.search_all_types { 1 } else { 0 },
        )
    };

    if raw_devlist.is_null() && error != sys::UPNPDISCOVER_SUCCESS {
        bail!("miniupnpc discovery failed: {}", upnp_error_string(error));
    }

    let devlist = UpnpDevList(raw_devlist);
    let devices = collect_devices(devlist.0);
    let gateway = build_gateway_from_devlist(devlist.0)?;
    Ok((
        DiscoveryResult {
            devices,
            gateway: gateway.as_ref().map(|gateway| gateway.summary.clone()),
        },
        gateway,
    ))
}

pub fn gateway_from_url(root_description_url: &str) -> Result<Option<Gateway>> {
    let _winsock = WinsockGuard::init()?;
    let root_description_url = c_string(root_description_url, "root_description_url")?;
    let mut urls = zeroed_urls();
    let mut data = zeroed_data();
    let mut local_ip = [0 as c_char; LANADDR_CAPACITY];

    let status = unsafe {
        sys::UPNP_GetIGDFromUrl(
            root_description_url.as_ptr(),
            &mut urls,
            &mut data,
            local_ip.as_mut_ptr(),
            local_ip.len() as c_int,
        )
    };
    if status == 0 {
        return Ok(None);
    }

    let connected = unsafe { sys::UPNPIGD_IsConnected(&mut urls, &mut data) == 1 };
    let external_ip = external_ip_from_raw(&urls, &data)?;
    let gateway_status = match external_ip.as_deref().and_then(parse_ip_addr) {
        Some(IpAddr::V4(ip)) if ip.is_private() || ip.is_link_local() => GatewayStatus::PrivateIp,
        Some(_) if connected => GatewayStatus::Connected,
        _ if connected => GatewayStatus::Connected,
        _ => GatewayStatus::Disconnected,
    };

    Ok(Some(build_gateway(
        gateway_status,
        urls,
        data,
        buffer_to_string(&local_ip),
        external_ip,
    )?))
}

fn build_gateway_from_devlist(devlist: *mut sys::UPNPDev) -> Result<Option<Gateway>> {
    if devlist.is_null() {
        return Ok(None);
    }

    let mut urls = zeroed_urls();
    let mut data = zeroed_data();
    let mut local_ip = [0 as c_char; LANADDR_CAPACITY];
    let mut external_ip = [0 as c_char; WANADDR_CAPACITY];
    let status = unsafe {
        sys::UPNP_GetValidIGD(
            devlist,
            &mut urls,
            &mut data,
            local_ip.as_mut_ptr(),
            local_ip.len() as c_int,
            external_ip.as_mut_ptr(),
            external_ip.len() as c_int,
        )
    };

    let gateway_status = match status {
        sys::UPNP_CONNECTED_IGD => GatewayStatus::Connected,
        sys::UPNP_PRIVATEIP_IGD => GatewayStatus::PrivateIp,
        sys::UPNP_DISCONNECTED_IGD => GatewayStatus::Disconnected,
        sys::UPNP_UNKNOWN_DEVICE => GatewayStatus::UnknownDevice,
        sys::UPNP_NO_IGD => return Ok(None),
        other => bail!("miniupnpc returned unexpected IGD status {other}"),
    };

    Ok(Some(build_gateway(
        gateway_status,
        urls,
        data,
        buffer_to_string(&local_ip),
        buffer_to_string(&external_ip),
    )?))
}

fn build_gateway(
    status: GatewayStatus,
    urls: sys::UPNPUrls,
    data: sys::IGDdatas,
    local_ip: Option<String>,
    external_ip: Option<String>,
) -> Result<Gateway> {
    let root_description_url = pointer_to_string(urls.rootdescURL)
        .ok_or_else(|| anyhow!("miniupnpc did not provide rootdescURL"))?;
    let control_url = pointer_to_string(urls.controlURL)
        .ok_or_else(|| anyhow!("miniupnpc did not provide controlURL"))?;
    let service_type = service_type_from_data(&data)
        .ok_or_else(|| anyhow!("miniupnpc did not provide a usable service type"))?;
    let summary = GatewaySummary {
        status,
        gateway_ip: host_from_url(&root_description_url),
        root_description_url,
        control_url,
        service_type,
        local_ip,
        external_ip,
    };
    Ok(Gateway {
        summary,
        urls,
        data,
    })
}

fn collect_devices(mut current: *mut sys::UPNPDev) -> Vec<DiscoveredDevice> {
    let mut devices = Vec::new();
    while !current.is_null() {
        let device = unsafe { &*current };
        devices.push(DiscoveredDevice {
            description_url: pointer_to_string(device.descURL).unwrap_or_default(),
            search_target: pointer_to_string(device.st),
            usn: pointer_to_string(device.usn),
            scope_id: device.scope_id,
        });
        current = device.pNext;
    }
    devices
}

fn external_ip_from_raw(urls: &sys::UPNPUrls, data: &sys::IGDdatas) -> Result<Option<String>> {
    let control_url = match pointer_to_string(urls.controlURL) {
        Some(value) => c_string(&value, "control_url")?,
        None => return Ok(None),
    };
    let service_type = match service_type_from_data(data) {
        Some(value) => c_string(&value, "service_type")?,
        None => return Ok(None),
    };
    let mut buffer = [0 as c_char; EXTERNAL_IP_CAPACITY];
    let status = unsafe {
        sys::UPNP_GetExternalIPAddress(
            control_url.as_ptr(),
            service_type.as_ptr(),
            buffer.as_mut_ptr(),
        )
    };
    if status == sys::UPNPCOMMAND_SUCCESS {
        return Ok(buffer_to_string(&buffer));
    }
    if matches!(
        status,
        sys::UPNPCOMMAND_HTTP_ERROR
            | sys::UPNPCOMMAND_INVALID_RESPONSE
            | sys::UPNPCOMMAND_UNKNOWN_ERROR
    ) {
        debug!(
            "miniupnpc external IP lookup failed with code {} ({})",
            status,
            upnp_error_string(status)
        );
        return Ok(None);
    }
    bail!(
        "miniupnpc external IP lookup failed: {}",
        upnp_error_string(status)
    )
}

fn service_type_from_data(data: &sys::IGDdatas) -> Option<String> {
    buffer_to_string(&data.first.servicetype).or_else(|| buffer_to_string(&data.second.servicetype))
}

fn build_device_type_list(search_targets: &[DeviceSearchTarget]) -> Result<DeviceTypeList> {
    let values = if search_targets.is_empty() {
        DEFAULT_DEVICE_TYPES
            .iter()
            .map(|value| CString::new(*value).unwrap())
            .collect::<Vec<_>>()
    } else {
        search_targets
            .iter()
            .map(|target| c_string(target.as_str(), "search_target"))
            .collect::<Result<Vec<_>>>()?
    };
    let mut pointers = values
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    pointers.push(ptr::null());
    Ok(DeviceTypeList {
        _values: values,
        pointers,
    })
}

fn minissdpd_socket_cstring(path: Option<&PathBuf>) -> Result<Option<CString>> {
    #[cfg(windows)]
    {
        if path.is_some() {
            bail!("minissdpd is not supported on Windows for miniupnpc discovery");
        }
        Ok(None)
    }

    #[cfg(not(windows))]
    {
        path.map(|value| {
            let socket = value
                .to_str()
                .ok_or_else(|| anyhow!("minissdpd socket path is not valid UTF-8"))?;
            c_string(socket, "minissdpd_socket")
        })
        .transpose()
    }
}

fn duration_to_millis(duration: Duration) -> Result<c_int> {
    let millis = duration.as_millis();
    c_int::try_from(millis).context("discovery timeout is too large for miniupnpc")
}

fn c_string(value: &str, field: &str) -> Result<CString> {
    CString::new(value).with_context(|| format!("{field} contains an interior NUL byte"))
}

fn pointer_to_string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .trim()
        .to_string();
    (!value.is_empty()).then_some(value)
}

fn buffer_to_string(buffer: &[c_char]) -> Option<String> {
    let nul = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    if nul == 0 {
        return None;
    }
    let bytes = buffer[..nul]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    let value = String::from_utf8_lossy(&bytes).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn host_from_url(url: &str) -> Option<String> {
    let authority = url
        .split_once("://")
        .map_or(url, |(_, remainder)| remainder);
    let authority = authority.split('/').next()?;
    if authority.starts_with('[') {
        return authority
            .split(']')
            .next()
            .map(|value| value.trim_start_matches('[').to_string());
    }
    Some(authority.split(':').next()?.to_string())
}

fn ensure_command_success(action: &str, status: c_int) -> Result<()> {
    if status == sys::UPNPCOMMAND_SUCCESS {
        return Ok(());
    }
    bail!("{action} failed: {}", upnp_error_string(status))
}

fn upnp_error_string(status: c_int) -> String {
    let text = unsafe { sys::strupnperror(status) };
    pointer_to_string(text).unwrap_or_else(|| format!("unknown miniupnpc error {status}"))
}

fn zeroed_urls() -> sys::UPNPUrls {
    unsafe { std::mem::zeroed() }
}

fn zeroed_data() -> sys::IGDdatas {
    unsafe { std::mem::zeroed() }
}

fn parse_ip_addr(value: &str) -> Option<IpAddr> {
    value.parse().ok()
}

struct UpnpDevList(*mut sys::UPNPDev);

struct DeviceTypeList {
    _values: Vec<CString>,
    pointers: Vec<*const c_char>,
}

struct WinsockGuard;

impl WinsockGuard {
    #[cfg(windows)]
    fn init() -> Result<Self> {
        let mut data = unsafe { std::mem::zeroed::<WSADATA>() };
        let status = unsafe { WSAStartup(make_word(2, 2), &mut data) };
        if status != 0 {
            bail!("WSAStartup failed with code {status}");
        }
        Ok(Self)
    }

    #[cfg(not(windows))]
    fn init() -> Result<Self> {
        Ok(Self)
    }
}

impl Drop for WinsockGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            let _ = WSACleanup();
        }
    }
}

#[cfg(windows)]
const fn make_word(low: u8, high: u8) -> u16 {
    (low as u16) | ((high as u16) << 8)
}

impl Drop for UpnpDevList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                sys::freeUPNPDevlist(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddPortMappingError, DeviceSearchTarget, GatewayStatus, buffer_to_string,
        default_search_targets, host_from_url,
    };

    #[test]
    fn add_port_mapping_error_decodes_known_igd_codes() {
        let only_permanent = AddPortMappingError::igd(725);
        assert!(only_permanent.is_only_permanent_leases_supported());
        assert!(!only_permanent.is_conflict_in_mapping_entry());
        assert!(
            only_permanent
                .description
                .contains("OnlyPermanentLeasesSupported")
        );
        assert!(only_permanent.to_string().contains("725"));

        let conflict = AddPortMappingError::igd(718);
        assert!(conflict.is_conflict_in_mapping_entry());
        assert!(conflict.description.contains("ConflictInMappingEntry"));

        let not_authorized = AddPortMappingError::igd(606);
        assert!(not_authorized.description.contains("not authorized"));
    }

    #[test]
    fn default_search_targets_include_igd_and_rootdevice() {
        let targets = default_search_targets()
            .into_iter()
            .map(|target| target.as_str().to_string())
            .collect::<Vec<_>>();

        assert!(targets.contains(&DeviceSearchTarget::RootDevice.as_str().to_string()));
        assert!(
            targets.contains(
                &DeviceSearchTarget::InternetGatewayDeviceV1
                    .as_str()
                    .to_string()
            )
        );
    }

    #[test]
    fn host_from_url_handles_ipv4() {
        assert_eq!(
            host_from_url("http://10.255.255.250:1900/gateDesc.xml").as_deref(),
            Some("10.255.255.250")
        );
    }

    #[test]
    fn buffer_to_string_ignores_empty_values() {
        assert_eq!(buffer_to_string(&[0; 4]), None);
    }

    #[test]
    fn gateway_status_debug_is_stable() {
        assert_eq!(format!("{:?}", GatewayStatus::Connected), "Connected");
    }
}
