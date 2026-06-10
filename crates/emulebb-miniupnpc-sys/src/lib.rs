#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_uchar, c_uint};

pub const MINIUPNPC_URL_MAXSIZE: usize = 128;

pub const UPNPDISCOVER_SUCCESS: c_int = 0;
pub const UPNPDISCOVER_UNKNOWN_ERROR: c_int = -1;
pub const UPNPDISCOVER_SOCKET_ERROR: c_int = -101;
pub const UPNPDISCOVER_MEMORY_ERROR: c_int = -102;

pub const UPNP_LOCAL_PORT_ANY: c_int = 0;
pub const UPNP_LOCAL_PORT_SAME: c_int = 1;

pub const UPNP_NO_IGD: c_int = 0;
pub const UPNP_CONNECTED_IGD: c_int = 1;
pub const UPNP_PRIVATEIP_IGD: c_int = 2;
pub const UPNP_DISCONNECTED_IGD: c_int = 3;
pub const UPNP_UNKNOWN_DEVICE: c_int = 4;

pub const UPNPCOMMAND_SUCCESS: c_int = 0;
pub const UPNPCOMMAND_UNKNOWN_ERROR: c_int = -1;
pub const UPNPCOMMAND_INVALID_ARGS: c_int = -2;
pub const UPNPCOMMAND_HTTP_ERROR: c_int = -3;
pub const UPNPCOMMAND_INVALID_RESPONSE: c_int = -4;
pub const UPNPCOMMAND_MEM_ALLOC_ERROR: c_int = -5;
pub const UPNPERR_NO_SUCH_ENTRY_IN_ARRAY: c_int = 714;

#[repr(C)]
pub struct UPNPDev {
    pub pNext: *mut UPNPDev,
    pub descURL: *mut c_char,
    pub st: *mut c_char,
    pub usn: *mut c_char,
    pub scope_id: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UPNPUrls {
    pub controlURL: *mut c_char,
    pub ipcondescURL: *mut c_char,
    pub controlURL_CIF: *mut c_char,
    pub controlURL_6FC: *mut c_char,
    pub rootdescURL: *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IGDdatas_service {
    pub controlurl: [c_char; MINIUPNPC_URL_MAXSIZE],
    pub eventsuburl: [c_char; MINIUPNPC_URL_MAXSIZE],
    pub scpdurl: [c_char; MINIUPNPC_URL_MAXSIZE],
    pub servicetype: [c_char; MINIUPNPC_URL_MAXSIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IGDdatas {
    pub cureltname: [c_char; MINIUPNPC_URL_MAXSIZE],
    pub urlbase: [c_char; MINIUPNPC_URL_MAXSIZE],
    pub presentationurl: [c_char; MINIUPNPC_URL_MAXSIZE],
    pub level: c_int,
    pub cif: IGDdatas_service,
    pub first: IGDdatas_service,
    pub second: IGDdatas_service,
    pub ipv6fc: IGDdatas_service,
    pub tmp: IGDdatas_service,
}

unsafe extern "C" {
    pub fn upnpDiscover(
        delay: c_int,
        multicastif: *const c_char,
        minissdpdsock: *const c_char,
        localport: c_int,
        ipv6: c_int,
        ttl: c_uchar,
        error: *mut c_int,
    ) -> *mut UPNPDev;

    pub fn upnpDiscoverDevices(
        deviceTypes: *const *const c_char,
        delay: c_int,
        multicastif: *const c_char,
        minissdpdsock: *const c_char,
        localport: c_int,
        ipv6: c_int,
        ttl: c_uchar,
        error: *mut c_int,
        searchalltypes: c_int,
    ) -> *mut UPNPDev;

    pub fn UPNP_GetValidIGD(
        devlist: *mut UPNPDev,
        urls: *mut UPNPUrls,
        data: *mut IGDdatas,
        lanaddr: *mut c_char,
        lanaddrlen: c_int,
        wanaddr: *mut c_char,
        wanaddrlen: c_int,
    ) -> c_int;

    pub fn UPNP_GetIGDFromUrl(
        rootdescurl: *const c_char,
        urls: *mut UPNPUrls,
        data: *mut IGDdatas,
        lanaddr: *mut c_char,
        lanaddrlen: c_int,
    ) -> c_int;

    pub fn UPNP_GetExternalIPAddress(
        controlURL: *const c_char,
        servicetype: *const c_char,
        extIpAdd: *mut c_char,
    ) -> c_int;

    pub fn UPNP_AddPortMapping(
        controlURL: *const c_char,
        servicetype: *const c_char,
        extPort: *const c_char,
        inPort: *const c_char,
        inClient: *const c_char,
        desc: *const c_char,
        proto: *const c_char,
        remoteHost: *const c_char,
        leaseDuration: *const c_char,
    ) -> c_int;

    pub fn UPNP_DeletePortMapping(
        controlURL: *const c_char,
        servicetype: *const c_char,
        extPort: *const c_char,
        proto: *const c_char,
        remoteHost: *const c_char,
    ) -> c_int;

    pub fn UPNP_GetSpecificPortMappingEntry(
        controlURL: *const c_char,
        servicetype: *const c_char,
        extPort: *const c_char,
        proto: *const c_char,
        remoteHost: *const c_char,
        intClient: *mut c_char,
        intPort: *mut c_char,
        desc: *mut c_char,
        enabled: *mut c_char,
        leaseDuration: *mut c_char,
    ) -> c_int;

    pub fn FreeUPNPUrls(urls: *mut UPNPUrls);
    pub fn freeUPNPDevlist(devlist: *mut UPNPDev);
    pub fn strupnperror(err: c_int) -> *const c_char;
    pub fn UPNPIGD_IsConnected(urls: *mut UPNPUrls, data: *mut IGDdatas) -> c_int;
}
