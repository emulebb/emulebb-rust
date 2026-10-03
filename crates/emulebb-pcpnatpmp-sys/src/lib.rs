#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_void};

pub const ENABLE_AUTODISCOVERY: u8 = 1;
pub const DISABLE_AUTODISCOVERY: u8 = 0;
pub const PCP_MAX_SUPPORTED_VERSION: u8 = 2;
pub const PCP_ERR_ROUTE_MISMATCH: c_int = -15;

pub const PCP_STATE_PROCESSING: c_int = 0;
pub const PCP_STATE_SUCCEEDED: c_int = 1;
pub const PCP_STATE_PARTIAL_RESULT: c_int = 2;
pub const PCP_STATE_SHORT_LIFETIME_ERROR: c_int = 3;
pub const PCP_STATE_FAILED: c_int = 4;

#[repr(C)]
pub struct pcp_ctx_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct pcp_flow_t {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in {
    // Darwin/BSD place an 8-bit length before the 8-bit address family.
    // Linux and Windows expose the family as one 16-bit field instead.
    #[cfg(target_vendor = "apple")]
    pub sin_len: u8,
    #[cfg(target_vendor = "apple")]
    pub sin_family: u8,
    #[cfg(not(target_vendor = "apple"))]
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

// Windows' IN6_ADDR is aligned to USHORT (2); POSIX in6_addr is aligned to
// uint32_t (4). The distinction affects every later pcp_flow_info_t field.
#[cfg_attr(windows, repr(C, align(2)))]
#[cfg_attr(not(windows), repr(C, align(4)))]
#[derive(Clone, Copy)]
pub struct in6_addr {
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct pcp_flow_info_t {
    pub result: c_int,
    pub pcp_server_ip: in6_addr,
    pub ext_ip: in6_addr,
    pub ext_port: u16,
    pub recv_lifetime_end: i64,
    pub lifetime_renew_s: i64,
    pub pcp_result_code: u8,
    pub int_ip: in6_addr,
    pub int_port: u16,
    pub int_scope_id: u32,
    pub dst_ip: in6_addr,
    pub dst_port: u16,
    pub protocol: u8,
    pub learned_dscp: u8,
    pub pcp_version: u8,
}

unsafe extern "C" {
    pub fn pcp_init_for_source(
        autodiscovery: u8,
        socket_vt: *mut c_void,
        source_addr: *mut c_void,
    ) -> *mut pcp_ctx_t;
    pub fn pcp_add_server_for_source(
        ctx: *mut pcp_ctx_t,
        pcp_server: *mut c_void,
        pcp_version: u8,
        source_addr: *mut c_void,
    ) -> c_int;
    pub fn pcp_terminate(ctx: *mut pcp_ctx_t, close_flows: c_int);
    pub fn pcp_new_flow(
        ctx: *mut pcp_ctx_t,
        src_addr: *mut c_void,
        dst_addr: *mut c_void,
        ext_addr: *mut c_void,
        protocol: u8,
        lifetime: u32,
        userdata: *mut c_void,
    ) -> *mut pcp_flow_t;
    pub fn pcp_flow_set_lifetime(flow: *mut pcp_flow_t, lifetime: u32);
    pub fn pcp_wait(
        flow: *mut pcp_flow_t,
        timeout_ms: c_int,
        exit_on_partial_result: c_int,
    ) -> c_int;
    pub fn pcp_flow_get_info(flow: *mut pcp_flow_t, info_count: *mut usize)
    -> *mut pcp_flow_info_t;
    pub fn pcp_free_flow_info(flow_info: *mut pcp_flow_info_t);
    pub fn pcp_close_flow(flow: *mut pcp_flow_t);
    pub fn pcp_delete_flow(flow: *mut pcp_flow_t);

    #[cfg(windows)]
    pub fn pcp_win_sock_startup() -> c_int;
}
