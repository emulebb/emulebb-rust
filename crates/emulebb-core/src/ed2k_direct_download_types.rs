use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use emulebb_ed2k::{
    ed2k_server::Ed2kFoundSource,
    ed2k_tcp::{Ed2kHelloIdentity, Ed2kPeerDownloadOutcome, Ed2kSecureIdent},
    ed2k_transfer::Ed2kTransferRuntime,
};

pub(crate) type DirectDownloadJoin = (SocketAddr, Ed2kFoundSource, Result<Ed2kPeerDownloadOutcome>);

#[derive(Debug)]
pub(crate) struct DirectDownloadOutcome {
    pub(crate) completed: bool,
    pub(crate) accepted_incomplete_peers: u32,
    pub(crate) last_error: Option<anyhow::Error>,
    /// Endpoints that detached their TCP socket onto the UDP reask loop. Their
    /// source leases are deliberately NOT released so the next download cycle
    /// does not re-connect them over TCP while the reask loop holds them.
    pub(crate) detached_reask_endpoints: Vec<(Ipv4Addr, u16)>,
    /// Sources that reported No Needed Parts for this file. The driver runs the
    /// A4AF-lite swap on each.
    pub(crate) no_needed_parts_sources: Vec<Ed2kFoundSource>,
}

pub(crate) struct DirectDownloadOptions {
    pub(crate) bind_ip: Ipv4Addr,
    pub(crate) hello_identity: Ed2kHelloIdentity,
    pub(crate) secure_ident: Arc<Ed2kSecureIdent>,
    pub(crate) transfer_runtime: Arc<Ed2kTransferRuntime>,
    pub(crate) file_hash_hex: String,
    pub(crate) file_name: String,
    pub(crate) file_size: u64,
    pub(crate) sources: Vec<Ed2kFoundSource>,
    pub(crate) connect_timeout: Duration,
    pub(crate) max_parallel_download_peers: usize,
}

pub(crate) struct DirectDownloadSpawnContext<'a, DownloadFn> {
    pub(crate) bind_ip: Ipv4Addr,
    pub(crate) hello_identity: Ed2kHelloIdentity,
    pub(crate) secure_ident: &'a Arc<Ed2kSecureIdent>,
    pub(crate) transfer_runtime: &'a Arc<Ed2kTransferRuntime>,
    pub(crate) file_hash_hex: &'a str,
    pub(crate) file_name: &'a str,
    pub(crate) file_size: u64,
    pub(crate) connect_timeout: Duration,
    pub(crate) retry_round: u32,
    pub(crate) download_peer: &'a DownloadFn,
}
