use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use tokio::sync::{Mutex, RwLock};

use crate::NatManager;
use emulebb_kad_proto::Ed2kHash;

use crate::{
    config::Ed2kRuntimeConfig, ed2k_tcp::Ed2kHelloIdentity, ed2k_transfer::Ed2kSharedCatalog,
    kad_firewall::KadFirewallState,
};

use super::server_events::Ed2kServerListEventSender;
use super::{Ed2kServerSearchInbox, is_low_id};
/// Live ED2K server session view used by the Rust client to decide whether TCP is
/// still effectively firewalled from the network's point of view.
#[derive(Debug, Clone, Default)]
pub struct Ed2kServerState {
    /// Currently connected server endpoint, if any.
    pub endpoint: Option<SocketAddr>,
    /// Server-assigned client ID from `OP_IDCHANGE`.
    pub client_id: Option<u32>,
    /// Last reported TCP capability flags from the server.
    pub server_flags: Option<u32>,
    /// Last reported server user count.
    pub server_users: Option<u32>,
    /// Last reported server file count.
    pub server_files: Option<u32>,
    /// Last reported live UDP capability flags from `OP_GLOBSERVSTATRES`
    /// (offset 24); refreshed each time a challenge-validated status reply
    /// includes them (eMule `CServer::SetUDPFlags`).
    pub server_udp_flags: Option<u32>,
    /// Last advertised server name, when known.
    pub server_name: Option<String>,
    /// Last advertised server description, when known.
    pub server_description: Option<String>,
    /// Whether a server TCP connection attempt is in progress.
    pub connecting: bool,
    /// Whether the current session is established.
    pub connected: bool,
}

impl Ed2kServerState {
    /// Returns whether the oracle-style HighID/LowID result says TCP is firewalled.
    #[must_use]
    pub fn tcp_firewalled(&self) -> Option<bool> {
        self.client_id.map(is_low_id)
    }
}

#[derive(Clone)]
pub(super) struct ServerSessionContext {
    pub(super) bind_ip: Ipv4Addr,
    pub(super) nat: Arc<NatManager>,
    pub(super) hello_identity: Ed2kHelloIdentity,
    pub(super) probe_search_term: Option<String>,
    pub(super) shared_catalog: Ed2kSharedCatalog,
    pub(super) state: Arc<RwLock<Ed2kServerState>>,
    pub(super) kad_firewall: Arc<Mutex<KadFirewallState>>,
    /// Idle TCP keepalive interval (empty OP_OFFERFILES ping). `None` disables
    /// the keepalive entirely, mirroring eMule's `ServerKeepAliveTimeout == 0`
    /// (ServerConnect.cpp:672-674). When enabled it is a minutes-scale value.
    pub(super) keepalive_interval: Option<Duration>,
    pub(super) connect_timeout: Duration,
    pub(super) rotation_interval: Option<Duration>,
    pub(super) shutdown: Arc<AtomicBool>,
    /// Learned public IP (eMule `theApp.SetPublicIP`): set from the HighID
    /// `OP_IDCHANGE` client_id, cleared on disconnect/LowID.
    pub(super) public_ip: crate::reachability::ExternalReachability,
    /// "Reconnect now" signal: notified when the advertised external port changes
    /// (UPnP became ready / was remapped) so the session drops and re-logs in with
    /// the new HighID callback port instead of waiting for a natural reconnect.
    pub(super) reconnect_signal: Arc<tokio::sync::Notify>,
    /// Optional feedback channel to the core's server store for discovered
    /// servers (`OP_SERVERLIST`) and connect/ping outcomes (fail-count / dead
    /// server drop). `None` when the loop is run without a core store wired.
    pub(super) server_list_events: Option<Ed2kServerListEventSender>,
    /// eMule `thePrefs.GetAddServersFromServer()` (default false): gates sending
    /// OP_GETSERVERLIST on connect and accepting servers from OP_SERVERLIST.
    pub(super) add_servers_from_server: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CallbackRequest {
    pub(super) peer_addr: SocketAddr,
    pub(super) connect_options: Option<u8>,
    pub(super) user_hash: Option<[u8; 16]>,
}

#[derive(Debug)]
pub(super) struct ServerUdpPacket {
    pub(super) opcode: u8,
    pub(super) payload: Vec<u8>,
    pub(super) from: SocketAddr,
}

/// One decoded ED2K server search result entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kSearchFile {
    /// File hash reported by the ED2K server.
    pub file_hash: Ed2kHash,
    /// File name tag, when present.
    pub file_name: Option<String>,
    /// File size tag, when present.
    pub file_size: Option<u64>,
    /// ED2K file-type tag, when present.
    pub file_type: Option<String>,
    /// Server-reported source availability, when present.
    pub source_count: Option<u32>,
}

/// One decoded ED2K server source-search entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kFoundSource {
    /// File hash referenced by the source reply.
    pub file_hash: Ed2kHash,
    /// Source IPv4 address reported by the ED2K server when the source is a
    /// direct-dial HighID peer. For LowID peers this is the server-reported
    /// client-id rendered as IPv4, which is not directly dialable.
    pub ip: Ipv4Addr,
    /// Source TCP port reported by the ED2K server.
    pub tcp_port: u16,
    /// Raw client-id token reported by the ED2K server.
    pub client_id: u32,
    /// Whether the server source entry refers to a LowID peer that requires a
    /// callback path instead of direct TCP dialing.
    pub low_id: bool,
    /// Whether the server used the obfuscated `OP_FOUNDSOURCES_OBFU` family.
    pub obfuscated: bool,
    /// Optional per-source obfuscation settings byte from the oracle wire shape.
    pub obfuscation_options: Option<u8>,
    /// Optional user hash present when the source advertises it in the obfuscated shape.
    pub user_hash: Option<[u8; 16]>,
    /// ED2K server endpoint that reported this source, when known.
    pub source_server: Option<SocketAddr>,
    /// Buddy Kad-id of a firewalled LowID Kad source (oracle `SetBuddyID`), present
    /// only for Kad source types 3/5. Gates buddy-relayed `OP_REASKCALLBACKUDP`.
    pub buddy_id: Option<[u8; 16]>,
    /// Buddy relay UDP endpoint of a firewalled LowID Kad source (oracle
    /// `SetBuddyIP`/`SetBuddyPort`), present only for Kad source types 3/5.
    pub buddy_endpoint: Option<(Ipv4Addr, u16)>,
    /// Source's own eD2k UDP port from a Kad source result (`FT_SOURCEUPORT`).
    /// For a firewalled buddy source this is the endpoint the source UDP-answers
    /// the downloader from after the buddy relays our callback, so it keys the
    /// reask pending gate. `None` for server sources (no Kad UDP port).
    pub source_udp_port: Option<u16>,
}

impl Ed2kFoundSource {
    /// Returns `true` when this source can be dialed directly over TCP.
    #[must_use]
    pub fn is_direct_dialable(&self) -> bool {
        const EMULE_CRYPT_REQUIRES: u8 = 0x04;
        if self.low_id {
            return false;
        }
        !self
            .obfuscation_options
            .is_some_and(|options| options & EMULE_CRYPT_REQUIRES != 0 && self.user_hash.is_none())
    }

    /// Returns `true` when this is a firewalled LowID Kad source whose Kad buddy
    /// (id + relay endpoint) is known, so it can be reasked via its buddy with an
    /// `OP_REASKCALLBACKUDP` instead of being direct-dialed (oracle Kad source
    /// types 3/5).
    #[must_use]
    pub fn has_kad_buddy_reask_target(&self) -> bool {
        self.low_id && self.buddy_id.is_some() && self.buddy_endpoint.is_some()
    }

    /// Returns `true` when this is a firewalled Kad source reachable only via a
    /// direct UDP callback (oracle Kad source type 6): firewalled, no buddy,
    /// direct-callback connect-options bit set, and a known Kad UDP endpoint to
    /// send `OP_DIRECTCALLBACKREQ` to.
    #[must_use]
    pub fn is_direct_callback_source(&self) -> bool {
        self.low_id
            && self.buddy_id.is_none()
            && self.source_udp_port.is_some()
            && self
                .obfuscation_options
                .is_some_and(|options| options & 0x08 != 0)
    }
}

/// Inputs for the long-lived ED2K server session loop.
pub struct Ed2kServerLoopOptions {
    pub bind_ip: Ipv4Addr,
    pub nat: Arc<NatManager>,
    pub config: Ed2kRuntimeConfig,
    pub hello_identity: Ed2kHelloIdentity,
    pub shared_catalog: Ed2kSharedCatalog,
    pub state: Arc<RwLock<Ed2kServerState>>,
    pub search_inbox: Ed2kServerSearchInbox,
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub shutdown: Arc<AtomicBool>,
    /// Learned public-IP cell (eMule `theApp` public IP), set from the HighID
    /// `OP_IDCHANGE`. Created by core and shared with the UDP reask loop.
    pub public_ip: crate::reachability::ExternalReachability,
    /// "Reconnect now" signal (shared with the advertised-ports sync task): fired
    /// when the external port changes so the session re-logs in promptly.
    pub reconnect_signal: Arc<tokio::sync::Notify>,
    /// Optional explicit REST/UI target for the next server connection attempt.
    pub target_server_endpoint: Arc<RwLock<Option<String>>>,
    /// Optional feedback channel to the core's server store (server discovery +
    /// connect/ping outcome). `None` disables server-list feedback.
    pub server_list_events: Option<Ed2kServerListEventSender>,
}
