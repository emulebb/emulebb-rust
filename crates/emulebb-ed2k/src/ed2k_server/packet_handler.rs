use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;
use tracing::{debug, error, info, warn};

use crate::ed2k_tcp::{connect_callback_peer, enrich_hello_identity};

use super::offer_policy::{OfferFilesCapabilityAdvertisement, OfferFilesPolicy};
use super::server_description::valid_dynamic_host;
use super::server_events::Ed2kServerListEvent;
use super::tag_codec::{DecodedTag, DecodedTagName, DecodedTagValue, decode_tag_details};
use super::types::{CallbackRequest, ServerSessionContext};
use super::{
    Ed2kPacket, Ed2kServerFailure, OP_CALLBACK_FAIL, OP_CALLBACKREQUESTED, OP_IDCHANGE,
    OP_OFFERFILES, OP_QUERY_MORE_RESULT, OP_REJECT, OP_SEARCHREQUEST, OP_SEARCHRESULT,
    OP_SERVERIDENT, OP_SERVERLIST, OP_SERVERMESSAGE, OP_SERVERSTATUS, ST_DESCRIPTION, ST_HARDFILES,
    ST_SERVERNAME, ST_SOFTFILES, ServerSession, ServerSessionPhase, TAGTYPE_UINT32,
    decode_ed2k_string, decode_search_result_page, decode_server_list, encode_search_request,
    format_connect_options, format_server_flags, ipv4_from_client_id, is_low_id,
    log_search_result_page, send_connected_server_startup, wait_for_offer_files_settle,
};

#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
pub(super) async fn handle_server_packet(
    session: &mut ServerSession,
    packet: Ed2kPacket,
    context: &ServerSessionContext,
    allow_probe_search: bool,
) -> Result<()> {
    match packet.opcode {
        OP_IDCHANGE => {
            let id_change = decode_id_change_payload(&packet.payload)?;
            if id_change.client_id == 0 {
                context
                    .last_client_id
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                {
                    let mut guard = session.state.write().await;
                    guard.connecting = false;
                    guard.connected = false;
                    guard.client_id = None;
                    guard.server_flags = id_change.server_flags;
                }
                session.assigned_client_id = None;
                session.server_flags = id_change.server_flags;
                session.login_accepted = false;
                // No public IP without a client id (eMule SetPublicIP(0)).
                context.public_ip.clear();
                info!(
                    "ED2K server {} returned zero client_id in OP_IDCHANGE; login not accepted",
                    session.endpoint
                );
                return Ok(());
            }
            {
                let mut guard = session.state.write().await;
                guard.connecting = false;
                guard.connected = true;
                guard.client_id = Some(id_change.client_id);
                guard.server_flags = id_change.server_flags;
            }
            info!(
                "ED2K server assigned client_id={} high_id={} server_flags={} reported_client_ip={}",
                id_change.client_id,
                !is_low_id(id_change.client_id),
                format_server_flags(id_change.server_flags.unwrap_or_default()),
                id_change
                    .reported_client_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            session.assigned_client_id = Some(id_change.client_id);
            context
                .last_client_id
                .store(id_change.client_id, std::sync::atomic::Ordering::Relaxed);
            session.server_flags = id_change.server_flags;
            session.login_accepted = true;
            // eMule `CServerList::ServerStats`: a successful connect resets the
            // server's fail-count. Report the login so the core clears it.
            if let Some(sender) = context.server_list_events.as_ref() {
                let _ = sender.send(Ed2kServerListEvent::ConnectSucceeded {
                    endpoint: session.endpoint.to_string(),
                });
            }
            // Learn our public IP exactly as eMule does (theApp.SetPublicIP).
            // HighID: the OP_IDCHANGE client_id IS our public IPv4. LowID: we are
            // firewalled, but the server may still report our real external IP
            // (ServerSocket.cpp: `if IsLowID(clientid) && reportedIP != 0
            // SetPublicIP(reportedIP)`), used only when it is itself non-LowID.
            if is_low_id(id_change.client_id) {
                match id_change
                    .reported_client_ip
                    .filter(|ip| !is_low_id(u32::from_le_bytes(ip.octets())))
                {
                    Some(reported_ip) => context.public_ip.set(reported_ip),
                    None => context.public_ip.clear(),
                }
            } else {
                context
                    .public_ip
                    .set(ipv4_from_client_id(id_change.client_id));
            }
            send_connected_server_startup(
                session,
                &context.shared_catalog,
                context.bind_ip,
                context.hello_identity.tcp_port,
                context.add_servers_from_server,
            )
            .await?;
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SEARCHRESULT => {
            let page = decode_search_result_page(&packet.payload)?;
            log_search_result_page(session.endpoint, &page.files);
            if page.more_results_available {
                session.set_phase(
                    ServerSessionPhase::AwaitingMore,
                    "probe search reported more results; requesting another page",
                );
                session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
            } else if session.probe_search_sent {
                session.set_phase(
                    ServerSessionPhase::Completed,
                    "probe search completed without additional pages",
                );
            }
        }
        OP_SERVERSTATUS => {
            if packet.payload.len() >= 8 {
                let users = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
                let files = u32::from_le_bytes(packet.payload[4..8].try_into().unwrap());
                {
                    let mut guard = session.state.write().await;
                    guard.server_users = Some(users);
                    guard.server_files = Some(files);
                }
                info!(
                    "ED2K server status from {}: users={} files={}",
                    session.endpoint, users, files
                );
            }
        }
        OP_SERVERIDENT => {
            let ident = decode_server_ident_details(&packet.payload)?;
            {
                let mut guard = session.state.write().await;
                if let Some(name) = &ident.name {
                    guard.server_name = Some(name.clone());
                }
                if let Some(description) = &ident.description {
                    guard.server_description = Some(description.clone());
                }
            }
            session
                .observe_offer_files_capability(ident.offer_files_capability.clone())
                .await;
            debug!(
                "ED2K server ident from {}: name={} description={} offer_files_capability={:?}",
                session.endpoint,
                ident.name.as_deref().unwrap_or("-"),
                ident.description.as_deref().unwrap_or("-"),
                ident.offer_files_capability,
            );
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SERVERLIST => {
            // Decode the `(ip, port)` server entries and report them to the core
            // for merge+dedup into the server list (eMule
            // `CServerSocket::ProcessPacket` OP_SERVERLIST -> AddServer, gated by
            // `GetAddServersFromServer`). The core owns the persisted store and
            // the "add servers from server" preference.
            let discovered = decode_server_list(&packet.payload);
            debug!(
                "ED2K server {} returned {} server list entries ({} usable)",
                session.endpoint,
                packet.payload.first().copied().unwrap_or_default(),
                discovered.len()
            );
            // eMule accepts servers from OP_SERVERLIST only when
            // `GetAddServersFromServer()` is set (the same preference that gates
            // the OP_GETSERVERLIST request). With the stock default (false) an
            // unsolicited OP_SERVERLIST reply is decoded for logging but never
            // merged into the local server list.
            if context.add_servers_from_server
                && !discovered.is_empty()
                && let Some(sender) = context.server_list_events.as_ref()
            {
                let _ = sender.send(Ed2kServerListEvent::DiscoveredServers(discovered));
            }
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SERVERMESSAGE => {
            if let Some(message) = decode_ed2k_string(&packet.payload)? {
                let decoded = decode_server_message(&message);
                for line in &decoded.lines {
                    match line.kind {
                        ServerMessageLineKind::Error => {
                            error!("ED2K server error from {}: {}", session.endpoint, line.text);
                        }
                        ServerMessageLineKind::Warning => {
                            warn!(
                                "ED2K server warning from {}: {}",
                                session.endpoint, line.text
                            );
                        }
                        ServerMessageLineKind::Information => {
                            info!(
                                "ED2K server message from {}: {}",
                                session.endpoint, line.text
                            );
                        }
                    }
                }
                if decoded.version.is_some() || decoded.dynamic_host.is_some() {
                    {
                        let mut guard = session.state.write().await;
                        if let Some(version) = decoded.version.as_ref() {
                            guard.server_version = Some(version.clone());
                        }
                        if let Some(dynamic_host) = decoded.dynamic_host.as_ref() {
                            guard.server_dynamic_host = Some(dynamic_host.clone());
                        }
                    }
                    if let Some(sender) = context.server_list_events.as_ref() {
                        let _ = sender.send(Ed2kServerListEvent::MetadataUpdated {
                            endpoint: session.endpoint.to_string(),
                            name: None,
                            description: None,
                            dynamic_host: decoded.dynamic_host,
                            version: decoded.version,
                            auxiliary_ports: Vec::new(),
                        });
                    }
                }
            }
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_CALLBACKREQUESTED => {
            if let Some(callback) = decode_callback_request(&packet.payload)? {
                info!(
                    "ED2K server requested callback from peer {} transport_hint={} payload_len={}",
                    callback.peer_addr,
                    callback
                        .connect_options
                        .map(format_connect_options)
                        .unwrap_or_else(|| "plaintext".to_string()),
                    packet.payload.len()
                );
                let bind_ip = context.bind_ip;
                let hello_identity = enrich_hello_identity(
                    context.hello_identity,
                    &context.state,
                    &context.kad_firewall,
                )
                .await;
                let connect_timeout = context.connect_timeout;
                tokio::spawn(async move {
                    match connect_callback_peer(
                        bind_ip,
                        callback.peer_addr,
                        hello_identity,
                        callback.user_hash,
                        callback.connect_options,
                        connect_timeout,
                    )
                    .await
                    {
                        Ok(mode) => {
                            info!(
                                "ED2K callback peer connect completed peer={} transport={}",
                                callback.peer_addr,
                                mode.as_str()
                            );
                        }
                        Err(error) => {
                            debug!(
                                "ED2K callback peer connect failed peer={}: {error}",
                                callback.peer_addr
                            );
                        }
                    }
                });
            }
        }
        OP_CALLBACK_FAIL => {
            debug!(
                "ED2K server callback failed notification from {}",
                session.endpoint
            );
        }
        OP_REJECT => {
            if session.last_tx_opcode == Some(OP_OFFERFILES) && session.offer_files_negotiated() {
                warn!(
                    "ED2K server {} rejected a negotiated OP_OFFERFILES batch; locking this connection to legacy pacing",
                    session.endpoint
                );
                session
                    .fallback_offer_files_to_legacy("server rejected negotiated OP_OFFERFILES")
                    .await;
                return Ok(());
            }
            return Err(Ed2kServerFailure::protocol_rejection(format!(
                "ED2K server {} rejected the last command",
                session.endpoint
            ))
            .into());
        }
        opcode => {
            debug!(
                "ignoring unsupported ED2K server opcode=0x{:02X} from {} payload_len={}",
                opcode,
                session.endpoint,
                packet.payload.len()
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerMessageLineKind {
    Information,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerMessageLine {
    kind: ServerMessageLineKind,
    text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DecodedServerMessage {
    lines: Vec<ServerMessageLine>,
    version: Option<String>,
    dynamic_host: Option<String>,
}

fn decode_server_message(message: &str) -> DecodedServerMessage {
    const VERSION_PREFIX: &str = "server version";
    const DYNAMIC_IP_PREFIX: &str = "[emDynIP: ";

    let mut decoded = DecodedServerMessage::default();
    for line in message
        .split(['\r', '\n'])
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let kind = if line.starts_with("ERROR") {
            ServerMessageLineKind::Error
        } else if line.starts_with("WARNING") {
            ServerMessageLineKind::Warning
        } else {
            ServerMessageLineKind::Information
        };
        let text = match kind {
            ServerMessageLineKind::Error => line["ERROR".len()..]
                .trim_start_matches([':', ' '])
                .to_string(),
            ServerMessageLineKind::Warning => line["WARNING".len()..]
                .trim_start_matches([':', ' '])
                .to_string(),
            ServerMessageLineKind::Information => line.to_string(),
        };
        decoded.lines.push(ServerMessageLine { kind, text });

        if line.len() >= VERSION_PREFIX.len()
            && line[..VERSION_PREFIX.len()].eq_ignore_ascii_case(VERSION_PREFIX)
        {
            let version = line[VERSION_PREFIX.len()..]
                .trim_start_matches([':', ' '])
                .trim();
            if !version.is_empty() {
                decoded.version = Some(version.to_string());
            }
        }

        if let Some(start) = line.find(DYNAMIC_IP_PREFIX) {
            let value_start = start + DYNAMIC_IP_PREFIX.len();
            if let Some(relative_end) = line[value_start..].find(']') {
                let value = &line[value_start..value_start + relative_end];
                if let Some(dynamic_host) = valid_dynamic_host(value) {
                    decoded.dynamic_host = Some(dynamic_host);
                }
            }
        }
    }
    decoded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IdChangePayload {
    pub(super) client_id: u32,
    pub(super) server_flags: Option<u32>,
    pub(super) reported_client_ip: Option<Ipv4Addr>,
}

pub(super) fn decode_id_change_payload(payload: &[u8]) -> Result<IdChangePayload> {
    if payload.len() < 4 {
        anyhow::bail!("short OP_IDCHANGE payload");
    }
    let client_id = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let server_flags =
        (payload.len() >= 8).then(|| u32::from_le_bytes(payload[4..8].try_into().unwrap()));
    let reported_client_ip = (payload.len() >= 16)
        .then(|| u32::from_le_bytes(payload[12..16].try_into().unwrap()))
        .filter(|client_id| !is_low_id(*client_id))
        .map(ipv4_from_client_id);

    Ok(IdChangePayload {
        client_id,
        server_flags,
        reported_client_ip,
    })
}

async fn maybe_send_probe_search(
    session: &mut ServerSession,
    context: &ServerSessionContext,
) -> Result<()> {
    if !session.login_accepted || session.probe_search_sent {
        return Ok(());
    }
    let Some(term) = context.probe_search_term.as_deref() else {
        return Ok(());
    };
    let search_payload = encode_search_request(term)?;
    if search_payload.is_empty() {
        return Ok(());
    }
    wait_for_offer_files_settle(session).await;
    session.set_phase(
        ServerSessionPhase::SearchActive,
        format!("dispatching probe keyword search term={term:?}"),
    );
    session
        .send_packet(OP_SEARCHREQUEST, &search_payload)
        .await?;
    session.probe_search_sent = true;
    info!(
        "sent ED2K server search probe term={term:?} endpoint={}",
        session.endpoint
    );
    Ok(())
}

pub(super) fn decode_callback_request(payload: &[u8]) -> Result<Option<CallbackRequest>> {
    if payload.len() < 6 {
        return Ok(None);
    }
    let ip = ipv4_from_client_id(u32::from_le_bytes(payload[..4].try_into().unwrap()));
    let port = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let has_crypt_profile = payload.len() >= 23;
    let connect_options = has_crypt_profile.then(|| payload[6]);
    let user_hash = has_crypt_profile.then(|| {
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&payload[7..23]);
        hash
    });
    Ok(Some(CallbackRequest {
        peer_addr: SocketAddr::new(IpAddr::V4(ip), port),
        connect_options,
        user_hash,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DecodedServerIdent {
    pub(super) name: Option<String>,
    pub(super) description: Option<String>,
    pub(super) offer_files_capability: OfferFilesCapabilityAdvertisement,
}

fn exact_u32_tag(tag: &DecodedTag) -> Option<u32> {
    if tag.base_type != TAGTYPE_UINT32 {
        return None;
    }
    match tag.value {
        Some(DecodedTagValue::Unsigned(value)) => u32::try_from(value).ok(),
        _ => None,
    }
}

fn set_capability_value(
    slot: &mut Option<u32>,
    tag: &DecodedTag,
    label: &str,
    errors: &mut Vec<String>,
) {
    if slot.is_some() {
        errors.push(format!("duplicate {label}"));
        return;
    }
    match exact_u32_tag(tag) {
        Some(value) => *slot = Some(value),
        None => errors.push(format!("{label} is not TAGTYPE_UINT32")),
    }
}

pub(super) fn decode_server_ident_details(payload: &[u8]) -> Result<DecodedServerIdent> {
    if payload.len() < 26 {
        return Ok(DecodedServerIdent {
            name: None,
            description: None,
            offer_files_capability: OfferFilesCapabilityAdvertisement::Absent,
        });
    }
    let tag_count = u32::from_le_bytes(payload[22..26].try_into().unwrap());
    let mut cursor = &payload[26..];
    let mut name = None;
    let mut description = None;
    let mut capability_seen = false;
    let mut capability_errors = Vec::new();
    let mut version = None;
    let mut batch_max = None;
    let mut min_interval_ms = None;
    let mut soft_files = None;
    let mut hard_files = None;
    for _ in 0..tag_count {
        let (tag, rest) = decode_tag_details(cursor)?;
        cursor = rest;
        match &tag.name {
            DecodedTagName::Numeric(ST_SERVERNAME) => {
                if let Some(DecodedTagValue::String(value)) = tag.value {
                    name = Some(value);
                }
            }
            DecodedTagName::Numeric(ST_DESCRIPTION) => {
                if let Some(DecodedTagValue::String(value)) = tag.value {
                    description = Some(value);
                }
            }
            DecodedTagName::Numeric(ST_SOFTFILES) => set_capability_value(
                &mut soft_files,
                &tag,
                "ST_SOFTFILES",
                &mut capability_errors,
            ),
            DecodedTagName::Numeric(ST_HARDFILES) => set_capability_value(
                &mut hard_files,
                &tag,
                "ST_HARDFILES",
                &mut capability_errors,
            ),
            DecodedTagName::Text(tag_name) if tag_name == "offerfiles_v" => {
                capability_seen = true;
                set_capability_value(&mut version, &tag, "offerfiles_v", &mut capability_errors);
            }
            DecodedTagName::Text(tag_name) if tag_name == "offerfiles_batch_max" => {
                capability_seen = true;
                set_capability_value(
                    &mut batch_max,
                    &tag,
                    "offerfiles_batch_max",
                    &mut capability_errors,
                );
            }
            DecodedTagName::Text(tag_name) if tag_name == "offerfiles_min_interval_ms" => {
                capability_seen = true;
                set_capability_value(
                    &mut min_interval_ms,
                    &tag,
                    "offerfiles_min_interval_ms",
                    &mut capability_errors,
                );
            }
            _ => {}
        }
    }
    let offer_files_capability = if !capability_seen {
        OfferFilesCapabilityAdvertisement::Absent
    } else if !capability_errors.is_empty() {
        OfferFilesCapabilityAdvertisement::Invalid(capability_errors.join("; "))
    } else {
        match (version, batch_max, min_interval_ms, soft_files, hard_files) {
            (Some(version), Some(batch_max), Some(min_interval_ms), Some(soft), Some(hard)) => {
                match OfferFilesPolicy::validate(version, batch_max, min_interval_ms, soft, hard) {
                    Ok(policy) => OfferFilesCapabilityAdvertisement::Supported(policy),
                    Err(error) => OfferFilesCapabilityAdvertisement::Invalid(error.to_string()),
                }
            }
            _ => OfferFilesCapabilityAdvertisement::Invalid(
                "offerfiles_v capability is incomplete".to_string(),
            ),
        }
    };
    Ok(DecodedServerIdent {
        name,
        description,
        offer_files_capability,
    })
}

pub(super) fn decode_server_ident(payload: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let ident = decode_server_ident_details(payload)?;
    Ok((ident.name, ident.description))
}

#[cfg(test)]
mod server_message_tests {
    use super::*;

    #[test]
    fn decodes_stock_server_message_semantics() {
        let decoded = decode_server_message(
            "Server Version: 17.6\r\nWARNING: maintenance soon\nhello [emDynIP: srv.example]\rERROR bad request",
        );
        assert_eq!(decoded.version.as_deref(), Some("17.6"));
        assert_eq!(decoded.dynamic_host.as_deref(), Some("srv.example"));
        assert_eq!(decoded.lines.len(), 4);
        assert_eq!(decoded.lines[1].kind, ServerMessageLineKind::Warning);
        assert_eq!(decoded.lines[1].text, "maintenance soon");
        assert_eq!(decoded.lines[3].kind, ServerMessageLineKind::Error);
        assert_eq!(decoded.lines[3].text, "bad request");
    }

    #[test]
    fn version_prefix_is_case_insensitive_and_ipv4_dynip_is_rejected() {
        let decoded = decode_server_message(
            "SERVER VERSION 18.01\n[emDynIP: 192.0.2.8]\nwarning stays informational",
        );
        assert_eq!(decoded.version.as_deref(), Some("18.01"));
        assert_eq!(decoded.dynamic_host, None);
        assert_eq!(decoded.lines[2].kind, ServerMessageLineKind::Information);
    }
}
