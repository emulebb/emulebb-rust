use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tokio::{sync::RwLock, time::Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    config::Ed2kRuntimeConfig,
    ed2k_tcp::Ed2kHelloIdentity,
    ed2k_transfer::{Ed2kSharedEntry, IndexedSharedCatalog},
};
use emulebb_kad_proto::Ed2kHash;

use super::packet_handler::{decode_id_change_payload, log_uncorrelated_server_reject};
use super::{
    Ed2kFoundSource, Ed2kServerState, OP_FOUNDSOURCES, OP_FOUNDSOURCES_OBFU, OP_IDCHANGE,
    OP_LOGINREQUEST, OP_REJECT, ResolvedServerEntry, ServerSession, ServerSessionPhase,
    ServerSessionRole, annotate_found_sources_server, configured_server_entries,
    decode_found_sources, encode_login_request, encode_source_request,
    login_identity_for_server_transport, merge_found_sources, resolve_server_entry,
    send_connected_server_startup, should_use_server_obfuscation, source_request_opcode,
    validate_found_sources,
};

/// Inputs for a one-shot ED2K source search across configured servers.
pub struct Ed2kSourceSearchOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub config: &'a Ed2kRuntimeConfig,
    pub hello_identity: Ed2kHelloIdentity,
    pub shared_catalog: &'a [Ed2kSharedEntry],
    pub preferred_endpoint: Option<SocketAddr>,
    pub excluded_endpoint: Option<SocketAddr>,
    pub max_attempts: usize,
    pub file_hash: Ed2kHash,
    pub file_size: u64,
    pub cancel: &'a CancellationToken,
}

/// Executes a one-shot ED2K server source search for one file hash and size.
///
/// The ED2K server protocol uses `OP_GETSOURCES`/`OP_FOUNDSOURCES` rather than
/// the generic search-query tree used for keyword searches, so this path stays
/// separate from `search_keyword_servers`.
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
pub async fn search_source_servers(
    options: Ed2kSourceSearchOptions<'_>,
) -> Result<Vec<Ed2kFoundSource>> {
    let Ed2kSourceSearchOptions {
        bind_ip,
        config,
        hello_identity,
        shared_catalog,
        preferred_endpoint,
        excluded_endpoint,
        max_attempts,
        file_hash,
        file_size: _file_size,
        cancel,
    } = options;
    let mut configured_servers = configured_server_entries(config)?;
    let nickname = config.server_nickname();
    if configured_servers.is_empty() {
        anyhow::bail!("ED2K source search requires at least one configured server");
    }
    if let Some(preferred_endpoint) = preferred_endpoint
        && let Some(index) = configured_servers.iter().position(|entry| {
            entry.host == preferred_endpoint.ip().to_string()
                && entry.port == preferred_endpoint.port()
        })
    {
        let preferred = configured_servers.remove(index);
        configured_servers.insert(0, preferred);
    }
    if let Some(excluded_endpoint) = excluded_endpoint {
        let before_len = configured_servers.len();
        configured_servers.retain(|entry| {
            entry.host != excluded_endpoint.ip().to_string()
                || entry.port != excluded_endpoint.port()
        });
        if configured_servers.len() != before_len {
            debug!(
                "ED2K source search skipping currently connected background endpoint={} file_hash={}",
                excluded_endpoint, file_hash
            );
        }
    }
    if configured_servers.is_empty() {
        return Ok(Vec::new());
    }

    // Low-ID servers often take around 10 seconds just to emit the warning and
    // OP_IDCHANGE on a new TCP session, so source-search sessions need a
    // longer floor than the generic connect timeout to reach GETSOURCES.
    let idle_timeout = Duration::from_secs(config.connect_timeout_secs.max(15));
    let mut last_error = None;
    let mut aggregated_results: Vec<Ed2kFoundSource> = Vec::new();

    for (attempt_index, configured_server) in configured_servers
        .into_iter()
        .take(max_attempts.max(1))
        .enumerate()
    {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }
        let resolved_server = match resolve_server_entry(&configured_server).await {
            Ok(server) => server,
            Err(error) => {
                warn!(
                    "failed to resolve ED2K source-search server {} name={}: {error}",
                    configured_server.base_endpoint_text(),
                    configured_server.display_name()
                );
                last_error = Some(error);
                continue;
            }
        };
        debug!(
            "ED2K source search attempt={}/{} endpoint={} name={} file_hash={}",
            attempt_index + 1,
            max_attempts.max(1),
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name(),
            file_hash
        );
        match search_sources_on_server(SourceSearchServerOptions {
            bind_ip,
            server: &resolved_server,
            hello_identity,
            nickname: &nickname,
            shared_catalog,
            file_hash,
            file_size: _file_size,
            idle_timeout,
            cancel,
        })
        .await
        {
            Ok(results) if !results.is_empty() => {
                merge_found_sources(&mut aggregated_results, results);
            }
            Ok(_) => continue,
            Err(error) => {
                warn!(
                    "ED2K source search failed for {} name={}: {error}",
                    resolved_server.base_endpoint(),
                    resolved_server.entry.display_name()
                );
                last_error = Some(error);
            }
        }
    }

    if !aggregated_results.is_empty() {
        return Ok(aggregated_results);
    }

    if let Some(error) = last_error {
        return Err(error);
    }
    Ok(Vec::new())
}

struct SourceSearchServerOptions<'a> {
    bind_ip: Ipv4Addr,
    server: &'a ResolvedServerEntry,
    hello_identity: Ed2kHelloIdentity,
    nickname: &'a str,
    shared_catalog: &'a [Ed2kSharedEntry],
    file_hash: Ed2kHash,
    file_size: u64,
    idle_timeout: Duration,
    cancel: &'a CancellationToken,
}

async fn search_sources_on_server(
    options: SourceSearchServerOptions<'_>,
) -> Result<Vec<Ed2kFoundSource>> {
    let SourceSearchServerOptions {
        bind_ip,
        server,
        hello_identity,
        nickname,
        shared_catalog,
        file_hash,
        file_size,
        idle_timeout,
        cancel,
    } = options;
    let use_server_obfuscation =
        should_use_server_obfuscation(hello_identity.connect_options, server);
    let login_identity =
        login_identity_for_server_transport(hello_identity, use_server_obfuscation);
    let transport_endpoint = server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        bind_ip,
        transport_endpoint,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        "active_sources",
        idle_timeout,
    )
    .await?;
    let login_payload =
        encode_login_request(login_identity, nickname, ServerSessionRole::SourceSearch);
    if use_server_obfuscation {
        session
            .negotiate_obfuscation_and_send(OP_LOGINREQUEST, &login_payload)
            .await
            .with_context(|| {
                format!(
                    "failed to negotiate ED2K server obfuscation with {}",
                    transport_endpoint
                )
            })?;
    } else {
        session.send_packet(OP_LOGINREQUEST, &login_payload).await?;
    }
    session.last_tx = Instant::now();
    let mut response_deadline = None;
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE for source search",
    );
    let active_catalog = Arc::new(RwLock::new(IndexedSharedCatalog::from_entries(
        shared_catalog.to_vec(),
    )));

    loop {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }
        let packet = if let Some(deadline) = response_deadline {
            tokio::time::timeout_at(deadline, session.read_packet()).await
        } else {
            tokio::time::timeout(idle_timeout, session.read_packet()).await
        }
        .with_context(|| {
            format!(
                "timed out waiting for ED2K server source-search reply from {transport_endpoint}"
            )
        })??;
        let Some(packet) = packet else {
            break;
        };
        match packet.opcode {
            OP_IDCHANGE => {
                let id_change = decode_id_change_payload(&packet.payload)
                    .with_context(|| format!("invalid OP_IDCHANGE from {transport_endpoint}"))?;
                session.server_flags = id_change.server_flags;
                if id_change.client_id == 0 {
                    anyhow::bail!(
                        "ED2K server {transport_endpoint} returned zero client_id in OP_IDCHANGE"
                    );
                }
                session.assigned_client_id = Some(id_change.client_id);
                // Ephemeral source-query session: never solicit the server list
                // (stock only issues OP_GETSERVERLIST from its single persistent
                // ServerConnect, and only when AddServersFromServer is set).
                send_connected_server_startup(
                    &mut session,
                    &active_catalog,
                    bind_ip,
                    hello_identity.tcp_port,
                    false,
                )
                .await?;
                session.set_phase(
                    ServerSessionPhase::SearchActive,
                    format!("dispatching source search file_hash={file_hash}"),
                );
                let source_request = encode_source_request(file_hash, file_size);
                let opcode =
                    source_request_opcode(login_identity.connect_options, session.server_flags);
                session.send_packet(opcode, &source_request).await?;
                response_deadline = Some(TokioInstant::now() + idle_timeout);
            }
            OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU => {
                let Some(response_hash) = packet
                    .payload
                    .get(..16)
                    .map(|bytes| Ed2kHash(bytes.try_into().unwrap()))
                else {
                    warn!(
                        "ignoring malformed ED2K one-shot source response from {} without a file hash; preserving request until the original deadline",
                        transport_endpoint
                    );
                    continue;
                };
                if response_hash != file_hash {
                    warn!(
                        "ignoring unmatched ED2K one-shot source response from {} expected_hash={} response_hash={} payload_len={}",
                        transport_endpoint,
                        file_hash,
                        response_hash,
                        packet.payload.len()
                    );
                    continue;
                }
                let decoded = match decode_found_sources(
                    &packet.payload,
                    packet.opcode == OP_FOUNDSOURCES_OBFU,
                ) {
                    Ok(decoded) => decoded,
                    Err(error) => {
                        warn!(
                            "ignoring malformed ED2K one-shot source response from {} for file_hash={file_hash}; preserving request until the original deadline: {error}",
                            transport_endpoint
                        );
                        continue;
                    }
                };
                if decoded.trailing_len > 0 {
                    debug!(
                        "accepted ED2K one-shot source response from {} with stock-compatible trailing bytes file_hash={} trailing_len={}",
                        transport_endpoint, file_hash, decoded.trailing_len
                    );
                }
                let results =
                    annotate_found_sources_server(decoded.sources, server.base_endpoint());
                if let Err(error) = validate_found_sources(&results, file_hash) {
                    warn!(
                        "ignoring invalid ED2K one-shot source response from {} for file_hash={file_hash}; preserving request until the original deadline: {error}",
                        transport_endpoint
                    );
                    continue;
                }
                session.set_phase(
                    ServerSessionPhase::Completed,
                    format!(
                        "completed source search file_hash={} sources={}",
                        file_hash,
                        results.len()
                    ),
                );
                return Ok(results);
            }
            OP_REJECT => {
                log_uncorrelated_server_reject(transport_endpoint, packet.payload.len());
            }
            _ => {}
        }
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_util::sync::CancellationToken;

    use super::{SourceSearchServerOptions, search_sources_on_server};

    async fn read_active_source_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], super::super::OP_EDONKEYPROT);
        let payload_len =
            u32::from_le_bytes(header[1..5].try_into().unwrap()).saturating_sub(1) as usize;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await.unwrap();
        (header[5], payload)
    }

    fn active_source_identity() -> crate::ed2k_tcp::Ed2kHelloIdentity {
        crate::ed2k_tcp::Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: 0,
            direct_udp_callback: false,
        }
    }

    fn active_source_server(endpoint: SocketAddr) -> super::super::ResolvedServerEntry {
        let SocketAddr::V4(endpoint) = endpoint else {
            panic!("test server must be IPv4");
        };
        super::super::ResolvedServerEntry {
            entry: super::super::ConfiguredServerEntry::from_endpoint_text(
                &SocketAddr::V4(endpoint).to_string(),
            )
            .unwrap(),
            ip: *endpoint.ip(),
        }
    }

    #[tokio::test]
    async fn active_source_search_ignores_reject_malformed_and_unmatched_replies() {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let file_hash = emulebb_kad_proto::Ed2kHash([0x44; 16]);
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (opcode, _) = read_active_source_frame(&mut stream).await;
            assert_eq!(opcode, super::super::OP_LOGINREQUEST);
            let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
            stream
                .write_all(
                    &super::super::encode_packet(
                        super::super::OP_IDCHANGE,
                        &high_id.to_le_bytes(),
                        false,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            loop {
                let (opcode, _) = read_active_source_frame(&mut stream).await;
                if matches!(
                    opcode,
                    super::super::OP_GETSOURCES | super::super::OP_GETSOURCES_OBFU
                ) {
                    break;
                }
            }
            let wrong_hash = emulebb_kad_proto::Ed2kHash([0x45; 16]);
            let mut found_sources = file_hash.0.to_vec();
            found_sources.push(0);
            found_sources.extend_from_slice(&[0xAA, 0xBB]);
            let mut replies =
                super::super::encode_packet(super::super::OP_REJECT, &[0x01], false).unwrap();
            replies.extend_from_slice(
                &super::super::encode_packet(super::super::OP_FOUNDSOURCES, &[0x01; 8], false)
                    .unwrap(),
            );
            replies.extend_from_slice(
                &super::super::encode_packet(super::super::OP_FOUNDSOURCES, &wrong_hash.0, false)
                    .unwrap(),
            );
            replies.extend_from_slice(
                &super::super::encode_packet(super::super::OP_FOUNDSOURCES, &file_hash.0, false)
                    .unwrap(),
            );
            replies.extend_from_slice(
                &super::super::encode_packet(super::super::OP_FOUNDSOURCES, &found_sources, false)
                    .unwrap(),
            );
            stream.write_all(&replies).await.unwrap();
        });
        let cancel = CancellationToken::new();
        let server = active_source_server(endpoint);

        let results = search_sources_on_server(SourceSearchServerOptions {
            bind_ip: crate::test_bind_ip(),
            server: &server,
            hello_identity: active_source_identity(),
            nickname: "eMule",
            shared_catalog: &[],
            file_hash,
            file_size: 123,
            idle_timeout: Duration::from_secs(1),
            cancel: &cancel,
        })
        .await
        .unwrap();

        assert!(results.is_empty());
        server_task.await.unwrap();
    }
}
