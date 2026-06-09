use std::sync::Arc;

use anyhow::Result;
use tokio::{sync::RwLock, time::Instant as TokioInstant};
use tracing::{debug, info, warn};

use super::types::{ServerSessionContext, ServerUdpPacket};
use super::udp_runtime::{
    bind_server_udp_socket, read_server_udp_packet, send_server_udp_status_request,
};
use super::{
    BackgroundServerSearchRequest, Ed2kServerSearchInbox, Ed2kServerState, OP_FOUNDSOURCES,
    OP_FOUNDSOURCES_OBFU, OP_LOGINREQUEST, OP_OFFERFILES, OP_QUERY_MORE_RESULT, OP_SEARCHRESULT,
    PendingBackgroundServerSearch, ResolvedServerEntry, ServerSession, ServerSessionPhase,
    annotate_found_sources_server, decode_found_sources, decode_search_result_page,
    encode_login_request, encode_packet, fail_background_search_request,
    fail_pending_background_search, format_connect_options, handle_background_udp_packet,
    handle_server_packet, log_search_result_page, login_identity_for_server_transport,
    send_offer_files_advertisement, server_udp_endpoint, should_use_server_obfuscation,
    start_background_server_search, validate_found_sources,
};

pub(super) async fn run_one_server_session(
    server: &ResolvedServerEntry,
    context: &ServerSessionContext,
    search_inbox: &mut Ed2kServerSearchInbox,
) -> Result<()> {
    let use_server_obfuscation =
        should_use_server_obfuscation(context.hello_identity.connect_options, server);
    let login_identity =
        login_identity_for_server_transport(context.hello_identity, use_server_obfuscation);
    let transport_endpoint = server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        context.bind_ip,
        transport_endpoint,
        Arc::clone(&context.state),
        "background",
        context.connect_timeout,
    )
    .await?;
    let server_udp_socket = match bind_server_udp_socket(context.bind_ip).await {
        Ok(socket) => {
            info!(
                "bound ED2K server UDP helper local={} remote={} trace_id={}",
                socket.local_addr()?,
                server_udp_endpoint(server),
                session.trace_id
            );
            Some(socket)
        }
        Err(error) => {
            warn!(
                "failed to bind ED2K server UDP helper for {}: {error}",
                server.base_endpoint()
            );
            None
        }
    };
    {
        let mut guard = context.state.write().await;
        guard.endpoint = Some(server.base_endpoint());
        guard.connected = false;
        guard.client_id = None;
        guard.server_flags = None;
    }

    let nat_status = context.nat.status().await;
    let observed_external_ip = nat_status.observed_external_addresses.first().cloned();
    let login_payload = encode_login_request(login_identity);
    info!(
        "connected to ED2K server {} name={} trace_id={} role=background bind_ip={} observed_external_ip={} transport={} connect_options={} supports_obf_tcp={} obf_port={} udp_flags=0x{:08X} udp_key_present={} chosen_port={}",
        server.base_endpoint(),
        server.entry.display_name(),
        session.trace_id,
        context.bind_ip,
        observed_external_ip.as_deref().unwrap_or("unknown"),
        if use_server_obfuscation {
            "obfuscated"
        } else {
            "plaintext"
        },
        format_connect_options(login_identity.connect_options),
        server.entry.supports_obfuscation_tcp(),
        server.entry.obfuscation_port_tcp,
        server.entry.udp_flags,
        server.entry.udp_key != 0,
        transport_endpoint.port(),
    );
    if use_server_obfuscation {
        let login_request = encode_packet(OP_LOGINREQUEST, &login_payload, false)?;
        session
            .negotiate_obfuscation_and_send(&login_request)
            .await?;
    } else {
        session.send_packet(OP_LOGINREQUEST, &login_payload).await?;
    }
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE",
    );

    let rotation_deadline = context
        .rotation_interval
        .map(|interval| TokioInstant::now() + interval);
    let mut queued_background_search = None;
    let mut pending_background_search = None;

    loop {
        if context.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            fail_background_search_request(
                &mut queued_background_search,
                "ED2K background session is shutting down before search dispatch",
            );
            fail_pending_background_search(
                &mut pending_background_search,
                "ED2K background session is shutting down before search completion",
            );
            clear_server_connection_state(&context.state).await;
            return Ok(());
        }

        tokio::select! {
            _ = async {
                if let Some(deadline) = rotation_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if queued_background_search.is_none() && pending_background_search.is_none() => {
                fail_background_search_request(
                    &mut queued_background_search,
                    "ED2K background session rotated before search dispatch",
                );
                fail_pending_background_search(
                    &mut pending_background_search,
                    "ED2K background session rotated before search completion",
                );
                info!(
                    "rotating ED2K server session from {} after {:?}",
                    server.base_endpoint(),
                    context.rotation_interval.expect("rotation interval is set"),
                );
                clear_server_connection_state(&context.state).await;
                return Ok(());
            }
            request = search_inbox.receiver.recv(), if queued_background_search.is_none() && pending_background_search.is_none() => {
                if let Some(request) = request {
                    if session.login_accepted {
                        match start_background_server_search(
                            &mut session,
                            server,
                            server_udp_socket.as_ref(),
                            context.hello_identity.connect_options,
                            &context.shared_catalog,
                            context.hello_identity.tcp_port,
                            request,
                        )
                        .await
                        {
                            Ok(pending) => pending_background_search = pending,
                            Err(error) => warn!("failed to start ED2K background server search on {}: {error}", server.base_endpoint()),
                        }
                    } else {
                        match &request {
                            BackgroundServerSearchRequest::Keyword { query, .. } => info!(
                                "queued ED2K background keyword search query={query:?} endpoint={} trace_id={} awaiting login",
                                session.endpoint,
                                session.trace_id
                            ),
                            BackgroundServerSearchRequest::Source { file_hash, .. } => info!(
                                "queued ED2K background source search file_hash={} endpoint={} trace_id={} awaiting login",
                                file_hash,
                                session.endpoint,
                                session.trace_id
                            ),
                            BackgroundServerSearchRequest::Callback { client_id, .. } => info!(
                                "queued ED2K background callback request client_id={} endpoint={} trace_id={} awaiting login",
                                client_id,
                                session.endpoint,
                                session.trace_id
                            ),
                            BackgroundServerSearchRequest::Publish { .. } => info!(
                                "queued ED2K background publish refresh endpoint={} trace_id={} awaiting login",
                                session.endpoint,
                                session.trace_id
                            ),
                        }
                        queued_background_search = Some(request);
                    }
                }
            }
            _ = async {
                if let Some(pending) = pending_background_search.as_ref() {
                    let deadline = match pending {
                        PendingBackgroundServerSearch::Keyword { deadline, .. }
                        | PendingBackgroundServerSearch::Source { deadline, .. } => *deadline,
                    };
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if pending_background_search.is_some() => {
                let timeout_error = match pending_background_search.as_ref() {
                    Some(PendingBackgroundServerSearch::Keyword { .. }) => {
                        "ED2K background session search timed out waiting for OP_SEARCHRESULT"
                    }
                    Some(PendingBackgroundServerSearch::Source { .. }) => {
                        "ED2K background session search timed out waiting for OP_FOUNDSOURCES"
                    }
                    None => unreachable!("pending background search timeout without search"),
                };
                fail_pending_background_search(&mut pending_background_search, timeout_error);
            }
            packet = session.read_packet() => {
                let Some(packet) = packet? else {
                    let closed_error = format!(
                        "ED2K server {} closed the connection",
                        server.base_endpoint()
                    );
                    fail_background_search_request(
                        &mut queued_background_search,
                        &format!("{closed_error} before search dispatch"),
                    );
                    fail_pending_background_search(
                        &mut pending_background_search,
                        &format!("{closed_error} before search completion"),
                    );
                    anyhow::bail!(
                        "{closed_error}"
                    );
                };
                if let Some(pending) = pending_background_search.take() {
                    match (packet.opcode, pending) {
                        (OP_SEARCHRESULT, PendingBackgroundServerSearch::Keyword {
                            query,
                            deadline,
                            mut results,
                            mut page_count,
                            response,
                        }) => {
                            let page = decode_search_result_page(&packet.payload)?;
                            log_search_result_page(session.endpoint, &page.files);
                            page_count += 1;
                            results.extend(page.files);
                            if page.more_results_available {
                                session.set_phase(
                                    ServerSessionPhase::AwaitingMore,
                                    format!(
                                        "received background search page {} query={query:?}; requesting more",
                                        page_count
                                    ),
                                );
                                session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
                                pending_background_search = Some(PendingBackgroundServerSearch::Keyword {
                                    query,
                                    deadline,
                                    results,
                                    page_count,
                                    response,
                                });
                                continue;
                            }
                            session.set_phase(
                                ServerSessionPhase::Completed,
                                format!(
                                    "completed background keyword search query={query:?} pages={page_count} results={}",
                                    results.len()
                                ),
                            );
                            info!(
                                "completed ED2K background keyword search query={:?} endpoint={} trace_id={} result_count={} pages={}",
                                query,
                                session.endpoint,
                                session.trace_id,
                                results.len(),
                                page_count
                            );
                            let _ = response.send(Ok(results));
                            continue;
                        }
                        (OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU, PendingBackgroundServerSearch::Source {
                            file_hash,
                            response,
                            ..
                        }) => {
                            let results = annotate_found_sources_server(
                                decode_found_sources(
                                    &packet.payload,
                                    packet.opcode == OP_FOUNDSOURCES_OBFU,
                                )?,
                                session.endpoint,
                            );
                            validate_found_sources(&results, file_hash)?;
                            session.set_phase(
                                ServerSessionPhase::Completed,
                                format!(
                                    "completed background source search file_hash={} sources={}",
                                    file_hash,
                                    results.len()
                                ),
                            );
                            info!(
                                "completed ED2K background source search file_hash={} endpoint={} trace_id={} source_count={} obfuscated={}",
                                file_hash,
                                session.endpoint,
                                session.trace_id,
                                results.len(),
                                packet.opcode == OP_FOUNDSOURCES_OBFU
                            );
                            let _ = response.send(Ok(results));
                            continue;
                        }
                        (_, pending) => {
                            pending_background_search = Some(pending);
                        }
                    }
                }
                handle_server_packet(
                    &mut session,
                    packet,
                    context,
                    queued_background_search.is_none() && pending_background_search.is_none(),
                )
                .await?;
                if session.login_accepted
                    && pending_background_search.is_none()
                    && let Some(request) = queued_background_search.take()
                {
                    match start_background_server_search(
                        &mut session,
                        server,
                        server_udp_socket.as_ref(),
                        context.hello_identity.connect_options,
                        &context.shared_catalog,
                        context.hello_identity.tcp_port,
                        request,
                    )
                    .await
                    {
                        Ok(pending) => pending_background_search = pending,
                        Err(error) => warn!("failed to start ED2K background server search on {}: {error}", server.base_endpoint()),
                    }
                }
            }
            udp_packet = async {
                if let Some(socket) = server_udp_socket.as_ref() {
                    read_server_udp_packet(socket, server).await
                } else {
                    std::future::pending::<Result<Option<ServerUdpPacket>>>().await
                }
            } => {
                match udp_packet {
                    Ok(Some(packet)) => {
                        handle_background_udp_packet(
                            server,
                            &packet,
                            &mut pending_background_search,
                            &context.state,
                        )?;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(
                            "ignoring ED2K server UDP helper receive failure for {}: {error}",
                            server.base_endpoint()
                        );
                    }
                }
            }
            _ = tokio::time::sleep(context.keepalive_interval) => {
                if session.last_tx.elapsed() >= context.keepalive_interval {
                    send_offer_files_advertisement(
                        &mut session,
                        &context.shared_catalog,
                        context.hello_identity.tcp_port,
                    )
                    .await?;
                    if session.last_tx.elapsed() >= context.keepalive_interval {
                        session.send_packet(OP_OFFERFILES, &0u32.to_le_bytes()).await?;
                        debug!("sent ED2K server keepalive to {}", server.base_endpoint());
                    }
                }
                if let Some(socket) = server_udp_socket.as_ref()
                    && let Err(error) = send_server_udp_status_request(socket, server).await
                {
                    warn!(
                        "failed to send ED2K server UDP status request to {}: {error}",
                        server.base_endpoint()
                    );
                }
            }
        }
    }
}

pub(super) async fn clear_server_connection_state(state: &Arc<RwLock<Ed2kServerState>>) {
    let mut guard = state.write().await;
    guard.connected = false;
    guard.endpoint = None;
    guard.client_id = None;
    guard.server_flags = None;
}
