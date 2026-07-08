use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{sync::RwLock, time::Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{config::Ed2kConfig, ed2k_tcp::Ed2kHelloIdentity, ed2k_transfer::Ed2kSharedEntry};

use super::packet_handler::decode_id_change_payload;
use super::{
    Ed2kServerState, OP_CALLBACK_FAIL, OP_CALLBACKREQUEST, OP_IDCHANGE, OP_LOGINREQUEST, OP_REJECT,
    ServerSession, ServerSessionPhase, encode_login_request, encode_packet,
    login_identity_for_server_transport, resolve_callback_server_entry,
    send_connected_server_startup, should_use_server_obfuscation, wait_for_offer_files_settle,
};

/// Inputs for a focused ED2K server callback request.
pub struct Ed2kCallbackRequestOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub config: &'a Ed2kConfig,
    pub hello_identity: Ed2kHelloIdentity,
    pub shared_catalog: &'a [Ed2kSharedEntry],
    pub server_endpoint: SocketAddr,
    pub client_id: u32,
    pub timeout: Duration,
    pub cancel: &'a CancellationToken,
}

/// Requests an ED2K server callback for a LowID peer on one explicit server.
///
/// This keeps callback routing aligned with the server that reported the
/// callback-only source whenever that provenance is available.
pub async fn request_callback_on_server(options: Ed2kCallbackRequestOptions<'_>) -> Result<()> {
    let Ed2kCallbackRequestOptions {
        bind_ip,
        config,
        hello_identity,
        shared_catalog,
        server_endpoint,
        client_id,
        timeout,
        cancel,
    } = options;
    let resolved_server = resolve_callback_server_entry(config, server_endpoint).await?;
    let use_server_obfuscation =
        should_use_server_obfuscation(hello_identity.connect_options, &resolved_server);
    let login_identity =
        login_identity_for_server_transport(hello_identity, use_server_obfuscation);
    let transport_endpoint = resolved_server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        bind_ip,
        transport_endpoint,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        "active_callback",
        timeout,
    )
    .await?;
    let login_payload = encode_login_request(login_identity);
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
        "login request sent; awaiting OP_IDCHANGE for callback request",
    );
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let packet = tokio::time::timeout(timeout, session.read_packet())
            .await
            .with_context(|| {
                format!("timed out waiting for ED2K callback-ready login on {transport_endpoint}")
            })??;
        let Some(packet) = packet else {
            anyhow::bail!("ED2K server {transport_endpoint} closed before callback dispatch");
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
                // Ephemeral callback-request session: never solicit the server
                // list (stock only issues OP_GETSERVERLIST from its persistent
                // ServerConnect, gated on AddServersFromServer).
                send_connected_server_startup(
                    &mut session,
                    &Arc::new(RwLock::new(shared_catalog.to_vec())),
                    bind_ip,
                    hello_identity.tcp_port,
                    false,
                )
                .await?;
                wait_for_offer_files_settle(&session).await;
                session.set_phase(
                    ServerSessionPhase::SearchActive,
                    format!("dispatching callback request client_id={client_id}"),
                );
                session
                    .send_packet(OP_CALLBACKREQUEST, &client_id.to_le_bytes())
                    .await?;
                info!(
                    "sent ED2K targeted callback request client_id={} endpoint={} trace_id={} transport={}",
                    client_id,
                    session.endpoint,
                    session.trace_id,
                    if use_server_obfuscation {
                        "obfuscated"
                    } else {
                        "plaintext"
                    }
                );
                let callback_response_deadline =
                    TokioInstant::now() + timeout.min(Duration::from_secs(5));
                loop {
                    if cancel.is_cancelled() {
                        return Ok(());
                    }
                    let remaining = callback_response_deadline
                        .checked_duration_since(TokioInstant::now())
                        .unwrap_or_default();
                    if remaining.is_zero() {
                        session.set_phase(
                            ServerSessionPhase::Completed,
                            format!(
                                "completed callback request client_id={client_id} without explicit failure"
                            ),
                        );
                        return Ok(());
                    }
                    let packet = tokio::time::timeout(remaining, session.read_packet())
                        .await
                        .with_context(|| {
                            format!(
                                "timed out waiting for ED2K callback response from {transport_endpoint}"
                            )
                        })??;
                    let Some(packet) = packet else {
                        anyhow::bail!(
                            "ED2K server {transport_endpoint} closed after callback dispatch"
                        );
                    };
                    match packet.opcode {
                        OP_CALLBACK_FAIL => {
                            anyhow::bail!(
                                "ED2K server {transport_endpoint} reported callback failure for client_id={client_id}"
                            );
                        }
                        OP_REJECT => {
                            anyhow::bail!(
                                "ED2K server {transport_endpoint} rejected the callback request"
                            );
                        }
                        _ => {}
                    }
                }
            }
            OP_REJECT => {
                anyhow::bail!("ED2K server {transport_endpoint} rejected the callback request");
            }
            _ => {}
        }
    }
}
