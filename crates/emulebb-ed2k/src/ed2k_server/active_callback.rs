use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{sync::RwLock, time::Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    config::Ed2kRuntimeConfig,
    ed2k_tcp::Ed2kHelloIdentity,
    ed2k_transfer::{Ed2kSharedEntry, IndexedSharedCatalog},
};

use super::packet_handler::{decode_id_change_payload, log_uncorrelated_server_reject};
use super::{
    Ed2kServerState, OP_CALLBACK_FAIL, OP_CALLBACKREQUEST, OP_IDCHANGE, OP_LOGINREQUEST, OP_REJECT,
    ServerSession, ServerSessionPhase, ServerSessionRole, encode_login_request,
    login_identity_for_server_transport, resolve_callback_server_entry,
    send_connected_server_startup, should_use_server_obfuscation, wait_for_offer_files_settle,
};

/// Inputs for a focused ED2K server callback request.
pub struct Ed2kCallbackRequestOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub config: &'a Ed2kRuntimeConfig,
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
    let nickname = config.server_nickname();
    let login_payload =
        encode_login_request(login_identity, &nickname, ServerSessionRole::Callback);
    if use_server_obfuscation {
        session
            .negotiate_obfuscation_and_send(OP_LOGINREQUEST, &login_payload)
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
                    &Arc::new(RwLock::new(IndexedSharedCatalog::from_entries(
                        shared_catalog.to_vec(),
                    ))),
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
                debug!(
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
                    let packet = match tokio::time::timeout(remaining, session.read_packet()).await
                    {
                        Ok(result) => result?,
                        Err(_) => {
                            session.set_phase(
                                ServerSessionPhase::Completed,
                                format!(
                                    "completed callback request client_id={client_id} without explicit failure"
                                ),
                            );
                            return Ok(());
                        }
                    };
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
                            log_uncorrelated_server_reject(
                                transport_endpoint,
                                packet.payload.len(),
                            );
                        }
                        _ => {}
                    }
                }
            }
            OP_REJECT => {
                log_uncorrelated_server_reject(transport_endpoint, packet.payload.len());
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_util::sync::CancellationToken;

    use super::{Ed2kCallbackRequestOptions, request_callback_on_server};

    async fn read_active_callback_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], super::super::OP_EDONKEYPROT);
        let payload_len =
            u32::from_le_bytes(header[1..5].try_into().unwrap()).saturating_sub(1) as usize;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await.unwrap();
        (header[5], payload)
    }

    fn active_callback_identity() -> crate::ed2k_tcp::Ed2kHelloIdentity {
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

    #[tokio::test]
    async fn active_callback_ignores_reject_but_honors_typed_failure() {
        for (response_opcode, expect_success) in [
            (super::super::OP_REJECT, true),
            (super::super::OP_CALLBACK_FAIL, false),
        ] {
            let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (opcode, _) = read_active_callback_frame(&mut stream).await;
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
                    let (opcode, _) = read_active_callback_frame(&mut stream).await;
                    if opcode == super::super::OP_CALLBACKREQUEST {
                        break;
                    }
                }
                stream
                    .write_all(
                        &super::super::encode_packet(response_opcode, &[0x01], false).unwrap(),
                    )
                    .await
                    .unwrap();
                if expect_success {
                    std::future::pending::<()>().await;
                }
            });
            let cancel = CancellationToken::new();
            let config = crate::config::Ed2kRuntimeConfig::default();

            let result = request_callback_on_server(Ed2kCallbackRequestOptions {
                bind_ip: crate::test_bind_ip(),
                config: &config,
                hello_identity: active_callback_identity(),
                shared_catalog: &[],
                server_endpoint: endpoint,
                client_id: 7,
                timeout: Duration::from_millis(250),
                cancel: &cancel,
            })
            .await;

            assert_eq!(result.is_ok(), expect_success);
            server_task.abort();
        }
    }
}
