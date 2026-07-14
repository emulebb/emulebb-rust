use std::{
    collections::VecDeque,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::Error;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use tracing::{info, warn};

use super::server_description_poll::poll_server_descriptions;
use super::server_entry::{ConfiguredServerEntry, ResolvedServerEntry};
use super::server_events::Ed2kServerListEvent;
use super::types::{Ed2kServerState, ServerSessionContext};
use super::{
    Ed2kServerLoopOptions, Ed2kServerSearchInbox, clear_server_connection_state,
    configured_server_entries, dump_ed2k_server_loop_meta, resolve_server_entry,
    run_one_server_session, session_driver::ServerSessionExit,
};

const ESTABLISHED_SESSION_RECONNECT_DELAY: Duration = Duration::from_secs(3);
const PARALLEL_ATTEMPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Runs the minimal oracle-shaped ED2K server session loop for the configured endpoints.
#[expect(
    clippy::cognitive_complexity,
    reason = "linear protocol orchestration flow"
)]
pub async fn run_ed2k_server_loop(options: Ed2kServerLoopOptions) {
    let Ed2kServerLoopOptions {
        bind_ip,
        nat,
        config,
        hello_identity,
        shared_catalog,
        state,
        search_inbox,
        kad_firewall,
        shutdown,
        public_ip,
        reconnect_signal,
        target_server_endpoint,
        server_list_events,
    } = options;
    let search_inbox = Arc::new(tokio::sync::Mutex::new(search_inbox));
    let failed_attempt_reconnect_delay = Duration::from_secs(config.reconnect_interval_secs.max(1));
    let session_context = ServerSessionContext {
        bind_ip,
        nat,
        hello_identity,
        probe_search_term: config.probe_search_term.clone(),
        shared_catalog,
        state: Arc::clone(&state),
        kad_firewall,
        // eMule ServerKeepAliveTimeout: 0 disables the idle keepalive entirely
        // (ServerConnect.cpp:672-674). When enabled it is a minutes-scale value.
        keepalive_interval: config.keepalive_interval(),
        // Server connect budget (eMule CONSERVTIMEOUT = SEC2MS(25), Opcodes.h:109).
        connect_timeout: Duration::from_secs(config.server_connect_timeout_secs.max(1)),
        rotation_interval: (config.session_rotation_secs > 0)
            .then(|| Duration::from_secs(config.session_rotation_secs)),
        shutdown: Arc::clone(&shutdown),
        public_ip,
        reconnect_signal,
        server_list_events,
        add_servers_from_server: config.add_servers_from_server,
    };

    let configured_servers = match configured_server_entries(&config) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("ED2K server session disabled: invalid server configuration: {error}");
            return;
        }
    };
    if configured_servers.is_empty() {
        info!(
            "ED2K server session disabled: no p2p.ed2k.server_entries or p2p.ed2k.server_endpoints configured"
        );
        return;
    }
    tokio::spawn(poll_server_descriptions(
        bind_ip,
        configured_servers.clone(),
        Arc::clone(&state),
        Arc::clone(&shutdown),
        session_context.server_list_events.clone(),
    ));
    let reconnect_enabled = config.reconnect_enabled;

    while !shutdown.load(Ordering::Relaxed) {
        let mut attempted_any = false;
        let target_endpoint = target_server_endpoint.read().await.clone();
        let selected_servers =
            selected_configured_servers(&configured_servers, target_endpoint.as_deref());
        if max_simultaneous_server_attempts(config.safe_server_connect, target_endpoint.as_deref())
            == 2
            && selected_servers.len() > 1
        {
            let outcome = run_parallel_server_cycle(
                selected_servers,
                &session_context,
                &search_inbox,
                &state,
            )
            .await;
            if matches!(outcome, ParallelServerCycleOutcome::Shutdown) {
                break;
            }
            if !reconnect_enabled {
                return;
            }
            let delay = if matches!(
                outcome,
                ParallelServerCycleOutcome::SessionEnded
                    | ParallelServerCycleOutcome::RestartPreferredOrder
            ) {
                ESTABLISHED_SESSION_RECONNECT_DELAY
            } else {
                failed_attempt_reconnect_delay
            };
            tokio::time::sleep(delay).await;
            continue;
        }
        let selected_server_count = selected_servers.len();
        for (server_index, configured_server) in selected_servers.into_iter().enumerate() {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            attempted_any = true;
            let mut retry_delay = failed_attempt_reconnect_delay;
            let mut retry_reason = "connect_or_session_end";
            match resolve_server_entry(&configured_server).await {
                Ok(server) => {
                    match run_one_server_session(&server, &session_context, &search_inbox).await {
                        Ok(ServerSessionExit::ContinueOrder) => {
                            (retry_delay, retry_reason) =
                                session_end_retry_delay(true, failed_attempt_reconnect_delay);
                        }
                        Ok(ServerSessionExit::RestartPreferredOrder) => {
                            if reconnect_enabled && !shutdown.load(Ordering::Relaxed) {
                                let endpoint = server.base_endpoint().to_string();
                                dump_ed2k_server_loop_meta(
                                    &endpoint,
                                    "retry_delay",
                                    format!(
                                        "server loop retry delay reason=reconnect_signal delay_ms={}",
                                        ESTABLISHED_SESSION_RECONNECT_DELAY.as_millis()
                                    ),
                                );
                                tokio::select! {
                                    () = tokio::time::sleep(ESTABLISHED_SESSION_RECONNECT_DELAY) => {
                                        dump_ed2k_server_loop_meta(
                                            &endpoint,
                                            "retry_delay_complete",
                                            "server loop retry delay completed reason=reconnect_signal",
                                        );
                                    }
                                    () = session_context.reconnect_signal.notified() => {
                                        dump_ed2k_server_loop_meta(
                                            &endpoint,
                                            "retry_delay_interrupted",
                                            "server loop retry delay interrupted reason=reconnect_signal",
                                        );
                                        info!(
                                            "ED2K server reconnect delay interrupted by explicit reconnect request"
                                        );
                                    }
                                }
                            }
                            break;
                        }
                        Err(error) => {
                            let was_connected = state.read().await.connected;
                            clear_server_connection_state(&state).await;
                            (retry_delay, retry_reason) = session_end_retry_delay(
                                was_connected,
                                failed_attempt_reconnect_delay,
                            );
                            let endpoint = server.base_endpoint().to_string();
                            dump_ed2k_server_loop_meta(
                                &endpoint,
                                "session_error",
                                format!("server session drop reason=session_error detail={error}"),
                            );
                            // eMule `CServerList::ServerStats`: a failed connect/session
                            // increments the server's fail-count (the core drops a
                            // non-static dead server at the threshold). A successful
                            // login emits `ConnectSucceeded` from inside the session,
                            // which resets the count.
                            if let Some(sender) = session_context.server_list_events.as_ref() {
                                let _ = sender.send(Ed2kServerListEvent::ConnectFailed {
                                    endpoint: configured_server.base_endpoint_text(),
                                });
                            }
                            warn!(
                                "ED2K server session ended for {} name={}: {error}",
                                server.base_endpoint(),
                                server.entry.display_name()
                            );
                        }
                    }
                }
                Err(error) => {
                    let endpoint = configured_server.base_endpoint_text();
                    dump_ed2k_server_loop_meta(
                        &endpoint,
                        "resolve_error",
                        format!("server session drop reason=resolve_error detail={error}"),
                    );
                    // A resolve failure is also a connect failure for the dead-server
                    // accounting (eMule treats a server it cannot reach as failed).
                    if let Some(sender) = session_context.server_list_events.as_ref() {
                        let _ = sender.send(Ed2kServerListEvent::ConnectFailed {
                            endpoint: configured_server.base_endpoint_text(),
                        });
                    }
                    warn!(
                        "failed to resolve ED2K server endpoint {} name={}: {error}",
                        configured_server.base_endpoint_text(),
                        configured_server.display_name()
                    );
                }
            }

            if reconnect_enabled
                && !shutdown.load(Ordering::Relaxed)
                && (server_index + 1 == selected_server_count
                    || retry_reason == "established_session_drop")
            {
                let endpoint = configured_server.base_endpoint_text();
                dump_ed2k_server_loop_meta(
                    &endpoint,
                    "retry_delay",
                    format!(
                        "server loop retry delay reason={} delay_ms={}",
                        retry_reason,
                        retry_delay.as_millis()
                    ),
                );
                tokio::select! {
                    () = tokio::time::sleep(retry_delay) => {
                        dump_ed2k_server_loop_meta(
                            &endpoint,
                            "retry_delay_complete",
                            format!("server loop retry delay completed reason={retry_reason}"),
                        );
                    }
                    () = session_context.reconnect_signal.notified() => {
                        dump_ed2k_server_loop_meta(
                            &endpoint,
                            "retry_delay_interrupted",
                            "server loop retry delay interrupted reason=reconnect_signal",
                        );
                        info!(
                            "ED2K server reconnect delay interrupted by explicit reconnect request"
                        );
                    }
                }
            }
        }
        if !reconnect_enabled {
            info!("ED2K server reconnect disabled by settings; leaving background session stopped");
            return;
        }

        if !attempted_any && !shutdown.load(Ordering::Relaxed) {
            dump_ed2k_server_loop_meta(
                "none",
                "retry_delay",
                format!(
                    "server loop retry delay reason=no_configured_server_selected delay_ms={}",
                    failed_attempt_reconnect_delay.as_millis()
                ),
            );
            tokio::time::sleep(failed_attempt_reconnect_delay).await;
            dump_ed2k_server_loop_meta(
                "none",
                "retry_delay_complete",
                "server loop retry delay completed reason=no_configured_server_selected",
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParallelServerCycleOutcome {
    Exhausted,
    SessionEnded,
    RestartPreferredOrder,
    Shutdown,
}

struct ParallelServerAttempt {
    configured: ConfiguredServerEntry,
    server: ResolvedServerEntry,
    state: Arc<RwLock<Ed2kServerState>>,
    task: JoinHandle<Result<ServerSessionExit, Error>>,
}

/// MFC keeps two automatic server attempts in flight when Safe Connect is off.
/// Each attempt gets private state so a losing socket cannot overwrite the
/// selected session; only the first logged-in attempt is mirrored publicly.
async fn run_parallel_server_cycle(
    configured_servers: Vec<ConfiguredServerEntry>,
    context: &ServerSessionContext,
    search_inbox: &Arc<Mutex<Ed2kServerSearchInbox>>,
    public_state: &Arc<RwLock<Ed2kServerState>>,
) -> ParallelServerCycleOutcome {
    {
        let mut state = public_state.write().await;
        state.connecting = true;
        state.connected = false;
        state.endpoint = None;
    }
    let mut pending = VecDeque::from(configured_servers);
    let mut active = Vec::<ParallelServerAttempt>::new();

    loop {
        while active.len() < 2 {
            let Some(configured) = pending.pop_front() else {
                break;
            };
            match resolve_server_entry(&configured).await {
                Ok(server) => {
                    let attempt_state = Arc::new(RwLock::new(Ed2kServerState::default()));
                    let mut attempt_context = context.clone();
                    attempt_context.state = Arc::clone(&attempt_state);
                    let attempt_server = server.clone();
                    let attempt_inbox = Arc::clone(search_inbox);
                    let task = tokio::spawn(async move {
                        run_one_server_session(&attempt_server, &attempt_context, &attempt_inbox)
                            .await
                    });
                    active.push(ParallelServerAttempt {
                        configured,
                        server,
                        state: attempt_state,
                        task,
                    });
                }
                Err(error) => report_parallel_attempt_failure(context, &configured, None, &error),
            }
        }

        if context.shutdown.load(Ordering::Relaxed) {
            for attempt in &active {
                attempt.task.abort();
            }
            return ParallelServerCycleOutcome::Shutdown;
        }

        let mut winner_index = None;
        for (index, attempt) in active.iter().enumerate() {
            if attempt.state.read().await.connected {
                winner_index = Some(index);
                break;
            }
        }
        if let Some(winner_index) = winner_index {
            let winner = active.swap_remove(winner_index);
            for loser in active {
                loser.task.abort();
            }
            return mirror_winning_server_session(winner, public_state).await;
        }

        let mut index = 0;
        while index < active.len() {
            if !active[index].task.is_finished() {
                index += 1;
                continue;
            }
            let attempt = active.swap_remove(index);
            match attempt.task.await {
                Ok(Ok(ServerSessionExit::RestartPreferredOrder)) => {
                    return ParallelServerCycleOutcome::RestartPreferredOrder;
                }
                Ok(Ok(ServerSessionExit::ContinueOrder)) => {}
                Ok(Err(error)) => report_parallel_attempt_failure(
                    context,
                    &attempt.configured,
                    Some(&attempt.server),
                    &error,
                ),
                Err(error) if error.is_cancelled() => {}
                Err(error) => warn!("ED2K parallel server attempt task failed: {error}"),
            }
        }

        if active.is_empty() && pending.is_empty() {
            clear_server_connection_state(public_state).await;
            return ParallelServerCycleOutcome::Exhausted;
        }
        tokio::time::sleep(PARALLEL_ATTEMPT_POLL_INTERVAL).await;
    }
}

fn max_simultaneous_server_attempts(
    safe_server_connect: bool,
    target_endpoint: Option<&str>,
) -> usize {
    if safe_server_connect || target_endpoint.is_some() {
        1
    } else {
        2
    }
}

async fn mirror_winning_server_session(
    winner: ParallelServerAttempt,
    public_state: &Arc<RwLock<Ed2kServerState>>,
) -> ParallelServerCycleOutcome {
    loop {
        *public_state.write().await = winner.state.read().await.clone();
        if winner.task.is_finished() {
            let outcome = match winner.task.await {
                Ok(Ok(ServerSessionExit::RestartPreferredOrder)) => {
                    ParallelServerCycleOutcome::RestartPreferredOrder
                }
                Ok(Ok(ServerSessionExit::ContinueOrder)) | Ok(Err(_)) | Err(_) => {
                    ParallelServerCycleOutcome::SessionEnded
                }
            };
            clear_server_connection_state(public_state).await;
            return outcome;
        }
        tokio::time::sleep(PARALLEL_ATTEMPT_POLL_INTERVAL).await;
    }
}

fn report_parallel_attempt_failure(
    context: &ServerSessionContext,
    configured: &ConfiguredServerEntry,
    server: Option<&ResolvedServerEntry>,
    error: &dyn std::fmt::Display,
) {
    if let Some(sender) = context.server_list_events.as_ref() {
        let _ = sender.send(Ed2kServerListEvent::ConnectFailed {
            endpoint: configured.base_endpoint_text(),
        });
    }
    warn!(
        "ED2K parallel server attempt failed for {} resolved={}: {error}",
        configured.base_endpoint_text(),
        server
            .map(|entry| entry.base_endpoint().to_string())
            .unwrap_or_else(|| "unresolved".to_string())
    );
}

fn selected_configured_servers(
    configured_servers: &[ConfiguredServerEntry],
    target_endpoint: Option<&str>,
) -> Vec<ConfiguredServerEntry> {
    let Some(target_endpoint) = target_endpoint else {
        return configured_servers.to_vec();
    };
    if let Some(target) = configured_servers.iter().find(|entry| {
        entry
            .base_endpoint_text()
            .eq_ignore_ascii_case(target_endpoint)
    }) {
        // WHY: an explicit REST/UI server selection is a pinned session. Falling
        // through to imported server.met rows makes parity/live runs silently
        // leave the selected server after a disconnect.
        return vec![target.clone()];
    }
    ConfiguredServerEntry::from_endpoint_text(target_endpoint)
        .map(|target| vec![target])
        .unwrap_or_default()
}

fn session_end_retry_delay(
    was_connected: bool,
    failed_attempt_delay: Duration,
) -> (Duration, &'static str) {
    if was_connected {
        (
            ESTABLISHED_SESSION_RECONNECT_DELAY,
            "established_session_drop",
        )
    } else {
        (failed_attempt_delay, "connect_or_session_end")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(endpoint: &str) -> ConfiguredServerEntry {
        ConfiguredServerEntry::from_endpoint_text(endpoint).unwrap()
    }

    #[test]
    fn targeted_server_is_pinned_without_fallbacks() {
        let servers = vec![
            server("192.0.2.1:4661"),
            server("192.0.2.2:4661"),
            server("192.0.2.3:4661"),
        ];

        let selected = selected_configured_servers(&servers, Some("192.0.2.2:4661"));

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].base_endpoint_text(), "192.0.2.2:4661");
    }

    #[test]
    fn unknown_target_uses_target_without_fallbacks() {
        let servers = vec![server("192.0.2.1:4661"), server("192.0.2.2:4661")];

        let selected = selected_configured_servers(&servers, Some("192.0.2.99:4661"));

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].base_endpoint_text(), "192.0.2.99:4661");
    }

    #[test]
    fn invalid_unknown_target_has_no_fallbacks() {
        let servers = vec![server("192.0.2.1:4661"), server("192.0.2.2:4661")];

        let selected = selected_configured_servers(&servers, Some("not-a-server"));

        assert!(selected.is_empty());
    }

    #[test]
    fn established_session_drop_uses_fast_reconnect_delay() {
        let failed_attempt_delay = Duration::from_secs(60);

        assert_eq!(
            session_end_retry_delay(true, failed_attempt_delay),
            (Duration::from_secs(3), "established_session_drop")
        );
        assert_eq!(
            session_end_retry_delay(false, failed_attempt_delay),
            (failed_attempt_delay, "connect_or_session_end")
        );
    }

    #[test]
    fn safe_connect_and_explicit_targets_limit_parallel_attempts() {
        assert_eq!(max_simultaneous_server_attempts(true, None), 1);
        assert_eq!(max_simultaneous_server_attempts(false, None), 2);
        assert_eq!(
            max_simultaneous_server_attempts(false, Some("192.0.2.2:4661")),
            1
        );
    }
}
