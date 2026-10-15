use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use anyhow::Error;
use tokio::{
    sync::{Mutex, Notify, RwLock, watch},
    task::JoinHandle,
};
use tracing::{info, warn};

use crate::config::Ed2kRuntimeConfig;

use super::server_description_poll::poll_server_descriptions;
use super::server_entry::{ConfiguredServerEntry, ResolvedServerEntry};
use super::server_events::Ed2kServerListEvent;
use super::types::{Ed2kServerConnectPlan, Ed2kServerState, ServerSessionContext};
use super::{
    Ed2kServerFailure, Ed2kServerLoopOptions, Ed2kServerSearchInbox, clear_server_connection_state,
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
        mut server_connect_plan,
        hello_identity,
        shared_catalog,
        state,
        search_inbox,
        kad_firewall,
        shutdown,
        server_enabled,
        public_ip,
        reconnect_signal,
        server_list_events,
        callback_sessions,
    } = options;
    let search_inbox = Arc::new(tokio::sync::Mutex::new(search_inbox));
    let initial_plan = server_connect_plan.borrow().clone();
    let initial_config = initial_plan.config();
    let session_context_base = ServerSessionContext {
        bind_ip,
        nat,
        hello_identity,
        nickname: initial_config.server_nickname(),
        last_client_id: Arc::new(AtomicU32::new(hello_identity.client_id)),
        probe_search_term: initial_config.probe_search_term.clone(),
        shared_catalog,
        state: Arc::clone(&state),
        kad_firewall,
        // eMule ServerKeepAliveTimeout: 0 disables the idle keepalive entirely
        // (ServerConnect.cpp:672-674). When enabled it is a minutes-scale value.
        keepalive_interval: initial_config.keepalive_interval(),
        // Server connect budget (eMule CONSERVTIMEOUT = SEC2MS(25), Opcodes.h:109).
        connect_timeout: Duration::from_secs(initial_config.server_connect_timeout_secs.max(1)),
        rotation_interval: (initial_config.session_rotation_secs > 0)
            .then(|| Duration::from_secs(initial_config.session_rotation_secs)),
        shutdown: Arc::clone(&shutdown),
        public_ip,
        server_list_events,
        add_servers_from_server: initial_config.add_servers_from_server,
        offer_files_capability_enabled: initial_config.offer_files_capability_enabled,
        callback_sessions,
    };

    let initial_configured_servers = match configured_server_entries(initial_plan.config()) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("ED2K server session disabled: invalid server configuration: {error}");
            return;
        }
    };
    if !initial_configured_servers.is_empty() {
        tokio::spawn(poll_server_descriptions(
            bind_ip,
            initial_configured_servers,
            Arc::clone(&state),
            session_context_base.public_ip.clone(),
            session_context_base.hello_identity.connect_options & 0x01 != 0,
            session_context_base.add_servers_from_server,
            Arc::clone(&shutdown),
            Arc::clone(&server_enabled),
            session_context_base.server_list_events.clone(),
        ));
    }

    'server_loop: while !shutdown.load(Ordering::Relaxed) {
        if !server_enabled.load(Ordering::SeqCst) {
            clear_server_connection_state(&state).await;
            tokio::select! {
                () = reconnect_signal.notified() => {},
                changed = server_connect_plan.changed() => {
                    if changed.is_err() {
                        break;
                    }
                },
                () = wait_for_shutdown(&shutdown) => break,
            }
            continue;
        }

        let plan = server_connect_plan.borrow_and_update().clone();
        let session_context = session_context_for_config(&session_context_base, plan.config());
        let failed_attempt_reconnect_delay =
            Duration::from_secs(plan.config().reconnect_interval_secs.max(1));
        let reconnect_enabled = plan.config().reconnect_enabled;
        let configured_servers = match configured_server_entries(plan.config()) {
            Ok(entries) => entries,
            Err(error) => {
                warn!("invalid live ED2K server connection plan: {error}");
                match wait_for_loop_control(
                    failed_attempt_reconnect_delay,
                    &mut server_connect_plan,
                    &reconnect_signal,
                    &shutdown,
                )
                .await
                {
                    ServerLoopControl::Shutdown => break,
                    ServerLoopControl::DelayElapsed
                    | ServerLoopControl::PlanChanged
                    | ServerLoopControl::ReconnectRequested => continue,
                }
            }
        };
        let mut attempted_any = false;
        let target_endpoint = plan.mode().directed_endpoint();
        let selected_servers = selected_configured_servers(
            &configured_servers,
            target_endpoint,
            plan.mode().is_automatic() && plan.config().auto_connect_static_only,
        );
        if max_simultaneous_server_attempts(plan.config().safe_server_connect, target_endpoint) == 2
            && selected_servers.len() > 1
        {
            let outcome = run_parallel_server_cycle(
                selected_servers,
                &session_context,
                &search_inbox,
                &state,
                &mut server_connect_plan,
                &reconnect_signal,
            )
            .await;
            match outcome {
                ParallelServerCycleOutcome::Shutdown => break,
                ParallelServerCycleOutcome::PlanChanged => continue,
                ParallelServerCycleOutcome::Exhausted
                | ParallelServerCycleOutcome::SessionEnded
                | ParallelServerCycleOutcome::ReconnectRequested => {}
            }
            if !reconnect_enabled {
                if matches!(outcome, ParallelServerCycleOutcome::ReconnectRequested) {
                    continue;
                }
                info!(
                    "ED2K automatic server reconnect disabled by settings; waiting for an explicit retry request"
                );
                if wait_for_explicit_retry(&mut server_connect_plan, &reconnect_signal, &shutdown)
                    .await
                {
                    continue;
                }
                break;
            }
            let delay = if matches!(
                outcome,
                ParallelServerCycleOutcome::SessionEnded
                    | ParallelServerCycleOutcome::ReconnectRequested
            ) {
                ESTABLISHED_SESSION_RECONNECT_DELAY
            } else {
                failed_attempt_reconnect_delay
            };
            if matches!(
                wait_for_loop_control(
                    delay,
                    &mut server_connect_plan,
                    &reconnect_signal,
                    &shutdown,
                )
                .await,
                ServerLoopControl::Shutdown
            ) {
                break;
            }
            continue;
        }
        let selected_server_count = selected_servers.len();
        for (server_index, configured_server) in selected_servers.into_iter().enumerate() {
            if shutdown.load(Ordering::Relaxed) {
                break 'server_loop;
            }
            attempted_any = true;
            let mut retry_delay = failed_attempt_reconnect_delay;
            let mut retry_reason = "connect_or_session_end";
            let resolve_result = tokio::select! {
                result = resolve_server_entry(&configured_server) => Some(result),
                changed = server_connect_plan.changed() => {
                    if changed.is_err() {
                        break 'server_loop;
                    }
                    None
                },
                () = reconnect_signal.notified() => None,
                () = wait_for_shutdown(&shutdown) => break 'server_loop,
            };
            let Some(resolve_result) = resolve_result else {
                clear_server_connection_state(&state).await;
                continue 'server_loop;
            };
            match resolve_result {
                Ok(server) => {
                    match run_controlled_server_session(
                        &server,
                        &configured_server,
                        &session_context,
                        &search_inbox,
                        &mut server_connect_plan,
                        &reconnect_signal,
                    )
                    .await
                    {
                        ControlledServerSessionOutcome::Finished {
                            result: Ok(ServerSessionExit::ContinueOrder),
                            plan_changed,
                        } => {
                            (retry_delay, retry_reason) =
                                session_end_retry_delay(true, failed_attempt_reconnect_delay);
                            if plan_changed {
                                continue 'server_loop;
                            }
                        }
                        ControlledServerSessionOutcome::ReconnectRequested => {
                            clear_server_connection_state(&state).await;
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
                                match wait_for_loop_control(
                                    ESTABLISHED_SESSION_RECONNECT_DELAY,
                                    &mut server_connect_plan,
                                    &reconnect_signal,
                                    &shutdown,
                                )
                                .await
                                {
                                    ServerLoopControl::DelayElapsed => {
                                        dump_ed2k_server_loop_meta(
                                            &endpoint,
                                            "retry_delay_complete",
                                            "server loop retry delay completed reason=reconnect_signal",
                                        );
                                    }
                                    ServerLoopControl::PlanChanged
                                    | ServerLoopControl::ReconnectRequested => {
                                        dump_ed2k_server_loop_meta(
                                            &endpoint,
                                            "retry_delay_interrupted",
                                            "server loop retry delay interrupted reason=reconnect_signal",
                                        );
                                        info!(
                                            "ED2K server reconnect delay interrupted by explicit reconnect request"
                                        );
                                    }
                                    ServerLoopControl::Shutdown => break 'server_loop,
                                }
                            }
                            continue 'server_loop;
                        }
                        ControlledServerSessionOutcome::Finished {
                            result: Ok(ServerSessionExit::IntentionalShutdown),
                            ..
                        }
                        | ControlledServerSessionOutcome::Shutdown => break 'server_loop,
                        ControlledServerSessionOutcome::PlanChanged => {
                            clear_server_connection_state(&state).await;
                            continue 'server_loop;
                        }
                        ControlledServerSessionOutcome::Finished {
                            result: Err(error),
                            plan_changed,
                        } => {
                            let was_connected = state.read().await.connected;
                            let failure =
                                Ed2kServerFailure::from_session_error(&error, was_connected);
                            clear_server_connection_state(&state).await;
                            (retry_delay, retry_reason) = session_end_retry_delay(
                                was_connected,
                                failed_attempt_reconnect_delay,
                            );
                            let endpoint = server.base_endpoint().to_string();
                            dump_ed2k_server_loop_meta(
                                &endpoint,
                                "session_error",
                                format!("server session drop {failure}"),
                            );
                            report_server_failure(
                                &session_context,
                                configured_server.base_endpoint_text(),
                                failure,
                            );
                            warn!(
                                "ED2K server session ended for {} name={}: {error}",
                                server.base_endpoint(),
                                server.entry.display_name()
                            );
                            if plan_changed {
                                continue 'server_loop;
                            }
                        }
                    }
                }
                Err(error) => {
                    let endpoint = configured_server.base_endpoint_text();
                    let failure = Ed2kServerFailure::dns(error.to_string());
                    dump_ed2k_server_loop_meta(
                        &endpoint,
                        "resolve_error",
                        format!("server session drop {failure}"),
                    );
                    report_server_failure(&session_context, endpoint, failure);
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
                match wait_for_loop_control(
                    retry_delay,
                    &mut server_connect_plan,
                    &reconnect_signal,
                    &shutdown,
                )
                .await
                {
                    ServerLoopControl::DelayElapsed => {
                        dump_ed2k_server_loop_meta(
                            &endpoint,
                            "retry_delay_complete",
                            format!("server loop retry delay completed reason={retry_reason}"),
                        );
                    }
                    ServerLoopControl::PlanChanged | ServerLoopControl::ReconnectRequested => {
                        dump_ed2k_server_loop_meta(
                            &endpoint,
                            "retry_delay_interrupted",
                            "server loop retry delay interrupted reason=reconnect_signal",
                        );
                        info!(
                            "ED2K server reconnect delay interrupted by explicit reconnect request"
                        );
                        continue 'server_loop;
                    }
                    ServerLoopControl::Shutdown => break 'server_loop,
                }
            }
        }
        if !reconnect_enabled {
            info!(
                "ED2K automatic server reconnect disabled by settings; waiting for an explicit retry request"
            );
            if wait_for_explicit_retry(&mut server_connect_plan, &reconnect_signal, &shutdown).await
            {
                continue;
            }
            break;
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
            match wait_for_loop_control(
                failed_attempt_reconnect_delay,
                &mut server_connect_plan,
                &reconnect_signal,
                &shutdown,
            )
            .await
            {
                ServerLoopControl::Shutdown => break,
                ServerLoopControl::PlanChanged | ServerLoopControl::ReconnectRequested => continue,
                ServerLoopControl::DelayElapsed => {}
            }
            dump_ed2k_server_loop_meta(
                "none",
                "retry_delay_complete",
                "server loop retry delay completed reason=no_configured_server_selected",
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerLoopControl {
    DelayElapsed,
    PlanChanged,
    ReconnectRequested,
    Shutdown,
}

fn session_context_for_config(
    base: &ServerSessionContext,
    config: &Ed2kRuntimeConfig,
) -> ServerSessionContext {
    let mut context = base.clone();
    context.nickname = config.server_nickname();
    context
        .probe_search_term
        .clone_from(&config.probe_search_term);
    context.keepalive_interval = config.keepalive_interval();
    context.connect_timeout = Duration::from_secs(config.server_connect_timeout_secs.max(1));
    context.rotation_interval = (config.session_rotation_secs > 0)
        .then(|| Duration::from_secs(config.session_rotation_secs));
    context.add_servers_from_server = config.add_servers_from_server;
    context.offer_files_capability_enabled = config.offer_files_capability_enabled;
    context
}

async fn wait_for_shutdown(shutdown: &Arc<std::sync::atomic::AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_loop_control(
    delay: Duration,
    server_connect_plan: &mut watch::Receiver<Ed2kServerConnectPlan>,
    reconnect_signal: &Notify,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
) -> ServerLoopControl {
    tokio::select! {
        () = tokio::time::sleep(delay) => ServerLoopControl::DelayElapsed,
        changed = server_connect_plan.changed() => {
            if changed.is_ok() {
                ServerLoopControl::PlanChanged
            } else {
                ServerLoopControl::Shutdown
            }
        }
        () = reconnect_signal.notified() => ServerLoopControl::ReconnectRequested,
        () = wait_for_shutdown(shutdown) => ServerLoopControl::Shutdown,
    }
}

async fn wait_for_explicit_retry(
    server_connect_plan: &mut watch::Receiver<Ed2kServerConnectPlan>,
    reconnect_signal: &Notify,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
) -> bool {
    tokio::select! {
        changed = server_connect_plan.changed() => changed.is_ok(),
        () = reconnect_signal.notified() => true,
        () = wait_for_shutdown(shutdown) => false,
    }
}

enum ControlledServerSessionOutcome {
    Finished {
        result: Result<ServerSessionExit, Error>,
        plan_changed: bool,
    },
    PlanChanged,
    ReconnectRequested,
    Shutdown,
}

async fn run_controlled_server_session(
    server: &ResolvedServerEntry,
    configured_server: &ConfiguredServerEntry,
    context: &ServerSessionContext,
    search_inbox: &Arc<Mutex<Ed2kServerSearchInbox>>,
    server_connect_plan: &mut watch::Receiver<Ed2kServerConnectPlan>,
    reconnect_signal: &Notify,
) -> ControlledServerSessionOutcome {
    let session = run_one_server_session(server, context, search_inbox);
    tokio::pin!(session);
    let mut plan_changed = false;
    loop {
        tokio::select! {
            result = &mut session => {
                return ControlledServerSessionOutcome::Finished { result, plan_changed };
            }
            changed = server_connect_plan.changed() => {
                if changed.is_err() {
                    return ControlledServerSessionOutcome::Shutdown;
                }
                let next_plan = server_connect_plan.borrow_and_update().clone();
                let connected = context.state.read().await.connected;
                if !connected || !plan_allows_configured_server(&next_plan, configured_server) {
                    return ControlledServerSessionOutcome::PlanChanged;
                }
                plan_changed = true;
            }
            () = reconnect_signal.notified() => {
                return ControlledServerSessionOutcome::ReconnectRequested;
            }
            () = wait_for_shutdown(&context.shutdown) => {
                return ControlledServerSessionOutcome::Shutdown;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParallelServerCycleOutcome {
    Exhausted,
    SessionEnded,
    PlanChanged,
    ReconnectRequested,
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
    server_connect_plan: &mut watch::Receiver<Ed2kServerConnectPlan>,
    reconnect_signal: &Notify,
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
            match server_connect_plan.has_changed() {
                Ok(true) => {
                    abort_parallel_attempts(&active);
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::PlanChanged;
                }
                Ok(false) => {}
                Err(_) => {
                    abort_parallel_attempts(&active);
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::Shutdown;
                }
            }
            let Some(configured) = pending.pop_front() else {
                break;
            };
            let resolve_result = tokio::select! {
                result = resolve_server_entry(&configured) => Some(result),
                changed = server_connect_plan.changed() => {
                    abort_parallel_attempts(&active);
                    clear_server_connection_state(public_state).await;
                    return if changed.is_ok() {
                        ParallelServerCycleOutcome::PlanChanged
                    } else {
                        ParallelServerCycleOutcome::Shutdown
                    };
                }
                () = reconnect_signal.notified() => {
                    abort_parallel_attempts(&active);
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::ReconnectRequested;
                }
                () = wait_for_shutdown(&context.shutdown) => {
                    abort_parallel_attempts(&active);
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::Shutdown;
                }
            };
            match resolve_result.expect("resolve branch returns a result") {
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
                Err(error) => report_parallel_attempt_failure(
                    context,
                    &configured,
                    None,
                    Ed2kServerFailure::dns(error.to_string()),
                ),
            }
        }

        if context.shutdown.load(Ordering::Relaxed) {
            abort_parallel_attempts(&active);
            clear_server_connection_state(public_state).await;
            return ParallelServerCycleOutcome::Shutdown;
        }

        match server_connect_plan.has_changed() {
            Ok(true) => {
                abort_parallel_attempts(&active);
                clear_server_connection_state(public_state).await;
                return ParallelServerCycleOutcome::PlanChanged;
            }
            Ok(false) => {}
            Err(_) => {
                abort_parallel_attempts(&active);
                clear_server_connection_state(public_state).await;
                return ParallelServerCycleOutcome::Shutdown;
            }
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
            abort_parallel_attempts(&active);
            return mirror_winning_server_session(
                winner,
                public_state,
                context,
                server_connect_plan,
                reconnect_signal,
            )
            .await;
        }

        let mut index = 0;
        while index < active.len() {
            if !active[index].task.is_finished() {
                index += 1;
                continue;
            }
            let attempt = active.swap_remove(index);
            let was_connected = attempt.state.read().await.connected;
            match attempt.task.await {
                Ok(Ok(ServerSessionExit::IntentionalShutdown)) => {
                    return ParallelServerCycleOutcome::Shutdown;
                }
                Ok(Ok(ServerSessionExit::ContinueOrder)) => {}
                Ok(Err(error)) => report_parallel_attempt_failure(
                    context,
                    &attempt.configured,
                    Some(&attempt.server),
                    Ed2kServerFailure::from_session_error(&error, was_connected),
                ),
                Err(error) if error.is_cancelled() => {}
                Err(error) => warn!("ED2K parallel server attempt task failed: {error}"),
            }
        }

        if active.is_empty() && pending.is_empty() {
            clear_server_connection_state(public_state).await;
            return ParallelServerCycleOutcome::Exhausted;
        }
        tokio::select! {
            () = tokio::time::sleep(PARALLEL_ATTEMPT_POLL_INTERVAL) => {}
            changed = server_connect_plan.changed() => {
                abort_parallel_attempts(&active);
                clear_server_connection_state(public_state).await;
                return if changed.is_ok() {
                    ParallelServerCycleOutcome::PlanChanged
                } else {
                    ParallelServerCycleOutcome::Shutdown
                };
            }
            () = reconnect_signal.notified() => {
                abort_parallel_attempts(&active);
                clear_server_connection_state(public_state).await;
                return ParallelServerCycleOutcome::ReconnectRequested;
            }
            () = wait_for_shutdown(&context.shutdown) => {
                abort_parallel_attempts(&active);
                clear_server_connection_state(public_state).await;
                return ParallelServerCycleOutcome::Shutdown;
            }
        }
    }
}

fn abort_parallel_attempts(attempts: &[ParallelServerAttempt]) {
    for attempt in attempts {
        attempt.task.abort();
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
    context: &ServerSessionContext,
    server_connect_plan: &mut watch::Receiver<Ed2kServerConnectPlan>,
    reconnect_signal: &Notify,
) -> ParallelServerCycleOutcome {
    let mut plan_changed = false;
    loop {
        *public_state.write().await = winner.state.read().await.clone();
        if winner.task.is_finished() {
            let mut outcome = match winner.task.await {
                Ok(Ok(ServerSessionExit::IntentionalShutdown)) => {
                    ParallelServerCycleOutcome::Shutdown
                }
                Ok(Ok(ServerSessionExit::ContinueOrder)) => {
                    ParallelServerCycleOutcome::SessionEnded
                }
                Ok(Err(error)) => {
                    report_parallel_attempt_failure(
                        context,
                        &winner.configured,
                        Some(&winner.server),
                        Ed2kServerFailure::from_session_error(&error, true),
                    );
                    ParallelServerCycleOutcome::SessionEnded
                }
                Err(error) => {
                    warn!("ED2K parallel winning server task failed: {error}");
                    ParallelServerCycleOutcome::SessionEnded
                }
            };
            if plan_changed && matches!(outcome, ParallelServerCycleOutcome::SessionEnded) {
                outcome = ParallelServerCycleOutcome::PlanChanged;
            }
            clear_server_connection_state(public_state).await;
            return outcome;
        }
        tokio::select! {
            () = tokio::time::sleep(PARALLEL_ATTEMPT_POLL_INTERVAL) => {}
            changed = server_connect_plan.changed() => {
                if changed.is_err() {
                    winner.task.abort();
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::Shutdown;
                }
                let next_plan = server_connect_plan.borrow_and_update().clone();
                let connected = winner.state.read().await.connected;
                if !connected || !plan_allows_configured_server(&next_plan, &winner.configured) {
                    winner.task.abort();
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::PlanChanged;
                }
                plan_changed = true;
            }
            () = reconnect_signal.notified() => {
                winner.task.abort();
                clear_server_connection_state(public_state).await;
                return ParallelServerCycleOutcome::ReconnectRequested;
            }
            () = wait_for_shutdown(&context.shutdown) => {
                winner.task.abort();
                clear_server_connection_state(public_state).await;
                return ParallelServerCycleOutcome::Shutdown;
            }
        }
    }
}

fn report_parallel_attempt_failure(
    context: &ServerSessionContext,
    configured: &ConfiguredServerEntry,
    server: Option<&ResolvedServerEntry>,
    failure: Ed2kServerFailure,
) {
    report_server_failure(context, configured.base_endpoint_text(), failure.clone());
    warn!(
        "ED2K parallel server attempt failed for {} resolved={}: {failure}",
        configured.base_endpoint_text(),
        server
            .map(|entry| entry.base_endpoint().to_string())
            .unwrap_or_else(|| "unresolved".to_string())
    );
}

fn report_server_failure(
    context: &ServerSessionContext,
    endpoint: String,
    failure: Ed2kServerFailure,
) {
    if let Some(sender) = context.server_list_events.as_ref() {
        let _ = sender.send(Ed2kServerListEvent::ConnectionFailed { endpoint, failure });
    }
}

fn selected_configured_servers(
    configured_servers: &[ConfiguredServerEntry],
    target_endpoint: Option<&str>,
    automatic_static_only: bool,
) -> Vec<ConfiguredServerEntry> {
    let Some(target_endpoint) = target_endpoint else {
        return configured_servers
            .iter()
            .filter(|entry| !automatic_static_only || entry.static_server)
            .cloned()
            .collect();
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
    Vec::new()
}

fn plan_allows_configured_server(
    plan: &Ed2kServerConnectPlan,
    configured_server: &ConfiguredServerEntry,
) -> bool {
    let Ok(configured_servers) = configured_server_entries(plan.config()) else {
        return false;
    };
    selected_configured_servers(
        &configured_servers,
        plan.mode().directed_endpoint(),
        plan.mode().is_automatic() && plan.config().auto_connect_static_only,
    )
    .iter()
    .any(|candidate| {
        candidate
            .base_endpoint_text()
            .eq_ignore_ascii_case(&configured_server.base_endpoint_text())
    })
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
    use std::sync::atomic::AtomicBool;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        task::JoinHandle,
        time::timeout,
    };

    use super::*;
    use crate::{
        NatManager,
        ed2k_server::{
            Ed2kServerConnectMode, Ed2kServerListEventReceiver, OP_IDCHANGE, OP_LOGINREQUEST,
            ed2k_server_list_event_channel, encode_packet, new_ed2k_server_search_channel,
        },
        ed2k_tcp::{Ed2kHelloIdentity, ed2k_callback_session_channel},
        ed2k_transfer::IndexedSharedCatalog,
        kad_firewall::KadFirewallState,
        reachability::ExternalReachability,
    };

    struct TestServerLoop {
        plan: watch::Sender<Ed2kServerConnectPlan>,
        state: Arc<RwLock<Ed2kServerState>>,
        shutdown: Arc<AtomicBool>,
        reconnect: Arc<Notify>,
        events: Ed2kServerListEventReceiver,
        task: JoinHandle<()>,
    }

    fn test_config(endpoints: Vec<String>, safe_server_connect: bool) -> Ed2kRuntimeConfig {
        Ed2kRuntimeConfig {
            server_endpoints: endpoints,
            obfuscation_enabled: false,
            server_connect_timeout_secs: 2,
            reconnect_interval_secs: 60,
            safe_server_connect,
            keepalive_secs: 0,
            ..Ed2kRuntimeConfig::default()
        }
    }

    fn spawn_test_server_loop(initial_plan: Ed2kServerConnectPlan) -> TestServerLoop {
        let (plan, plan_rx) = watch::channel(initial_plan);
        let state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let reconnect = Arc::new(Notify::new());
        let (_, search_inbox) = new_ed2k_server_search_channel(1);
        let (callback_sessions, _callback_inbox) = ed2k_callback_session_channel();
        let (server_list_events, events) = ed2k_server_list_event_channel();
        let options = Ed2kServerLoopOptions {
            bind_ip: crate::test_bind_ip(),
            nat: Arc::new(NatManager::default()),
            server_connect_plan: plan_rx,
            hello_identity: Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 4662,
                udp_port: 4672,
                server_ip: 0,
                server_port: 0,
                connect_options: 0,
                direct_udp_callback: false,
            },
            shared_catalog: Arc::new(RwLock::new(IndexedSharedCatalog::default())),
            state: Arc::clone(&state),
            search_inbox,
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            shutdown: Arc::clone(&shutdown),
            server_enabled: Arc::new(AtomicBool::new(true)),
            public_ip: ExternalReachability::default(),
            reconnect_signal: Arc::clone(&reconnect),
            server_list_events: Some(server_list_events),
            callback_sessions,
        };
        let task = tokio::spawn(run_ed2k_server_loop(options));
        TestServerLoop {
            plan,
            state,
            shutdown,
            reconnect,
            events,
            task,
        }
    }

    async fn stop_test_server_loop(runtime: TestServerLoop) {
        runtime.shutdown.store(true, Ordering::SeqCst);
        runtime.reconnect.notify_waiters();
        timeout(Duration::from_secs(2), runtime.task)
            .await
            .expect("server loop should stop promptly")
            .expect("server loop task should not panic");
    }

    async fn accept_login(listener: TcpListener) -> TcpStream {
        let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("server loop should connect")
            .expect("test server should accept connection");
        let mut header = [0u8; 6];
        timeout(Duration::from_secs(5), stream.read_exact(&mut header))
            .await
            .expect("server loop should send login")
            .expect("test server should read login header");
        assert_eq!(header[5], OP_LOGINREQUEST);
        let payload_len =
            usize::try_from(u32::from_le_bytes(header[1..5].try_into().unwrap())).unwrap() - 1;
        let mut payload = vec![0; payload_len];
        stream.read_exact(&mut payload).await.unwrap();
        stream
    }

    async fn establish_login(stream: &mut TcpStream) {
        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
    }

    async fn drain_until_closed(mut stream: TcpStream) {
        let mut buffer = [0; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }

    async fn wait_for_connected_endpoint(
        state: &Arc<RwLock<Ed2kServerState>>,
        endpoint: std::net::SocketAddr,
    ) {
        timeout(Duration::from_secs(5), async {
            loop {
                let snapshot = state.read().await.clone();
                if snapshot.connected && snapshot.endpoint == Some(endpoint) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("server loop should establish the selected endpoint");
    }

    async fn wait_for_connection_failures(
        events: &mut Ed2kServerListEventReceiver,
        expected: usize,
    ) {
        timeout(Duration::from_secs(5), async {
            let mut failures = 0;
            while failures < expected {
                if matches!(
                    events.recv().await,
                    Some(Ed2kServerListEvent::ConnectionFailed { .. })
                ) {
                    failures += 1;
                }
            }
        })
        .await
        .expect("server loop should report all failed attempts");
    }

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

        let selected = selected_configured_servers(&servers, Some("192.0.2.2:4661"), true);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].base_endpoint_text(), "192.0.2.2:4661");
    }

    #[test]
    fn unknown_target_is_not_synthesized_back_into_the_live_directory() {
        let servers = vec![server("192.0.2.1:4661"), server("192.0.2.2:4661")];

        let selected = selected_configured_servers(&servers, Some("192.0.2.99:4661"), true);

        assert!(selected.is_empty());
    }

    #[test]
    fn invalid_unknown_target_has_no_fallbacks() {
        let servers = vec![server("192.0.2.1:4661"), server("192.0.2.2:4661")];

        let selected = selected_configured_servers(&servers, Some("not-a-server"), true);

        assert!(selected.is_empty());
    }

    #[test]
    fn automatic_static_only_filters_without_reordering() {
        let mut dynamic = server("192.0.2.1:4661");
        dynamic.static_server = false;
        let static_server = server("192.0.2.2:4661");
        let mut dynamic_two = server("192.0.2.3:4661");
        dynamic_two.static_server = false;
        let servers = vec![dynamic, static_server, dynamic_two];

        let selected = selected_configured_servers(&servers, None, true);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].base_endpoint_text(), "192.0.2.2:4661");
    }

    #[test]
    fn explicit_target_bypasses_automatic_static_only_filter() {
        let mut dynamic = server("192.0.2.1:4661");
        dynamic.static_server = false;

        let selected = selected_configured_servers(&[dynamic], Some("192.0.2.1:4661"), true);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].base_endpoint_text(), "192.0.2.1:4661");
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

    #[tokio::test]
    async fn live_plan_adds_server_without_restarting_the_loop() {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_login(listener).await;
            establish_login(&mut stream).await;
            drain_until_closed(stream).await;
        });
        let runtime = spawn_test_server_loop(Ed2kServerConnectPlan::new(
            test_config(Vec::new(), true),
            Ed2kServerConnectMode::Manual,
        ));

        runtime.plan.send_replace(Ed2kServerConnectPlan::new(
            test_config(vec![endpoint.to_string()], true),
            Ed2kServerConnectMode::Manual,
        ));

        wait_for_connected_endpoint(&runtime.state, endpoint).await;
        stop_test_server_loop(runtime).await;
        timeout(Duration::from_secs(2), server)
            .await
            .expect("test server should observe loop shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn reconnect_disabled_loop_accepts_later_directed_plan() {
        let initial_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let initial_endpoint = initial_listener.local_addr().unwrap();
        let replacement_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let replacement_endpoint = replacement_listener.local_addr().unwrap();
        let (close_initial, close_initial_rx) = oneshot::channel();
        let initial_server = tokio::spawn(async move {
            let mut stream = accept_login(initial_listener).await;
            establish_login(&mut stream).await;
            let _ = close_initial_rx.await;
            drop(stream);
        });
        let replacement_server = tokio::spawn(async move {
            let mut stream = accept_login(replacement_listener).await;
            establish_login(&mut stream).await;
            drain_until_closed(stream).await;
        });
        let mut initial_config = test_config(vec![initial_endpoint.to_string()], true);
        initial_config.reconnect_enabled = false;
        let runtime = spawn_test_server_loop(Ed2kServerConnectPlan::new(
            initial_config,
            Ed2kServerConnectMode::Manual,
        ));
        wait_for_connected_endpoint(&runtime.state, initial_endpoint).await;
        close_initial.send(()).unwrap();
        initial_server.await.unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                let snapshot = runtime.state.read().await.clone();
                if snapshot.endpoint.is_none() && !snapshot.connecting && !snapshot.connected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed session should return to idle state");

        let mut replacement_config = test_config(vec![replacement_endpoint.to_string()], true);
        replacement_config.reconnect_enabled = false;
        runtime.plan.send_replace(Ed2kServerConnectPlan::new(
            replacement_config,
            Ed2kServerConnectMode::Directed(replacement_endpoint.to_string()),
        ));

        wait_for_connected_endpoint(&runtime.state, replacement_endpoint).await;
        stop_test_server_loop(runtime).await;
        timeout(Duration::from_secs(2), replacement_server)
            .await
            .expect("replacement server should observe loop shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn reconnect_disabled_parallel_exhaustion_accepts_later_directed_plan() {
        let first_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let first_endpoint = first_listener.local_addr().unwrap();
        let second_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let second_endpoint = second_listener.local_addr().unwrap();
        let replacement_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let replacement_endpoint = replacement_listener.local_addr().unwrap();
        let mut failed_servers = Vec::new();
        for listener in [first_listener, second_listener] {
            failed_servers.push(tokio::spawn(async move {
                let stream = accept_login(listener).await;
                drop(stream);
            }));
        }
        let replacement_server = tokio::spawn(async move {
            let mut stream = accept_login(replacement_listener).await;
            establish_login(&mut stream).await;
            drain_until_closed(stream).await;
        });
        let mut initial_config = test_config(
            vec![first_endpoint.to_string(), second_endpoint.to_string()],
            false,
        );
        initial_config.reconnect_enabled = false;
        let mut runtime = spawn_test_server_loop(Ed2kServerConnectPlan::new(
            initial_config,
            Ed2kServerConnectMode::Manual,
        ));
        wait_for_connection_failures(&mut runtime.events, 2).await;
        assert!(
            timeout(Duration::from_millis(250), runtime.plan.closed())
                .await
                .is_err(),
            "parallel exhaustion must retain the live plan receiver"
        );

        let mut replacement_config = test_config(vec![replacement_endpoint.to_string()], false);
        replacement_config.reconnect_enabled = false;
        runtime.plan.send_replace(Ed2kServerConnectPlan::new(
            replacement_config,
            Ed2kServerConnectMode::Directed(replacement_endpoint.to_string()),
        ));

        wait_for_connected_endpoint(&runtime.state, replacement_endpoint).await;
        stop_test_server_loop(runtime).await;
        failed_servers.push(replacement_server);
        for server in failed_servers {
            timeout(Duration::from_secs(2), server)
                .await
                .expect("test server should observe connection closure")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn directed_plan_change_cancels_pending_target_and_connects_unpinned_server() {
        let target_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let target_endpoint = target_listener.local_addr().unwrap();
        let fallback_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let fallback_endpoint = fallback_listener.local_addr().unwrap();
        let (target_login, target_login_rx) = oneshot::channel();
        let target_server = tokio::spawn(async move {
            let stream = accept_login(target_listener).await;
            let _ = target_login.send(());
            drain_until_closed(stream).await;
        });
        let fallback_server = tokio::spawn(async move {
            let mut stream = accept_login(fallback_listener).await;
            establish_login(&mut stream).await;
            drain_until_closed(stream).await;
        });
        let config = test_config(
            vec![target_endpoint.to_string(), fallback_endpoint.to_string()],
            true,
        );
        let runtime = spawn_test_server_loop(Ed2kServerConnectPlan::new(
            config.clone(),
            Ed2kServerConnectMode::Directed(target_endpoint.to_string()),
        ));
        timeout(Duration::from_secs(5), target_login_rx)
            .await
            .expect("directed target should receive a login")
            .unwrap();

        runtime.plan.send_replace(Ed2kServerConnectPlan::new(
            config,
            Ed2kServerConnectMode::Manual,
        ));

        wait_for_connected_endpoint(&runtime.state, fallback_endpoint).await;
        stop_test_server_loop(runtime).await;
        for server in [target_server, fallback_server] {
            timeout(Duration::from_secs(2), server)
                .await
                .expect("test server should observe connection closure")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn parallel_plan_change_prevents_stale_attempts_from_winning() {
        let first_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let first_endpoint = first_listener.local_addr().unwrap();
        let second_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let second_endpoint = second_listener.local_addr().unwrap();
        let replacement_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let replacement_endpoint = replacement_listener.local_addr().unwrap();
        let (accepted, mut accepted_rx) = tokio::sync::mpsc::channel(2);
        let (release, release_rx) = watch::channel(false);
        let mut stale_servers = Vec::new();
        for listener in [first_listener, second_listener] {
            let accepted = accepted.clone();
            let mut release_rx = release_rx.clone();
            stale_servers.push(tokio::spawn(async move {
                let mut stream = accept_login(listener).await;
                accepted.send(()).await.unwrap();
                release_rx.wait_for(|released| *released).await.unwrap();
                let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
                let _ = stream
                    .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
                    .await;
                drain_until_closed(stream).await;
            }));
        }
        drop(accepted);
        let replacement_server = tokio::spawn(async move {
            let mut stream = accept_login(replacement_listener).await;
            establish_login(&mut stream).await;
            drain_until_closed(stream).await;
        });
        let runtime = spawn_test_server_loop(Ed2kServerConnectPlan::new(
            test_config(
                vec![first_endpoint.to_string(), second_endpoint.to_string()],
                false,
            ),
            Ed2kServerConnectMode::Manual,
        ));
        for _ in 0..2 {
            timeout(Duration::from_secs(5), accepted_rx.recv())
                .await
                .expect("parallel attempts should both connect")
                .expect("parallel attempt signal should remain open");
        }

        runtime.plan.send_replace(Ed2kServerConnectPlan::new(
            test_config(vec![replacement_endpoint.to_string()], false),
            Ed2kServerConnectMode::Manual,
        ));
        release.send_replace(true);

        wait_for_connected_endpoint(&runtime.state, replacement_endpoint).await;
        stop_test_server_loop(runtime).await;
        stale_servers.push(replacement_server);
        for server in stale_servers {
            timeout(Duration::from_secs(2), server)
                .await
                .expect("test server should observe connection closure")
                .unwrap();
        }
    }
}
