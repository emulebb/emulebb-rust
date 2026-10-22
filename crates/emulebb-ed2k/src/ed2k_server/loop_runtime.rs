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
    task::{JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::Ed2kRuntimeConfig;
use crate::reachability::{ReachabilityUpdate, RuntimeReachabilityWriter, ServerReachabilityLease};

use super::server_description_poll::poll_server_descriptions;
use super::server_entry::{ConfiguredServerEntry, ResolvedServerEntry};
use super::server_events::Ed2kServerListEvent;
use super::types::{
    Ed2kServerConnectPlan, Ed2kServerState, ServerSessionActivation, ServerSessionActivator,
    ServerSessionContext,
};
use super::{
    Ed2kServerFailure, Ed2kServerLoopOptions, Ed2kServerSearchInbox, clear_server_connection_state,
    configured_server_entries, dump_ed2k_server_loop_meta, resolve_server_entry,
    run_one_server_session, session_driver::ServerSessionExit,
};

const ESTABLISHED_SESSION_RECONNECT_DELAY: Duration = Duration::from_secs(3);
const PARALLEL_ATTEMPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

struct AbortOnDropTask<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    async fn join(&mut self) -> Result<T, JoinError> {
        let result = self
            .handle
            .as_mut()
            .expect("owned task cannot be joined twice")
            .await;
        self.handle.take();
        result
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.as_ref() {
            handle.abort();
        }
    }
}

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
        server_control,
        public_ip,
        reachability_writer,
        server_list_events,
        callback_sessions,
    } = options;
    let server_enabled = server_control.enabled_flag();
    let reconnect_signal = server_control.wake_signal();
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
        session_cancel: CancellationToken::new(),
        public_ip,
        activation: ServerSessionActivation::active(),
        server_list_events,
        add_servers_from_server: initial_config.add_servers_from_server,
        offer_files_capability_enabled: initial_config.offer_files_capability_enabled,
        callback_sessions,
    };

    let description_cancel = CancellationToken::new();
    let mut description_task = AbortOnDropTask::new(tokio::spawn(poll_server_descriptions(
        bind_ip,
        server_connect_plan.clone(),
        Arc::clone(&state),
        session_context_base.public_ip.clone(),
        Arc::clone(&shutdown),
        Arc::clone(&server_enabled),
        session_context_base.server_list_events.clone(),
        description_cancel.clone(),
    )));

    'server_loop: while !shutdown.load(Ordering::Relaxed) {
        if !server_enabled.load(Ordering::SeqCst) {
            clear_server_connection_state(&state).await;
            server_control.acknowledge_disabled();
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
                &reachability_writer,
            )
            .await;
            match outcome {
                ParallelServerCycleOutcome::Shutdown => break,
                ParallelServerCycleOutcome::PlanChanged => continue,
                ParallelServerCycleOutcome::Exhausted
                | ParallelServerCycleOutcome::SessionEnded
                | ParallelServerCycleOutcome::ReconnectRequested => {}
            }
            if matches!(outcome, ParallelServerCycleOutcome::ReconnectRequested)
                && !server_enabled.load(Ordering::SeqCst)
            {
                continue;
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
                    let outcome = run_controlled_server_session(
                        &server,
                        &configured_server,
                        &session_context,
                        &search_inbox,
                        &mut server_connect_plan,
                        &reconnect_signal,
                        &reachability_writer,
                    )
                    .await;
                    match outcome {
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
                            if !server_enabled.load(Ordering::SeqCst) {
                                continue 'server_loop;
                            }
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
    description_cancel.cancel();
    let _ = description_task.join().await;
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
    runtime_reachability: &RuntimeReachabilityWriter,
) -> ControlledServerSessionOutcome {
    let Some(mut reachability) = runtime_reachability.begin_server_session() else {
        return ControlledServerSessionOutcome::Shutdown;
    };
    if reachability.activate() == ReachabilityUpdate::RejectedStale {
        return ControlledServerSessionOutcome::Shutdown;
    }
    let reachability_writer = reachability.writer();
    let mut session_context = context.clone();
    let session_cancel = CancellationToken::new();
    session_context.session_cancel = session_cancel.clone();
    let session =
        run_one_server_session(server, &session_context, search_inbox, &reachability_writer);
    tokio::pin!(session);
    let mut plan_changed = false;
    loop {
        tokio::select! {
            result = &mut session => {
                reachability.retire();
                return ControlledServerSessionOutcome::Finished { result, plan_changed };
            }
            changed = server_connect_plan.changed() => {
                if changed.is_err() {
                    reachability.retire();
                    session_cancel.cancel();
                    let _ = (&mut session).await;
                    return ControlledServerSessionOutcome::Shutdown;
                }
                let next_plan = server_connect_plan.borrow_and_update().clone();
                let connected = context.state.read().await.connected;
                if !connected || !plan_allows_configured_server(&next_plan, configured_server) {
                    reachability.retire();
                    session_cancel.cancel();
                    let _ = (&mut session).await;
                    return ControlledServerSessionOutcome::PlanChanged;
                }
                plan_changed = true;
            }
            () = reconnect_signal.notified() => {
                reachability.retire();
                session_cancel.cancel();
                let _ = (&mut session).await;
                return ControlledServerSessionOutcome::ReconnectRequested;
            }
            () = wait_for_shutdown(&context.shutdown) => {
                reachability.retire();
                session_cancel.cancel();
                let _ = (&mut session).await;
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
    activation: ServerSessionActivator,
    cancel: CancellationToken,
    reachability: ServerReachabilityLease,
    task: AbortOnDropTask<Result<ServerSessionExit, Error>>,
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
    runtime_reachability: &RuntimeReachabilityWriter,
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
                    return retire_parallel_cycle(
                        &mut active,
                        public_state,
                        ParallelServerCycleOutcome::PlanChanged,
                    )
                    .await;
                }
                Ok(false) => {}
                Err(_) => {
                    return retire_parallel_cycle(
                        &mut active,
                        public_state,
                        ParallelServerCycleOutcome::Shutdown,
                    )
                    .await;
                }
            }
            let Some(configured) = pending.pop_front() else {
                break;
            };
            let resolve_result = tokio::select! {
                result = resolve_server_entry(&configured) => Some(result),
                changed = server_connect_plan.changed() => {
                    let outcome = if changed.is_ok() {
                        ParallelServerCycleOutcome::PlanChanged
                    } else {
                        ParallelServerCycleOutcome::Shutdown
                    };
                    return retire_parallel_cycle(&mut active, public_state, outcome).await;
                }
                () = reconnect_signal.notified() => {
                    return retire_parallel_cycle(
                        &mut active,
                        public_state,
                        ParallelServerCycleOutcome::ReconnectRequested,
                    ).await;
                }
                () = wait_for_shutdown(&context.shutdown) => {
                    return retire_parallel_cycle(
                        &mut active,
                        public_state,
                        ParallelServerCycleOutcome::Shutdown,
                    ).await;
                }
            };
            match resolve_result.expect("resolve branch returns a result") {
                Ok(server) => {
                    let Some(reachability) = runtime_reachability.begin_server_session() else {
                        return retire_parallel_cycle(
                            &mut active,
                            public_state,
                            ParallelServerCycleOutcome::Shutdown,
                        )
                        .await;
                    };
                    let reachability_writer = reachability.writer();
                    let attempt_state = Arc::new(RwLock::new(Ed2kServerState::default()));
                    let mut attempt_context = context.clone();
                    attempt_context.state = Arc::clone(&attempt_state);
                    let (activation, activator) = ServerSessionActivation::pending();
                    attempt_context.activation = activation;
                    let cancel = CancellationToken::new();
                    attempt_context.session_cancel = cancel.clone();
                    let attempt_server = server.clone();
                    let attempt_inbox = Arc::clone(search_inbox);
                    let task = AbortOnDropTask::new(tokio::spawn(async move {
                        run_one_server_session(
                            &attempt_server,
                            &attempt_context,
                            &attempt_inbox,
                            &reachability_writer,
                        )
                        .await
                    }));
                    active.push(ParallelServerAttempt {
                        configured,
                        server,
                        state: attempt_state,
                        activation: activator,
                        cancel,
                        reachability,
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
            return retire_parallel_cycle(
                &mut active,
                public_state,
                ParallelServerCycleOutcome::Shutdown,
            )
            .await;
        }

        match server_connect_plan.has_changed() {
            Ok(true) => {
                return retire_parallel_cycle(
                    &mut active,
                    public_state,
                    ParallelServerCycleOutcome::PlanChanged,
                )
                .await;
            }
            Ok(false) => {}
            Err(_) => {
                return retire_parallel_cycle(
                    &mut active,
                    public_state,
                    ParallelServerCycleOutcome::Shutdown,
                )
                .await;
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
            retire_parallel_attempts(&mut active).await;
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
            let mut attempt = attempt;
            match attempt.task.join().await {
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
                let outcome = if changed.is_ok() {
                    ParallelServerCycleOutcome::PlanChanged
                } else {
                    ParallelServerCycleOutcome::Shutdown
                };
                return retire_parallel_cycle(&mut active, public_state, outcome).await;
            }
            () = reconnect_signal.notified() => {
                return retire_parallel_cycle(
                    &mut active,
                    public_state,
                    ParallelServerCycleOutcome::ReconnectRequested,
                ).await;
            }
            () = wait_for_shutdown(&context.shutdown) => {
                return retire_parallel_cycle(
                    &mut active,
                    public_state,
                    ParallelServerCycleOutcome::Shutdown,
                ).await;
            }
        }
    }
}

async fn retire_parallel_attempts(attempts: &mut Vec<ParallelServerAttempt>) {
    for attempt in attempts.iter_mut() {
        attempt.reachability.retire();
        attempt.activation.retire();
        attempt.cancel.cancel();
    }
    for attempt in attempts.iter_mut() {
        if let Err(error) = attempt.task.join().await
            && !error.is_cancelled()
        {
            warn!("ED2K parallel server task failed during retirement: {error}");
        }
    }
    attempts.clear();
}

async fn retire_parallel_cycle(
    attempts: &mut Vec<ParallelServerAttempt>,
    public_state: &Arc<RwLock<Ed2kServerState>>,
    outcome: ParallelServerCycleOutcome,
) -> ParallelServerCycleOutcome {
    retire_parallel_attempts(attempts).await;
    clear_server_connection_state(public_state).await;
    outcome
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
    mut winner: ParallelServerAttempt,
    public_state: &Arc<RwLock<Ed2kServerState>>,
    context: &ServerSessionContext,
    server_connect_plan: &mut watch::Receiver<Ed2kServerConnectPlan>,
    reconnect_signal: &Notify,
) -> ParallelServerCycleOutcome {
    let mut plan_changed = false;
    *public_state.write().await = winner.state.read().await.clone();
    if winner.reachability.activate() == ReachabilityUpdate::RejectedStale {
        winner.activation.retire();
        winner.cancel.cancel();
        let _ = winner.task.join().await;
        clear_server_connection_state(public_state).await;
        return ParallelServerCycleOutcome::Shutdown;
    }
    winner.activation.activate();
    loop {
        *public_state.write().await = winner.state.read().await.clone();
        if winner.task.is_finished() {
            let mut outcome = match winner.task.join().await {
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
            winner.reachability.retire();
            clear_server_connection_state(public_state).await;
            return outcome;
        }
        tokio::select! {
            () = tokio::time::sleep(PARALLEL_ATTEMPT_POLL_INTERVAL) => {}
            changed = server_connect_plan.changed() => {
                if changed.is_err() {
                    winner.reachability.retire();
                    winner.activation.retire();
                    winner.cancel.cancel();
                    let _ = winner.task.join().await;
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::Shutdown;
                }
                let next_plan = server_connect_plan.borrow_and_update().clone();
                let connected = winner.state.read().await.connected;
                if !connected || !plan_allows_configured_server(&next_plan, &winner.configured) {
                    winner.reachability.retire();
                    winner.activation.retire();
                    winner.cancel.cancel();
                    let _ = winner.task.join().await;
                    clear_server_connection_state(public_state).await;
                    return ParallelServerCycleOutcome::PlanChanged;
                }
                plan_changed = true;
            }
            () = reconnect_signal.notified() => {
                winner.reachability.retire();
                winner.activation.retire();
                winner.cancel.cancel();
                let _ = winner.task.join().await;
                clear_server_connection_state(public_state).await;
                return ParallelServerCycleOutcome::ReconnectRequested;
            }
            () = wait_for_shutdown(&context.shutdown) => {
                winner.reachability.retire();
                winner.activation.retire();
                winner.cancel.cancel();
                let _ = winner.task.join().await;
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
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        NatManager,
        ed2k_server::{
            Ed2kBackgroundSearchInterrupted, Ed2kServerConnectMode, Ed2kServerControlHandle,
            Ed2kServerListEventReceiver, Ed2kServerSearchHandle, OP_IDCHANGE, OP_LOGINREQUEST,
            OP_SEARCHREQUEST, OP_SERVERLIST, ed2k_server_control_channel,
            ed2k_server_list_event_channel, encode_packet, new_ed2k_server_search_channel,
            search_keyword_via_background_session,
        },
        ed2k_tcp::{Ed2kHelloIdentity, ed2k_callback_session_channel},
        ed2k_transfer::IndexedSharedCatalog,
        kad_firewall::KadFirewallState,
        reachability::{
            ExternalReachability, ReachabilityRuntimeAuthority, ReachabilityRuntimeLease,
        },
    };

    struct TestServerLoop {
        plan: watch::Sender<Ed2kServerConnectPlan>,
        state: Arc<RwLock<Ed2kServerState>>,
        reachability: ExternalReachability,
        shutdown: Arc<AtomicBool>,
        server_control: Ed2kServerControlHandle,
        search: Ed2kServerSearchHandle,
        events: Ed2kServerListEventReceiver,
        _reachability_lease: ReachabilityRuntimeLease,
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
        let (server_control, server_control_rx) = ed2k_server_control_channel(true);
        let (search, search_inbox) = new_ed2k_server_search_channel(1);
        let (callback_sessions, _callback_inbox) = ed2k_callback_session_channel();
        let (server_list_events, events) = ed2k_server_list_event_channel();
        let reachability_authority = ReachabilityRuntimeAuthority::new();
        let reachability = reachability_authority.reader();
        let reachability_lease = reachability_authority.begin_runtime();
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
            server_control: server_control_rx,
            public_ip: reachability.clone(),
            reachability_writer: reachability_lease.writer(),
            server_list_events: Some(server_list_events),
            callback_sessions,
        };
        let task = tokio::spawn(run_ed2k_server_loop(options));
        TestServerLoop {
            plan,
            state,
            reachability,
            shutdown,
            server_control,
            search,
            events,
            _reachability_lease: reachability_lease,
            task,
        }
    }

    async fn stop_test_server_loop(runtime: TestServerLoop) {
        runtime.shutdown.store(true, Ordering::SeqCst);
        runtime.server_control.wake_supervisor();
        timeout(Duration::from_secs(2), runtime.task)
            .await
            .expect("server loop should stop promptly")
            .expect("server loop task should not panic");
    }

    #[tokio::test]
    async fn retired_parallel_activation_wakes_pending_session() {
        let (activation, activator) = ServerSessionActivation::pending();
        let waiter = tokio::spawn(async move { activation.wait_until_active().await });

        activator.retire();

        assert!(
            !timeout(Duration::from_secs(1), waiter)
                .await
                .expect("retired activation waiter should complete")
                .unwrap()
        );
    }

    #[tokio::test]
    async fn disabling_server_lane_skips_reconnect_delay() {
        let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_login(listener).await;
            establish_login(&mut stream).await;
            drain_until_closed(stream).await;
        });
        let runtime = spawn_test_server_loop(Ed2kServerConnectPlan::new(
            test_config(vec![endpoint.to_string()], true),
            Ed2kServerConnectMode::Manual,
        ));
        wait_for_connected_endpoint(&runtime.state, endpoint).await;

        timeout(
            Duration::from_secs(1),
            runtime.server_control.disable_and_wait(),
        )
        .await
        .expect("server lane should retire without reconnect delay")
        .unwrap();

        let state = runtime.state.read().await.clone();
        assert!(!state.connecting);
        assert!(!state.connected);
        assert_eq!(state.endpoint, None);
        stop_test_server_loop(runtime).await;
        timeout(Duration::from_secs(2), server)
            .await
            .expect("test server should observe disabled session closure")
            .unwrap();
    }

    #[tokio::test]
    async fn forced_outer_abort_aborts_parallel_session_tasks() {
        let first_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let first_endpoint = first_listener.local_addr().unwrap();
        let second_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let second_endpoint = second_listener.local_addr().unwrap();
        let (accepted, mut accepted_rx) = tokio::sync::mpsc::channel(2);
        let mut servers = Vec::new();
        for listener in [first_listener, second_listener] {
            let accepted = accepted.clone();
            servers.push(tokio::spawn(async move {
                let stream = accept_login(listener).await;
                accepted.send(()).await.unwrap();
                drain_until_closed(stream).await;
            }));
        }
        drop(accepted);
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

        runtime.task.abort();
        timeout(Duration::from_secs(1), runtime.task)
            .await
            .expect("outer server loop should abort")
            .expect_err("outer server loop should report cancellation");

        for server in servers {
            timeout(Duration::from_secs(2), server)
                .await
                .expect("parallel server should observe descendant task closure")
                .unwrap();
        }
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
        establish_login_with_id(stream, u32::from_le_bytes([0x10, 0x20, 0x30, 0x40])).await;
    }

    async fn establish_login_with_id(stream: &mut TcpStream, high_id: u32) {
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
    }

    async fn read_client_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let payload_len =
            u32::from_le_bytes(header[1..5].try_into().unwrap()).saturating_sub(1) as usize;
        let mut payload = vec![0; payload_len];
        stream.read_exact(&mut payload).await.unwrap();
        (header[5], payload)
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
        assert!(runtime.reachability.is_known());
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
        assert_eq!(runtime.reachability.get(), None);

        let mut replacement_config = test_config(vec![replacement_endpoint.to_string()], true);
        replacement_config.reconnect_enabled = false;
        runtime.plan.send_replace(Ed2kServerConnectPlan::new(
            replacement_config,
            Ed2kServerConnectMode::Directed(replacement_endpoint.to_string()),
        ));

        wait_for_connected_endpoint(&runtime.state, replacement_endpoint).await;
        assert!(runtime.reachability.is_known());
        stop_test_server_loop(runtime).await;
        timeout(Duration::from_secs(2), replacement_server)
            .await
            .expect("replacement server should observe loop shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn parallel_attempt_publishes_only_selected_session_side_effects() {
        let losing_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let losing_endpoint = losing_listener.local_addr().unwrap();
        let winning_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let winning_endpoint = winning_listener.local_addr().unwrap();
        let losing_server = tokio::spawn(async move {
            let mut stream = accept_login(losing_listener).await;
            let mut server_list = vec![1, 192, 0, 2, 44];
            server_list.extend_from_slice(&4661u16.to_le_bytes());
            stream
                .write_all(&encode_packet(OP_SERVERLIST, &server_list, false).unwrap())
                .await
                .unwrap();
            drain_until_closed(stream).await;
        });
        let winning_id = u32::from_le_bytes([0x44, 0x33, 0x22, 0x11]);
        let winning_server = tokio::spawn(async move {
            let mut stream = accept_login(winning_listener).await;
            establish_login_with_id(&mut stream, winning_id).await;
            drain_until_closed(stream).await;
        });
        let mut config = test_config(
            vec![losing_endpoint.to_string(), winning_endpoint.to_string()],
            false,
        );
        config.add_servers_from_server = true;
        let mut runtime = spawn_test_server_loop(Ed2kServerConnectPlan::new(
            config,
            Ed2kServerConnectMode::Automatic,
        ));

        wait_for_connected_endpoint(&runtime.state, winning_endpoint).await;
        assert_eq!(runtime.reachability.octets(), [0x44, 0x33, 0x22, 0x11]);
        assert_eq!(
            timeout(Duration::from_secs(2), runtime.events.recv())
                .await
                .expect("winning login should publish a server event"),
            Some(Ed2kServerListEvent::ConnectSucceeded {
                endpoint: winning_endpoint.to_string(),
            })
        );
        assert!(
            timeout(Duration::from_millis(250), runtime.events.recv())
                .await
                .is_err(),
            "the losing attempt must not publish pre-activation server-list work"
        );

        let reachability = runtime.reachability.clone();
        stop_test_server_loop(runtime).await;
        assert_eq!(
            reachability.get(),
            None,
            "retired parallel winner must revoke its server public IP"
        );
        for server in [losing_server, winning_server] {
            timeout(Duration::from_secs(2), server)
                .await
                .expect("parallel test server should observe connection closure")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn plan_change_interrupts_claimed_background_work_before_replacement() {
        let initial_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let initial_endpoint = initial_listener.local_addr().unwrap();
        let replacement_listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
        let replacement_endpoint = replacement_listener.local_addr().unwrap();
        let (request_observed, request_observed_rx) = oneshot::channel();
        let initial_server = tokio::spawn(async move {
            let mut stream = accept_login(initial_listener).await;
            establish_login(&mut stream).await;
            loop {
                let (opcode, _) = read_client_frame(&mut stream).await;
                if opcode == OP_SEARCHREQUEST {
                    request_observed.send(()).unwrap();
                    break;
                }
            }
            drain_until_closed(stream).await;
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

        let search_handle = runtime.search.clone();
        let search = tokio::spawn(async move {
            search_keyword_via_background_session(
                &search_handle,
                "superseded query",
                Default::default(),
                Duration::from_secs(10),
                &CancellationToken::new(),
            )
            .await
        });
        timeout(Duration::from_secs(2), request_observed_rx)
            .await
            .expect("initial server should receive the claimed search")
            .unwrap();

        let mut replacement_config = test_config(vec![replacement_endpoint.to_string()], true);
        replacement_config.reconnect_enabled = false;
        runtime.plan.send_replace(Ed2kServerConnectPlan::new(
            replacement_config,
            Ed2kServerConnectMode::Directed(replacement_endpoint.to_string()),
        ));

        let error = timeout(Duration::from_secs(2), search)
            .await
            .expect("superseded search should complete promptly")
            .unwrap()
            .expect_err("superseded search should be retryable-interrupted");
        assert!(
            error
                .downcast_ref::<Ed2kBackgroundSearchInterrupted>()
                .is_some(),
            "unexpected superseded search error: {error:#}"
        );
        wait_for_connected_endpoint(&runtime.state, replacement_endpoint).await;

        stop_test_server_loop(runtime).await;
        for server in [initial_server, replacement_server] {
            timeout(Duration::from_secs(2), server)
                .await
                .expect("test server should observe session closure")
                .unwrap();
        }
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
