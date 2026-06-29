use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use tracing::{info, warn};

use super::server_entry::ConfiguredServerEntry;
use super::server_events::Ed2kServerListEvent;
use super::types::ServerSessionContext;
use super::{
    Ed2kServerLoopOptions, clear_server_connection_state, configured_server_entries,
    resolve_server_entry, run_one_server_session,
};
/// Runs the minimal oracle-shaped ED2K server session loop for the configured endpoints.
#[allow(clippy::cognitive_complexity)]
pub async fn run_ed2k_server_loop(options: Ed2kServerLoopOptions) {
    let Ed2kServerLoopOptions {
        bind_ip,
        nat,
        config,
        hello_identity,
        shared_catalog,
        state,
        mut search_inbox,
        kad_firewall,
        shutdown,
        public_ip,
        reconnect_signal,
        target_server_endpoint,
        server_list_events,
    } = options;
    let reconnect_delay = Duration::from_secs(config.reconnect_interval_secs.max(1));
    let session_context = ServerSessionContext {
        bind_ip,
        nat,
        hello_identity,
        probe_search_term: config.probe_search_term.clone(),
        shared_catalog,
        state: Arc::clone(&state),
        kad_firewall,
        keepalive_interval: Duration::from_secs(config.keepalive_secs.max(1)),
        // Server connect budget (eMule CONSERVTIMEOUT = SEC2MS(25), Opcodes.h:109).
        connect_timeout: Duration::from_secs(config.server_connect_timeout_secs.max(1)),
        rotation_interval: (config.session_rotation_secs > 0)
            .then(|| Duration::from_secs(config.session_rotation_secs)),
        shutdown: Arc::clone(&shutdown),
        public_ip,
        reconnect_signal,
        server_list_events,
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
    let reconnect_enabled = config.reconnect_enabled;

    while !shutdown.load(Ordering::Relaxed) {
        let mut attempted_any = false;
        let target_endpoint = target_server_endpoint.read().await.clone();
        for configured_server in
            ordered_configured_servers(&configured_servers, target_endpoint.as_deref())
        {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            attempted_any = true;
            match resolve_server_entry(&configured_server).await {
                Ok(server) => {
                    if let Err(error) =
                        run_one_server_session(&server, &session_context, &mut search_inbox).await
                    {
                        clear_server_connection_state(&state).await;
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
                Err(error) => {
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

            if reconnect_enabled && !shutdown.load(Ordering::Relaxed) {
                tokio::select! {
                    () = tokio::time::sleep(reconnect_delay) => {}
                    () = session_context.reconnect_signal.notified() => {
                        info!(
                            "ED2K server reconnect delay interrupted by explicit reconnect request"
                        );
                    }
                }
            }
        }
        if !reconnect_enabled {
            info!(
                "ED2K server reconnect disabled by preferences; leaving background session stopped"
            );
            return;
        }

        if !attempted_any && !shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(reconnect_delay).await;
        }
    }
}

fn ordered_configured_servers(
    configured_servers: &[ConfiguredServerEntry],
    target_endpoint: Option<&str>,
) -> Vec<ConfiguredServerEntry> {
    let Some(target_endpoint) = target_endpoint else {
        return configured_servers.to_vec();
    };
    let Some(target_index) = configured_servers.iter().position(|entry| {
        entry
            .base_endpoint_text()
            .eq_ignore_ascii_case(target_endpoint)
    }) else {
        return configured_servers.to_vec();
    };
    let mut ordered = Vec::with_capacity(configured_servers.len());
    ordered.push(configured_servers[target_index].clone());
    ordered.extend(
        configured_servers
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != target_index)
            .map(|(_, entry)| entry.clone()),
    );
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(endpoint: &str) -> ConfiguredServerEntry {
        ConfiguredServerEntry::from_endpoint_text(endpoint).unwrap()
    }

    #[test]
    fn targeted_server_is_tried_first_without_dropping_fallbacks() {
        let servers = vec![
            server("192.0.2.1:4661"),
            server("192.0.2.2:4661"),
            server("192.0.2.3:4661"),
        ];

        let ordered = ordered_configured_servers(&servers, Some("192.0.2.2:4661"));

        assert_eq!(ordered[0].base_endpoint_text(), "192.0.2.2:4661");
        assert_eq!(ordered[1].base_endpoint_text(), "192.0.2.1:4661");
        assert_eq!(ordered[2].base_endpoint_text(), "192.0.2.3:4661");
    }

    #[test]
    fn unknown_target_keeps_configured_order() {
        let servers = vec![server("192.0.2.1:4661"), server("192.0.2.2:4661")];

        let ordered = ordered_configured_servers(&servers, Some("192.0.2.99:4661"));

        assert_eq!(ordered, servers);
    }
}
