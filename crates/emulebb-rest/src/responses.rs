//! Pure REST response/view builders.
//!
//! These free functions translate `emulebb-core` domain values into the exact
//! JSON shapes the eMuleBB REST contract publishes. They were extracted verbatim
//! from `lib.rs` during the maintainability restructuring; behavior is unchanged.

use std::{collections::BTreeSet, path::Path as FsPath};

use emulebb_core::{
    AppInfo, AppLifecycle, LocalShare, NatStatusSnapshot, NetworkBindingStatus, NetworkStatus,
    Search, SearchResult, SearchSpec, ServerInfo, Status, Transfer, TransferEventDiagnostics,
    TransferThroughputStats, UploadPolicyMetrics, VpnGuardProbeStatus, VpnGuardStatus,
    normal_path_display,
};
use serde_json::{Value, json};

use crate::{BulkOperationResult, RestState, SearchResultsPage, SharedFileResponse};

pub(crate) const CONTRACT_VERSION: &str = "1.2.0";

pub(crate) fn lifecycle_response(lifecycle: &AppLifecycle) -> Value {
    let shutdown = lifecycle.state == "shuttingdown" || lifecycle.state == "done";
    json!({
        "state": lifecycle.state,
        "startupComplete": lifecycle.state == "running",
        "coreReady": lifecycle.state == "running",
        "sharedFilesReady": lifecycle.state == "running",
        "acceptingRest": !shutdown,
        "acceptingMutations": lifecycle.state == "running",
        "shutdownInProgress": shutdown
    })
}

pub(crate) fn app_info_response(app: AppInfo) -> Value {
    let capabilities = app
        .capabilities
        .into_iter()
        .map(|capability| (capability, Value::Bool(true)))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "name": app.name,
        "version": app.version,
        "apiVersion": app.api_version,
        // Match the eMuleBB master app metadata: build flavor + platform token.
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "platform": if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" },
        "lifecycle": lifecycle_response(&app.lifecycle),
        "capabilities": capabilities
    })
}

pub(crate) fn capabilities_response(app: AppInfo) -> Value {
    json!({
        "contractVersion": CONTRACT_VERSION,
        "apiVersion": app.api_version,
        "capabilities": app.capabilities
    })
}

pub(crate) fn stats_response(
    status: &Status,
    upload_policy: &UploadPolicyMetrics,
    throughput: &TransferThroughputStats,
    shared_hashing_count: i64,
) -> Value {
    let ed2k_connected = status.ed2k.connected;
    let kad_connected = status.kad.connected;
    let ed2k_high_id = ed2k_connected && !status.ed2k.firewalled.unwrap_or(false);
    let shared_hashing_active = shared_hashing_count > 0;
    json!({
        "connected": ed2k_connected || kad_connected,
        "downloadSpeedKiBps": throughput.download_rate_bytes_per_sec as f64 / 1024.0,
        "uploadSpeedKiBps": upload_policy.upload_rate_bytes_per_sec as f64 / 1024.0,
        "sessionDownloadedBytes": throughput.session_downloaded_bytes,
        "sessionUploadedBytes": throughput.session_uploaded_bytes,
        "activeDownloads": status.transfers.active,
        "activeUploads": upload_policy.active_sessions,
        "waitingUploads": upload_policy.waiting_sessions,
        "uploadBaseSlots": upload_policy.base_slots,
        "uploadElasticSlots": upload_policy.elastic_slots,
        "uploadEffectiveSlotCap": upload_policy.active_slots,
        "uploadLimitBytesPerSec": upload_policy.upload_limit_bytes_per_sec,
        "uploadElasticUnderfillBytesPerSec": upload_policy.elastic_underfill_bytes_per_sec,
        "uploadElasticUnderfill": upload_policy.elastic_underfill,
        "uploadUnderfillSinceMs": upload_policy.underfill_since_ms,
        "downloadCount": status.transfers.total,
        "sharedHashingActive": shared_hashing_active,
        "sharedHashingCount": shared_hashing_count,
        "sharedFilesReady": status.lifecycle.state == "running",
        "sharedFilesComplete": !shared_hashing_active,
        "ed2kConnected": ed2k_connected,
        "ed2kHighId": ed2k_high_id,
        "kadRunning": status.kad.running,
        "kadConnected": kad_connected,
        "kadFirewallState": firewall_state(status.kad.firewalled)
    })
}

pub(crate) async fn status_response(state: &RestState) -> Value {
    let status = state.core.status().await;
    let guard = state.core.vpn_guard_status();
    let network = state.core.network_binding_status();
    let upload_policy = state.core.upload_policy_metrics().await;
    let throughput = state.core.transfer_throughput_stats();
    let shared_directories = state.core.shared_directories().await;
    let shared_hashing_count = shared_directories.hashing_count;
    let shared_directory_reload_progress = shared_directories.reload_progress;
    let shared_hashing_active = shared_hashing_count > 0;
    let shared_file_count = state.core.shared_catalog_count().await;
    let download_file_count = status.transfers.total;
    let runtime_diagnostics = runtime_diagnostics_response_with(
        state,
        shared_file_count,
        download_file_count,
        shared_hashing_count,
        shared_directory_reload_progress.clone(),
        &upload_policy,
    );
    json!({
        "lifecycle": lifecycle_response(&status.lifecycle),
        "stats": stats_response(&status, &upload_policy, &throughput, shared_hashing_count),
        "servers": server_status_response(state).await,
        "kad": kad_response(&status.kad, network.as_ref(), &guard),
        "network": network_response(network.as_ref(), &guard),
        "sharedStartupCache": {
            "available": false,
            "ready": status.lifecycle.state == "running",
            "complete": !shared_hashing_active,
            "filePresent": false,
            "loaded": false,
            "rejected": false,
            "removed": false,
            "rejectCode": null,
            "recordsLoaded": 0,
            "volumesLoaded": 0,
            "hashingCount": shared_hashing_count,
            "deferredHashingActive": shared_hashing_active,
            "interruptedHashingInvalidatedCache": false,
            "reloadProgress": shared_directory_reload_progress.clone()
        },
        "runtimeDiagnostics": runtime_diagnostics
    })
}

pub(crate) async fn runtime_diagnostics_response(state: &RestState) -> Value {
    let status = state.core.status().await;
    let upload_policy = state.core.upload_policy_metrics().await;
    let shared_directories = state.core.shared_directories().await;
    let shared_file_count = state.core.shared_catalog_count().await;
    runtime_diagnostics_response_with(
        state,
        shared_file_count,
        status.transfers.total,
        shared_directories.hashing_count,
        shared_directories.reload_progress,
        &upload_policy,
    )
}

fn runtime_diagnostics_response_with(
    state: &RestState,
    shared_file_count: usize,
    download_file_count: usize,
    shared_hashing_count: i64,
    shared_directory_reload_progress: impl serde::Serialize,
    upload_policy: &UploadPolicyMetrics,
) -> Value {
    json!({
        "processId": std::process::id(),
        "knownFileCount": shared_file_count,
        "sharedFileCount": shared_file_count,
        "sharedHashingCount": shared_hashing_count,
        "sharedDirectoryReloadProgress": shared_directory_reload_progress,
        "ed2kPublish": state.core.ed2k_publish_diagnostics(),
        "kadPublish": state.core.kad_publish_diagnostics(),
        "transferEvents": state.core.transfer_event_diagnostics(),
        "downloadFileCount": download_file_count,
        "activeUploads": upload_policy.active_sessions,
        "waitingUploads": upload_policy.waiting_sessions,
        "geolocation": null
    })
}

pub(crate) fn transfer_event_diagnostics_response(diagnostics: &TransferEventDiagnostics) -> Value {
    json!({
        "enabled": diagnostics.enabled,
        "stream": diagnostics.stream,
        "channelCapacity": diagnostics.channel_capacity,
        "queuedEventCount": diagnostics.queued_event_count,
        "subscriberCount": diagnostics.subscriber_count,
        "latestEventId": diagnostics.latest_event_id,
        "nextEventId": diagnostics.next_event_id,
        "resumeBehavior": diagnostics.resume_behavior,
    })
}

pub(crate) fn network_response(
    network: Option<&NetworkBindingStatus>,
    guard: &VpnGuardStatus,
) -> Value {
    let network = network.cloned().unwrap_or_else(|| NetworkBindingStatus {
        resolve_result: "default".to_string(),
        ..NetworkBindingStatus::default()
    });
    json!({
        "ports": {
            "tcp": network.tcp_port,
            "udp": network.udp_port,
            "serverUdp": network.server_udp_port
        },
        "binding": {
            "configuredAddress": network.configured_address,
            "configuredInterfaceId": network.configured_interface_id,
            "configuredInterfaceName": network.configured_interface_name,
            "activeConfiguredAddress": network.active_configured_address,
            "activeInterfaceId": network.active_interface_id,
            "activeInterfaceName": network.active_interface_name,
            "activeInterfaceIndex": network.active_interface_index,
            "resolveResult": network.resolve_result
        },
        "vpnGuard": vpn_guard_response(guard)
    })
}

/// The `vpnGuard` REST object incl. the bound dual-plane egress-probe results
/// (eMuleBB `PublicIpProbe`): `stunProbe` (UDP) + `httpProbe` (TCP), the
/// probe-confirmed `publicIp`, and the `egressVerified` verdict.
pub(crate) fn vpn_guard_response(guard: &VpnGuardStatus) -> Value {
    json!({
        "enabled": guard.enabled,
        "mode": guard.mode,
        "allowedPublicIpCidrs": guard.allowed_public_ip_cidrs,
        "startupBlocked": guard.startup_blocked,
        "startupBlockReason": guard.startup_block_reason,
        "publicIp": guard.public_ip,
        "egressVerified": guard.egress_verified,
        "egressBlockReason": guard.egress_block_reason,
        "stunProbe": probe_json(&guard.stun_probe),
        "httpProbe": probe_json(&guard.http_probe)
    })
}

pub(crate) fn nat_response(status: &NatStatusSnapshot) -> Value {
    json!({
        "enabled": status.enabled,
        "gatewayDiscovered": status.gateway_discovered,
        "backend": status.backend,
        "protocol": status.protocol,
        "bindIp": status.bind_ip,
        "pcpServerIp": status.pcp_server_ip,
        "igdIp": status.igd_ip,
        "minissdpdSocket": status.minissdpd_socket,
        "ssdpLocalPort": status.ssdp_local_port,
        "externalIpOverride": status.external_ip_override,
        "gateway": status.gateway.as_ref().map(|gateway| json!({
            "backend": gateway.backend,
            "controlUrl": gateway.control_url,
            "localIp": gateway.local_ip,
            "gatewayIp": gateway.gateway_ip,
            "externalIp": gateway.external_ip
        })),
        "mappings": status.mappings.iter().map(|mapping| json!({
            "name": mapping.name,
            "protocol": serde_json::to_value(mapping.protocol).expect("transport protocol serializes"),
            "localAddr": mapping.local_addr.to_string(),
            "externalAddr": mapping.external_addr.to_string(),
            "leaseExpiresInSecs": mapping.lease_expires_in_secs,
            "backend": mapping.backend
        })).collect::<Vec<_>>(),
        "observedExternalAddresses": status.observed_external_addresses,
        "lastRefreshUnixSecs": status.last_refresh_unix_secs,
        "lastError": status.last_error
    })
}

fn probe_json(probe: &VpnGuardProbeStatus) -> Value {
    json!({
        "attempted": probe.attempted,
        "succeeded": probe.succeeded,
        "publicIp": probe.public_ip,
        "provider": probe.provider,
        "error": probe.error
    })
}

pub(crate) fn kad_response(
    kad: &NetworkStatus,
    network: Option<&NetworkBindingStatus>,
    guard: &VpnGuardStatus,
) -> Value {
    let contact_count = kad.contact_count.unwrap_or(kad.peer_count);
    json!({
        "running": kad.running,
        "connected": kad.connected,
        "firewallState": firewall_state(kad.firewalled),
        "bootstrapping": kad.bootstrapping.unwrap_or(false),
        "bootstrapProgress": kad.bootstrap_progress.unwrap_or(0),
        "contactCount": contact_count,
        "lanMode": kad.lan_mode.unwrap_or(false),
        "users": kad.users,
        "files": kad.files,
        "nodes": contact_count,
        "indexedSources": kad.indexed_sources.unwrap_or(0),
        "indexedKeywords": kad.indexed_keywords.unwrap_or(0),
        "operationQueued": kad.operation_queued.unwrap_or(false),
        "alreadyRunning": kad.already_running.unwrap_or(false),
        "blockedByVpnGuard": guard.startup_blocked,
        "network": network_response(network, guard)
    })
}

pub(crate) fn server_response(server: &ServerInfo) -> Value {
    let mut response = json!({
        "address": server.address,
        "port": server.port,
        "name": server.name,
        "priority": server.priority,
        "static": server.static_server,
        "enabled": server.enabled,
        "connected": server.connected,
        "connecting": server.connecting,
        "current": server.current,
        "description": server.description,
        "dynIp": server.dyn_ip,
        "auxiliaryPorts": server.auxiliary_ports,
        "failedCount": server.failed_count,
        "hardFiles": server.hard_files,
        "ip": server.ip,
        "ping": server.ping,
        "softFiles": server.soft_files,
        "offerFilesPublishedEntries": server.offer_files_published_entries,
        "offerFilesPendingEntries": server.offer_files_pending_entries,
        "version": server.version,
        "obfuscationTcpPort": server.obfuscation_tcp_port,
        "udpFlags": server.udp_flags,
        "users": server.users,
        "files": server.files,
        "hostName": server.host_name,
        "hostNameStatus": server.host_name_status,
        "hostNameResolvedAt": server.host_name_resolved_at,
        "hostNameError": server.host_name_error
    });
    let object = response
        .as_object_mut()
        .expect("server response is always a JSON object");
    if let Some(mode) = server.offer_files_mode.as_ref() {
        object.insert("offerFilesMode".to_string(), json!(mode));
    }
    if let Some(batch_max) = server.offer_files_batch_max {
        object.insert("offerFilesBatchMax".to_string(), json!(batch_max));
    }
    if let Some(min_interval_ms) = server.offer_files_min_interval_ms {
        object.insert(
            "offerFilesMinIntervalMs".to_string(),
            json!(min_interval_ms),
        );
    }
    if let Some(reason) = server.offer_files_fallback_reason.as_ref() {
        object.insert("offerFilesFallbackReason".to_string(), json!(reason));
    }
    response
}

pub(crate) fn server_responses(servers: Vec<ServerInfo>) -> Vec<Value> {
    servers.iter().map(server_response).collect()
}

pub(crate) async fn server_status_response(state: &RestState) -> Value {
    let status = state.core.status().await;
    let servers = state.core.servers().await;
    server_status_value(&status, &servers)
}

pub(crate) async fn server_connect_acknowledgement(state: &RestState) -> Value {
    let status = state.core.status().await;
    let servers = state.core.servers().await;
    server_connect_acknowledgement_value(&status, &servers)
}

fn server_connect_acknowledgement_value(status: &Status, servers: &[ServerInfo]) -> Value {
    let mut response = server_status_value(status, servers);
    let connected = response["connected"].as_bool().unwrap_or(false);
    let object = response
        .as_object_mut()
        .expect("server status response must be an object");
    object.insert("operationQueued".to_string(), Value::Bool(true));
    if !connected {
        // The core accepted the command and launched/notified the asynchronous
        // server loop. That worker may not have published its first endpoint yet,
        // so its instantaneous telemetry must not turn a successful POST into a
        // misleading disconnected-and-idle acknowledgement.
        object.insert("connecting".to_string(), Value::Bool(true));
    }
    response
}

pub(crate) fn server_status_value(status: &Status, servers: &[ServerInfo]) -> Value {
    let current_server = servers
        .iter()
        .find(|server| server.current)
        .map(server_response);
    let connecting = servers.iter().any(|server| server.connecting);
    json!({
        "connected": status.ed2k.connected,
        "connecting": connecting,
        "currentServer": current_server,
        "ed2kIdState": ed2k_id_state(status.ed2k.connected, status.ed2k.firewalled),
        "serverCount": servers.len()
    })
}

pub(crate) fn search_status_token(status: &str) -> &str {
    if status == "completed" {
        "complete"
    } else {
        status
    }
}

fn firewall_state(firewalled: Option<bool>) -> &'static str {
    match firewalled {
        Some(true) => "firewalled",
        Some(false) => "open",
        None => "unknown",
    }
}

fn ed2k_id_state(connected: bool, firewalled: Option<bool>) -> &'static str {
    match connected.then_some(firewalled).flatten() {
        Some(true) => "low",
        Some(false) => "high",
        None => "unknown",
    }
}

#[cfg(test)]
fn search_result_response(result: &SearchResult) -> Value {
    search_result_response_with_options(result, true)
}

pub(crate) fn search_result_response_with_options(
    result: &SearchResult,
    include_evidence: bool,
) -> Value {
    let extension = FsPath::new(&result.name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let observations = result
        .observations
        .iter()
        .map(|observation| {
            json!({
                "origin": observation.origin,
                "serverEndpoint": observation.server_endpoint,
                "name": observation.name,
                "sizeBytes": observation.size_bytes,
                "sources": observation.sources,
                "completeSources": observation.complete_sources,
                "sourceClientId": observation.source_client_id,
                "sourceClientPort": observation.source_client_port,
                "fileType": observation.file_type,
                "media": {
                    "artist": observation.media.artist,
                    "album": observation.media.album,
                    "title": observation.media.title,
                    "lengthSeconds": observation.media.length_seconds,
                    "bitrateKbps": observation.media.bitrate_kbps,
                    "codec": observation.media.codec,
                },
                "rating": observation.rating,
                "hasAichHash": !observation.aich_hash.is_empty(),
                "complete": observation.complete,
                "directory": observation.directory,
                "observedAt": observation.observed_at,
            })
        })
        .collect::<Vec<_>>();
    let observed_names = result
        .observations
        .iter()
        .map(|observation| observation.name.clone())
        .chain(std::iter::once(result.name.clone()))
        .filter(|name| !name.trim().is_empty())
        .collect::<BTreeSet<_>>();
    let observed_extensions = observed_names
        .iter()
        .filter_map(|name| {
            FsPath::new(name)
                .extension()
                .and_then(|extension| extension.to_str())
                .filter(|extension| !extension.is_empty())
                .map(str::to_ascii_lowercase)
        })
        .collect::<BTreeSet<_>>();
    let aich_hashes = result
        .observations
        .iter()
        .map(|observation| observation.aich_hash.as_str())
        .chain(std::iter::once(result.aich_hash.as_str()))
        .filter(|hash| !hash.is_empty())
        .collect::<BTreeSet<_>>();
    let observed_sources = result
        .observations
        .iter()
        .filter_map(|observation| {
            observation
                .source_client_id
                .zip(observation.source_client_port)
        })
        .collect::<BTreeSet<_>>();
    let divergent_names = observed_names.len() > 1;
    let has_aich_hash = !aich_hashes.is_empty();
    let multiple_aich = aich_hashes.len() > 1;
    let mut response = json!({
        "searchId": result.search_id,
        "type": result.r#type,
        "hash": result.hash,
        "name": result.name,
        "sizeBytes": result.size_bytes,
        "sources": result.sources,
        "completeSources": result.complete_sources,
        "fileType": result.file_type,
        "media": {
            "artist": result.media.artist,
            "album": result.media.album,
            "title": result.media.title,
            "lengthSeconds": result.media.length_seconds,
            "bitrateKbps": result.media.bitrate_kbps,
            "codec": result.media.codec,
        },
        "extension": extension,
        "complete": result.complete,
        "directory": result.directory,
        "rating": result.rating,
        "observations": observations,
    });
    if include_evidence {
        let mut availability = json!({
            "sources": result.sources,
            "completeSources": result.complete_sources,
        });
        if result.complete {
            availability["completionState"] = json!("complete");
        }
        if !observed_sources.is_empty() {
            availability["observedSourceEndpoints"] = json!(observed_sources.len());
        }
        response["evidence"] = json!({
            "availabilityEvidence": availability,
            "nameEvidence": {
                "observedNames": observed_names,
                "observedExtensions": observed_extensions,
                "divergent": divergent_names,
            },
            "integrityEvidence": {
                "hasAichHash": has_aich_hash,
                "multipleAich": multiple_aich,
            }
        });
    }
    response
}

pub(crate) fn search_results_response(
    results: &[SearchResult],
    include_evidence: bool,
) -> Vec<Value> {
    results
        .iter()
        .map(|result| search_result_response_with_options(result, include_evidence))
        .collect()
}

pub(crate) fn search_session_response(search: &Search) -> Value {
    json!({
        "id": search.id,
        "query": search.spec.query,
        "requestedMethod": search.spec.method,
        "resolvedMethod": search.resolved_method,
        "type": search.spec.r#type,
        "criteria": search_criteria_response(&search.spec),
        "status": search_status_token(&search.status),
        "statusReason": search.status_reason,
        "progress": search.progress,
        "resultCount": search.results.len()
    })
}

pub(crate) fn search_response(search: &Search) -> Value {
    // search/start contract: a freshly created search returns an empty first
    // page with the shared {items,total,offset,limit} shape (status "running").
    // Results are fetched by polling GET /searches/{id}.
    json!({
        "id": search.id,
        "query": search.spec.query,
        "requestedMethod": search.spec.method,
        "resolvedMethod": search.resolved_method,
        "type": search.spec.r#type,
        "criteria": search_criteria_response(&search.spec),
        "status": search_status_token(&search.status),
        "statusReason": search.status_reason,
        "progress": search.progress,
        "total": 0,
        "offset": 0,
        "limit": 100,
        "items": []
    })
}

pub(crate) fn search_page_response(search: &SearchResultsPage) -> Value {
    json!({
        "id": search.id,
        "query": search.spec.query,
        "requestedMethod": search.spec.method,
        "resolvedMethod": search.resolved_method,
        "type": search.spec.r#type,
        "criteria": search_criteria_response(&search.spec),
        "status": search_status_token(&search.status),
        "statusReason": search.status_reason,
        "progress": search.progress,
        "total": search.total,
        "offset": search.offset,
        "limit": search.limit,
        "sort": search.sort,
        "order": search.order,
        "items": search_results_response(&search.results, search.include_evidence)
    })
}

fn search_criteria_response(spec: &SearchSpec) -> Value {
    json!({
        "extension": spec.extension,
        "minSizeBytes": spec.min_size_bytes,
        "maxSizeBytes": spec.max_size_bytes,
        "minAvailability": spec.min_availability,
        "minCompleteSources": spec.min_complete_sources,
        "minBitrateKbps": spec.min_bitrate_kbps,
        "minLengthSeconds": spec.min_length_seconds,
        "codec": spec.codec,
        "title": spec.title,
        "album": spec.album,
        "artist": spec.artist,
    })
}

pub(crate) fn shared_file_response(share: &LocalShare) -> SharedFileResponse {
    let path = managed_shared_file_path(share);
    SharedFileResponse {
        hash: share.hash.clone(),
        name: share.name.clone(),
        directory: shared_file_directory(&path),
        path,
        size_bytes: share.size_bytes,
        priority: share.priority.clone(),
        auto_upload_priority: share.auto_upload_priority,
        requests: share.all_time_upload_requests,
        accepted_requests: share.all_time_upload_accepts,
        transferred_bytes: share.all_time_uploaded_bytes,
        all_time_requests: share.all_time_upload_requests,
        all_time_accepts: share.all_time_upload_accepts,
        all_time_transferred: share.all_time_uploaded_bytes,
        part_count: share.part_count,
        part_file: false,
        complete: true,
        comment: share.comment.clone(),
        rating: share.rating,
        has_comment: !share.comment.is_empty(),
        user_rating: share.rating,
        published_ed2k: true,
        shared_by_rule: false,
        ed2k_link: share.ed2k_link.clone(),
    }
}

pub(crate) fn managed_shared_file_path(share: &LocalShare) -> String {
    if let Some(source_path) = share.source_path.as_ref().filter(|path| !path.is_empty()) {
        return normal_path_display(source_path);
    }
    let path = FsPath::new(&share.transfer_dir);
    if path.is_dir() {
        normal_path_display(&path.join("pieces.bin").display().to_string())
    } else {
        normal_path_display(&share.transfer_dir)
    }
}

pub(crate) fn shared_file_directory(path: &str) -> String {
    normal_path_display(
        &FsPath::new(path)
            .parent()
            .map(|directory| directory.display().to_string())
            .unwrap_or_default(),
    )
}

pub(crate) fn bulk_result_from_transfer(transfer: &Transfer) -> BulkOperationResult {
    BulkOperationResult {
        ok: true,
        id: None,
        hash: Some(transfer.hash.clone()),
        name: Some(transfer.name.clone()),
        error: None,
    }
}

pub(crate) fn bulk_result_from_hash(hash: &str) -> BulkOperationResult {
    BulkOperationResult {
        ok: true,
        id: None,
        hash: Some(hash.to_string()),
        name: None,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use emulebb_core::{
        EmulebbCore, LocalShare, NetworkBindingStatus, NetworkStatus, SearchResult,
        SearchResultObservation, ServerInfo, TransferThroughputStats, VpnGuardStatus,
    };
    use emulebb_index::FileIndex;

    use super::{
        kad_response, network_response, search_result_response,
        server_connect_acknowledgement_value, server_status_value, shared_file_response,
        stats_response,
    };

    #[test]
    fn shared_file_response_exposes_persisted_upload_counters() {
        let response = shared_file_response(&LocalShare {
            hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Synthetic.Shared.bin".to_string(),
            size_bytes: 123,
            part_count: 1,
            ed2k_link: "ed2k://|file|Synthetic.Shared.bin|123|00112233445566778899aabbccddeeff|/"
                .to_string(),
            aich_root: String::new(),
            transfer_dir: "transfers".to_string(),
            source_path: Some(r"\\?\C:\shared\Synthetic.Shared.bin".to_string()),
            priority: "normal".to_string(),
            auto_upload_priority: false,
            all_time_uploaded_bytes: 4096,
            all_time_upload_requests: 7,
            all_time_upload_accepts: 5,
            comment: String::new(),
            rating: 0,
        });

        assert_eq!(response.requests, 7);
        assert_eq!(response.accepted_requests, 5);
        assert_eq!(response.transferred_bytes, 4096);
        assert_eq!(response.all_time_requests, 7);
        assert_eq!(response.all_time_accepts, 5);
        assert_eq!(response.all_time_transferred, 4096);
        assert_eq!(response.path, r"C:\shared\Synthetic.Shared.bin");
        assert_eq!(
            response.directory,
            if cfg!(windows) { r"C:\shared" } else { "" }
        );
    }

    #[test]
    fn search_result_response_emits_only_supported_evidence() {
        let mut result = SearchResult {
            search_id: "search-1".to_string(),
            r#type: "doc".to_string(),
            hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "sample.bin".to_string(),
            size_bytes: 1024,
            sources: 2,
            complete_sources: 1,
            source_client_id: None,
            source_client_port: None,
            file_type: "doc".to_string(),
            media: emulebb_core::SearchResultMedia {
                artist: "Example Artist".to_string(),
                album: "Example Album".to_string(),
                title: "Example Title".to_string(),
                length_seconds: 321,
                bitrate_kbps: 192,
                codec: "FLAC".to_string(),
            },
            rating: 4,
            aich_hash: "A".repeat(32),
            complete: true,
            directory: String::new(),
            observations: Vec::new(),
        };
        result.observations.push(SearchResultObservation {
            origin: "global".to_string(),
            server_endpoint: Some("192.0.2.10:4661".to_string()),
            name: result.name.clone(),
            size_bytes: result.size_bytes,
            sources: result.sources,
            complete_sources: result.complete_sources,
            source_client_id: None,
            source_client_port: None,
            file_type: result.file_type.clone(),
            media: result.media.clone(),
            rating: result.rating,
            aich_hash: result.aich_hash.clone(),
            complete: result.complete,
            directory: result.directory.clone(),
            observed_at: Default::default(),
        });

        let complete = search_result_response(&result);
        assert_eq!(complete["complete"], true);
        assert_eq!(complete["rating"], 4);
        assert_eq!(complete["media"]["artist"], "Example Artist");
        assert_eq!(complete["media"]["album"], "Example Album");
        assert_eq!(complete["media"]["title"], "Example Title");
        assert_eq!(complete["media"]["lengthSeconds"], 321);
        assert_eq!(complete["media"]["bitrateKbps"], 192);
        assert_eq!(complete["media"]["codec"], "FLAC");
        assert_eq!(
            complete["observations"][0]["serverEndpoint"],
            "192.0.2.10:4661"
        );
        assert!(complete.get("method").is_none());
        assert!(complete.get("knownType").is_none());
        assert!(complete.get("clientIp").is_none());
        assert!(complete.get("serverCount").is_none());
        assert!(complete["evidence"].get("confidence").is_none());
        assert_eq!(
            complete["evidence"]["integrityEvidence"]["hasAichHash"],
            true
        );
        assert_eq!(
            complete["evidence"]["availabilityEvidence"]["completionState"],
            "complete"
        );
        assert!(
            complete["evidence"]["availabilityEvidence"]
                .get("complete")
                .is_none()
        );

        result.complete = false;
        let incomplete = search_result_response(&result);
        assert!(
            incomplete["evidence"]["availabilityEvidence"]
                .get("completionState")
                .is_none()
        );
    }

    #[test]
    fn kad_response_surfaces_indexed_counts() {
        let guard = VpnGuardStatus::default();
        let mut kad = NetworkStatus {
            running: true,
            connected: true,
            peer_count: 7,
            firewalled: Some(false),
            bootstrapping: Some(false),
            bootstrap_progress: Some(100),
            contact_count: Some(7),
            lan_mode: Some(false),
            users: Some(0),
            files: Some(0),
            indexed_sources: Some(42),
            indexed_keywords: Some(13),
            operation_queued: None,
            already_running: None,
        };
        let value = kad_response(&kad, None, &guard);
        assert_eq!(value["indexedSources"], 42);
        assert_eq!(value["indexedKeywords"], 13);
        assert_eq!(value["firewallState"], "open");

        // When Kad is not running the counts are unknown -> reported as 0.
        kad.firewalled = None;
        kad.indexed_sources = None;
        kad.indexed_keywords = None;
        let value = kad_response(&kad, None, &guard);
        assert_eq!(value["indexedSources"], 0);
        assert_eq!(value["indexedKeywords"], 0);
        assert_eq!(value["firewallState"], "unknown");
    }

    #[test]
    fn network_response_defaults_without_configured_ed2k_network() {
        let value = network_response(None, &VpnGuardStatus::off());

        assert_eq!(value["ports"]["tcp"], 0);
        assert_eq!(value["ports"]["udp"], 0);
        assert_eq!(value["binding"]["resolveResult"], "default");
    }

    #[test]
    fn network_response_reports_configured_ports_and_binding() {
        let network = NetworkBindingStatus {
            tcp_port: 4662,
            udp_port: 4672,
            server_udp_port: None,
            configured_address: "192.0.2.10".to_string(),
            configured_interface_id: "hide.me".to_string(),
            configured_interface_name: "hide.me".to_string(),
            active_configured_address: "192.0.2.10".to_string(),
            active_interface_id: "hide.me".to_string(),
            active_interface_name: "hide.me".to_string(),
            active_interface_index: 17,
            resolve_result: "resolved".to_string(),
        };

        let value = network_response(Some(&network), &VpnGuardStatus::off());

        assert_eq!(value["ports"]["tcp"], 4662);
        assert_eq!(value["ports"]["udp"], 4672);
        assert!(value["ports"]["serverUdp"].is_null());
        assert_eq!(value["binding"]["configuredAddress"], "192.0.2.10");
        assert_eq!(value["binding"]["activeInterfaceIndex"], 17);
        assert_eq!(value["binding"]["resolveResult"], "resolved");
    }

    #[tokio::test]
    async fn stats_response_reports_real_throughput_and_omits_optional_totals() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let status = core.status().await;
        let upload_policy = core.upload_policy_metrics().await;
        let throughput = TransferThroughputStats {
            download_rate_bytes_per_sec: 4096,
            session_downloaded_bytes: 1_048_576,
            session_uploaded_bytes: 524_288,
        };
        let value = stats_response(&status, &upload_policy, &throughput, 0);
        assert_eq!(value["downloadSpeedKiBps"], 4.0);
        assert_eq!(value["sessionDownloadedBytes"], 1_048_576);
        assert_eq!(value["sessionUploadedBytes"], 524_288);
        assert_eq!(value["sharedHashingActive"], false);
        assert_eq!(value["sharedHashingCount"], 0);
        assert_eq!(value["sharedFilesReady"], true);
        assert_eq!(value["sharedFilesComplete"], true);
        // Lifetime totals are optional in the contract and eMuleBB omits them; we
        // omit rather than emit a misleading 0 (no lifetime persistence).
        assert!(value.get("totalDownloadedBytes").is_none());
        assert!(value.get("totalUploadedBytes").is_none());
    }

    #[tokio::test]
    async fn stats_response_reports_active_shared_hashing() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let status = core.status().await;
        let upload_policy = core.upload_policy_metrics().await;
        let throughput = TransferThroughputStats::default();

        let value = stats_response(&status, &upload_policy, &throughput, 3);

        assert_eq!(value["sharedHashingActive"], true);
        assert_eq!(value["sharedHashingCount"], 3);
        assert_eq!(value["sharedFilesReady"], true);
        assert_eq!(value["sharedFilesComplete"], false);
    }

    #[tokio::test]
    async fn stats_response_reports_ed2k_low_id_as_not_high_id() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let mut status = core.status().await;
        status.ed2k.connected = true;
        status.ed2k.firewalled = Some(true);
        let upload_policy = core.upload_policy_metrics().await;
        let throughput = TransferThroughputStats::default();

        let value = stats_response(&status, &upload_policy, &throughput, 0);

        assert_eq!(value["ed2kConnected"], true);
        assert_eq!(value["ed2kHighId"], false);
        assert_eq!(value["kadFirewallState"], "unknown");
    }

    #[tokio::test]
    async fn server_status_reports_connected_low_id_verdict() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let mut status = core.status().await;

        let disconnected = server_status_value(&status, &[]);
        assert_eq!(disconnected["ed2kIdState"], "unknown");

        status.ed2k.connected = true;
        status.ed2k.firewalled = Some(true);
        let low_id = server_status_value(&status, &[]);
        assert_eq!(low_id["ed2kIdState"], "low");

        status.ed2k.firewalled = Some(false);
        let high_id = server_status_value(&status, &[]);
        assert_eq!(high_id["ed2kIdState"], "high");
    }

    #[tokio::test]
    async fn server_status_reports_connecting_current_server() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let status = core.status().await;
        let servers = vec![ServerInfo {
            address: "203.0.113.9".to_string(),
            port: 4661,
            endpoint: "203.0.113.9:4661".to_string(),
            name: "test server".to_string(),
            priority: "normal".to_string(),
            static_server: true,
            enabled: true,
            connected: false,
            connecting: true,
            current: true,
            description: String::new(),
            dyn_ip: String::new(),
            auxiliary_ports: vec![4662, 4663],
            failed_count: 0,
            hard_files: 0,
            ip: String::new(),
            ping: 0,
            soft_files: 0,
            offer_files_mode: Some("negotiatedV1".to_string()),
            offer_files_batch_max: Some(300),
            offer_files_min_interval_ms: Some(1_500),
            offer_files_fallback_reason: Some("none".to_string()),
            offer_files_published_entries: 400,
            offer_files_pending_entries: 25,
            version: String::new(),
            obfuscation_tcp_port: Some(4665),
            obfuscation_udp_port: Some(4675),
            udp_flags: Some(0x331),
            udp_key: Some(0x1122_3344),
            udp_key_ip: Some(0x5566_7788),
            max_users: 0,
            low_id_users: 0,
            users: 0,
            files: 0,
            host_name: None,
            host_name_status: None,
            host_name_resolved_at: None,
            host_name_error: None,
        }];

        let value = server_status_value(&status, &servers);

        assert_eq!(value["connected"], false);
        assert_eq!(value["connecting"], true);
        assert_eq!(value["currentServer"]["connecting"], true);
        assert_eq!(value["currentServer"]["connected"], false);
        assert_eq!(value["currentServer"]["auxiliaryPorts"][0], 4662);
        assert_eq!(value["currentServer"]["auxiliaryPorts"][1], 4663);
        assert_eq!(value["currentServer"]["offerFilesMode"], "negotiatedV1");
        assert_eq!(value["currentServer"]["offerFilesBatchMax"], 300);
        assert_eq!(value["currentServer"]["offerFilesMinIntervalMs"], 1_500);
        assert_eq!(value["currentServer"]["offerFilesFallbackReason"], "none");
        assert_eq!(value["currentServer"]["offerFilesPublishedEntries"], 400);
        assert_eq!(value["currentServer"]["offerFilesPendingEntries"], 25);
        assert_eq!(value["currentServer"]["obfuscationTcpPort"], 4665);
        assert_eq!(value["currentServer"]["udpFlags"], 0x331);
        assert_eq!(value["ed2kIdState"], "unknown");
    }

    #[tokio::test]
    async fn server_connect_acknowledges_queued_work_before_worker_state_updates() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let status = core.status().await;

        let value = server_connect_acknowledgement_value(&status, &[]);

        assert_eq!(value["connected"], false);
        assert_eq!(value["connecting"], true);
        assert_eq!(value["operationQueued"], true);
        assert!(value["currentServer"].is_null());
    }
}
