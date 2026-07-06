//! Pure REST response/view builders.
//!
//! These free functions translate `emulebb-core` domain values into the exact
//! JSON shapes the eMuleBB REST contract publishes. They were extracted verbatim
//! from `lib.rs` during the maintainability restructuring; behavior is unchanged.

use std::path::Path as FsPath;

use emulebb_core::{
    AppInfo, AppLifecycle, LocalShare, NetworkBindingStatus, NetworkStatus, Search, SearchResult,
    ServerInfo, Status, Transfer, TransferThroughputStats, UploadPolicyMetrics,
    VpnGuardProbeStatus, VpnGuardStatus,
};
use serde_json::{Value, json};

use crate::{BulkOperationResult, RestState, SearchResultsPage, SharedFileResponse};

const CONTRACT_VERSION: &str = "1.2.0";

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
        "kadFirewalled": status.kad.firewalled
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
    let shared_reload = shared_directories.reload;
    let shared_hashing_active = shared_hashing_count > 0;
    let shared_file_count = state.core.shared_catalog_count().await;
    let download_file_count = status.transfers.total;
    let ed2k_publish = state.core.ed2k_publish_diagnostics();
    let kad_publish = state.core.kad_publish_diagnostics();
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
            "reload": shared_reload.clone()
        },
        "runtimeDiagnostics": {
            "processId": std::process::id(),
            "knownFileCount": shared_file_count,
            "sharedFileCount": shared_file_count,
            "sharedHashingCount": shared_hashing_count,
            "sharedReload": shared_reload,
            "ed2kPublish": ed2k_publish,
            "kadPublish": kad_publish,
            "downloadFileCount": download_file_count,
            "activeUploads": upload_policy.active_sessions,
            "waitingUploads": upload_policy.waiting_sessions,
            "geolocation": null
        }
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
        "vpnGuard": vpn_guard_json(guard)
    })
}

/// The `vpnGuard` REST object incl. the bound dual-plane egress-probe results
/// (eMuleBB `PublicIpProbe`): `stunProbe` (UDP) + `httpProbe` (TCP), the
/// probe-confirmed `publicIp`, and the `egressVerified` verdict.
fn vpn_guard_json(guard: &VpnGuardStatus) -> Value {
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
        "firewalled": kad.firewalled,
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
    json!({
        "address": server.address,
        "port": server.port,
        "name": server.name,
        "priority": server.priority,
        "static": server.static_server,
        "connected": server.connected,
        "connecting": server.connecting,
        "current": server.current,
        "description": server.description,
        "dynIp": server.dyn_ip,
        "failedCount": server.failed_count,
        "hardFiles": server.hard_files,
        "ip": server.ip,
        "ping": server.ping,
        "softFiles": server.soft_files,
        "version": server.version,
        "users": server.users,
        "files": server.files
    })
}

pub(crate) fn server_responses(servers: Vec<ServerInfo>) -> Vec<Value> {
    servers.iter().map(server_response).collect()
}

pub(crate) async fn server_status_response(state: &RestState) -> Value {
    let status = state.core.status().await;
    let servers = state.core.servers().await;
    server_status_value(&status, &servers)
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
        "lowId": status
            .ed2k
            .connected
            .then(|| status.ed2k.firewalled.unwrap_or(false)),
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

pub(crate) fn search_result_response(result: &SearchResult) -> Value {
    let extension = FsPath::new(&result.name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    json!({
        "searchId": result.search_id,
        "method": result.method,
        "type": result.r#type,
        "hash": result.hash,
        "name": result.name,
        "sizeBytes": result.size_bytes,
        "sources": result.sources,
        "completeSources": result.complete_sources,
        "fileType": result.file_type,
        "extension": extension,
        "complete": result.complete,
        "knownType": result.known_type,
        "directory": result.directory,
        "clientIp": "",
        "clientPort": 0,
        "serverIp": "",
        "serverPort": 0,
        "clientCount": 0,
        "serverCount": 0,
        "kadPublishInfo": 0,
        "rating": 0,
        "hasComment": false,
        "spam": false,
        "evidence": {
            "confidence": {
                "band": "looks_good",
                "score": 70,
                "fakeScore": 0,
                "severity": "none",
                "spam": false,
                "userRating": 0,
                "kadBand": "unknown",
                "reasons": []
            },
            "availabilityEvidence": {
                "sources": result.sources,
                "completeSources": result.complete_sources,
                "complete": result.complete,
                "clientCount": 0,
                "serverCount": 0,
                "kadPublishers": 0
            },
            "nameEvidence": {
                "observedNames": [result.name],
                "observedExtensions": if extension.is_empty() { json!([]) } else { json!([extension]) },
                "canonicalNames": [result.name],
                "ignoredNameTokens": [],
                "divergenceGroups": [],
                "divergent": false
            },
            "integrityEvidence": {
                "hasAichHash": false,
                "multipleAich": false,
                "pendingHeaderCheck": false,
                "cachedHeaderEvidence": false,
                "claimedType": null,
                "extensionType": null,
                "detectedHeaderType": null
            }
        }
    })
}

pub(crate) fn search_results_response(results: &[SearchResult]) -> Vec<Value> {
    results.iter().map(search_result_response).collect()
}

pub(crate) fn search_session_response(search: &Search) -> Value {
    json!({
        "id": search.id,
        "query": search.query,
        "method": search.method,
        "type": search.r#type,
        "status": search_status_token(&search.status),
        "statusReason": search.status_reason,
        "resultCount": search.results.len()
    })
}

pub(crate) fn search_response(search: &Search) -> Value {
    // search/start contract: a freshly created search returns an empty first
    // page with the shared {items,total,offset,limit} shape (status "running").
    // Results are fetched by polling GET /searches/{id}.
    json!({
        "id": search.id,
        "query": search.query,
        "method": search.method,
        "type": search.r#type,
        "status": search_status_token(&search.status),
        "statusReason": search.status_reason,
        "total": 0,
        "offset": 0,
        "limit": 100,
        "items": []
    })
}

pub(crate) fn search_page_response(search: &SearchResultsPage) -> Value {
    json!({
        "id": search.id,
        "query": search.query,
        "method": search.method,
        "type": search.file_type,
        "status": search_status_token(&search.status),
        "statusReason": search.status_reason,
        "total": search.total,
        "offset": search.offset,
        "limit": search.limit,
        "items": search_results_response(&search.results)
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
        return source_path.clone();
    }
    let path = FsPath::new(&share.transfer_dir);
    if path.is_dir() {
        path.join("pieces.bin").display().to_string()
    } else {
        share.transfer_dir.clone()
    }
}

pub(crate) fn shared_file_directory(path: &str) -> String {
    FsPath::new(path)
        .parent()
        .map(|directory| directory.display().to_string())
        .unwrap_or_default()
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
        EmulebbCore, LocalShare, NetworkBindingStatus, NetworkStatus, ServerInfo,
        TransferThroughputStats, VpnGuardStatus,
    };
    use emulebb_index::FileIndex;

    use super::{
        kad_response, network_response, server_status_value, shared_file_response, stats_response,
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
            source_path: Some("shared/Synthetic.Shared.bin".to_string()),
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
        assert_eq!(response.path, "shared/Synthetic.Shared.bin");
        assert_eq!(response.directory, "shared");
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

        // When Kad is not running the counts are unknown -> reported as 0.
        kad.indexed_sources = None;
        kad.indexed_keywords = None;
        let value = kad_response(&kad, None, &guard);
        assert_eq!(value["indexedSources"], 0);
        assert_eq!(value["indexedKeywords"], 0);
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
            server_udp_port: 0,
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
        assert_eq!(value["ports"]["serverUdp"], 0);
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
    }

    #[tokio::test]
    async fn server_status_reports_connected_low_id_verdict() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let mut status = core.status().await;

        let disconnected = server_status_value(&status, &[]);
        assert!(disconnected["lowId"].is_null());

        status.ed2k.connected = true;
        status.ed2k.firewalled = Some(true);
        let low_id = server_status_value(&status, &[]);
        assert_eq!(low_id["lowId"], true);

        status.ed2k.firewalled = Some(false);
        let high_id = server_status_value(&status, &[]);
        assert_eq!(high_id["lowId"], false);
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
            connected: false,
            connecting: true,
            current: true,
            description: String::new(),
            dyn_ip: String::new(),
            failed_count: 0,
            hard_files: 0,
            ip: String::new(),
            ping: 0,
            soft_files: 0,
            version: String::new(),
            users: 0,
            files: 0,
        }];

        let value = server_status_value(&status, &servers);

        assert_eq!(value["connected"], false);
        assert_eq!(value["connecting"], true);
        assert_eq!(value["currentServer"]["connecting"], true);
        assert_eq!(value["currentServer"]["connected"], false);
        assert!(value["lowId"].is_null());
    }
}
