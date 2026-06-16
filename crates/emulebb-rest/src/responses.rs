//! Pure REST response/view builders.
//!
//! These free functions translate `emulebb-core` domain values into the exact
//! JSON shapes the eMuleBB REST contract publishes. They were extracted verbatim
//! from `lib.rs` during the maintainability restructuring; behavior is unchanged.

use std::path::Path as FsPath;

use emulebb_core::{
    AppInfo, AppLifecycle, LocalShare, NetworkStatus, Search, SearchResult, ServerInfo, Status,
    Transfer, TransferThroughputStats, UploadPolicyMetrics, VpnGuardStatus,
};
use serde_json::{Value, json};

use crate::{BulkOperationResult, RestState, SearchResultsPage, SharedFileResponse};

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

pub(crate) fn stats_response(
    status: &Status,
    upload_policy: &UploadPolicyMetrics,
    throughput: &TransferThroughputStats,
) -> Value {
    let ed2k_connected = status.ed2k.connected;
    let kad_connected = status.kad.connected;
    json!({
        "connected": ed2k_connected || kad_connected,
        "downloadSpeedKiBps": throughput.download_rate_bytes_per_sec as f64 / 1024.0,
        "uploadSpeedKiBps": upload_policy.upload_rate_bytes_per_sec as f64 / 1024.0,
        "sessionDownloadedBytes": throughput.session_downloaded_bytes,
        "sessionUploadedBytes": throughput.session_uploaded_bytes,
        "activeDownloads": status.transfers.active,
        "activeUploads": upload_policy.active_sessions,
        "waitingUploads": upload_policy.waiting_sessions,
        "downloadCount": status.transfers.active + status.transfers.completed,
        "sharedHashingActive": false,
        "sharedHashingCount": 0,
        "sharedFilesReady": status.lifecycle.state == "running",
        "ed2kConnected": ed2k_connected,
        "ed2kHighId": ed2k_connected,
        "kadRunning": status.kad.running,
        "kadConnected": kad_connected,
        "kadFirewalled": status.kad.firewalled
    })
}

pub(crate) async fn status_response(state: &RestState) -> Value {
    let status = state.core.status().await;
    let guard = state.core.vpn_guard_status();
    let upload_policy = state.core.upload_policy_metrics().await;
    let throughput = state.core.transfer_throughput_stats();
    let shared_file_count = state.core.shares().await.len();
    let download_file_count = status.transfers.active + status.transfers.completed;
    json!({
        "lifecycle": lifecycle_response(&status.lifecycle),
        "stats": stats_response(&status, &upload_policy, &throughput),
        "servers": server_status_response(state).await,
        "kad": kad_response(&status.kad, &guard),
        "network": network_response(&guard),
        "sharedStartupCache": {
            "available": false,
            "ready": true,
            "filePresent": false,
            "loaded": false,
            "rejected": false,
            "removed": false,
            "rejectCode": null,
            "recordsLoaded": 0,
            "volumesLoaded": 0,
            "hashingCount": 0,
            "deferredHashingActive": false,
            "interruptedHashingInvalidatedCache": false
        },
        "runtimeDiagnostics": {
            "processId": std::process::id(),
            "knownFileCount": shared_file_count,
            "sharedFileCount": shared_file_count,
            "sharedHashingCount": 0,
            "downloadFileCount": download_file_count,
            "activeUploads": upload_policy.active_sessions,
            "waitingUploads": upload_policy.waiting_sessions,
            "geolocation": null
        }
    })
}

pub(crate) fn network_response(guard: &VpnGuardStatus) -> Value {
    json!({
        "ports": {
            "tcp": 0,
            "udp": 0,
            "serverUdp": 0
        },
        "binding": {
            "configuredAddress": "",
            "configuredInterfaceId": "",
            "configuredInterfaceName": "",
            "activeConfiguredAddress": "",
            "activeInterfaceId": "",
            "activeInterfaceName": "",
            "activeInterfaceIndex": 0,
            "resolveResult": "default"
        },
        "vpnGuard": {
            "enabled": guard.enabled,
            "mode": guard.mode,
            "allowedPublicIpCidrs": guard.allowed_public_ip_cidrs,
            "startupBlocked": guard.startup_blocked,
            "startupBlockReason": guard.startup_block_reason
        }
    })
}

pub(crate) fn kad_response(kad: &NetworkStatus, guard: &VpnGuardStatus) -> Value {
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
        "network": network_response(guard)
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
    let current_server = servers
        .iter()
        .find(|server| server.current)
        .map(server_response);
    json!({
        "connected": status.ed2k.connected,
        "connecting": false,
        "currentServer": current_server,
        "lowId": if status.ed2k.connected { Some(false) } else { None },
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
        requests: 0,
        accepted_requests: 0,
        transferred_bytes: 0,
        all_time_requests: 0,
        all_time_accepts: 0,
        all_time_transferred: 0,
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
        EmulebbCore, NetworkStatus, TransferThroughputStats, VpnGuardStatus,
    };
    use emulebb_index::FileIndex;

    use super::{kad_response, stats_response};

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
        let value = kad_response(&kad, &guard);
        assert_eq!(value["indexedSources"], 42);
        assert_eq!(value["indexedKeywords"], 13);

        // When Kad is not running the counts are unknown -> reported as 0.
        kad.indexed_sources = None;
        kad.indexed_keywords = None;
        let value = kad_response(&kad, &guard);
        assert_eq!(value["indexedSources"], 0);
        assert_eq!(value["indexedKeywords"], 0);
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
        let value = stats_response(&status, &upload_policy, &throughput);
        assert_eq!(value["downloadSpeedKiBps"], 4.0);
        assert_eq!(value["sessionDownloadedBytes"], 1_048_576);
        assert_eq!(value["sessionUploadedBytes"], 524_288);
        // Lifetime totals are optional in the contract and eMuleBB omits them; we
        // omit rather than emit a misleading 0 (no lifetime persistence).
        assert!(value.get("totalDownloadedBytes").is_none());
        assert!(value.get("totalUploadedBytes").is_none());
    }
}
