use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct Envelope<T> {
    pub(super) data: T,
}

#[derive(Debug, Deserialize)]
pub(super) struct ErrorEnvelope {
    pub(super) error: ApiError,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApiError {
    pub(super) code: String,
    pub(super) message: String,
}

#[derive(Debug, Clone, Default)]
pub(super) struct DataCache {
    pub(super) snapshot: Option<Snapshot>,
    pub(super) search: Option<SearchDto>,
    pub(super) preferences: Option<Preferences>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct Snapshot {
    pub(super) app: AppInfo,
    pub(super) status: StatusInfo,
    pub(super) transfers: Vec<TransferDto>,
    pub(super) shared_files: Vec<SharedFileDto>,
    pub(super) uploads: Vec<UploadDto>,
    pub(super) upload_queue: Vec<UploadDto>,
    pub(super) servers: Vec<ServerDto>,
    pub(super) kad: KadDto,
    pub(super) logs: Vec<LogEntryDto>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct AppInfo {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) lifecycle: Lifecycle,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct StatusInfo {
    pub(super) lifecycle: Lifecycle,
    pub(super) stats: Stats,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct Lifecycle {
    pub(super) state: String,
    pub(super) startup_complete: bool,
    pub(super) accepting_rest: bool,
    pub(super) accepting_mutations: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct Stats {
    pub(super) connected: bool,
    pub(super) download_speed_ki_bps: f64,
    pub(super) upload_speed_ki_bps: f64,
    pub(super) session_downloaded_bytes: u64,
    pub(super) session_uploaded_bytes: u64,
    pub(super) active_downloads: Option<u64>,
    pub(super) active_uploads: u64,
    pub(super) waiting_uploads: u64,
    pub(super) download_count: u64,
    pub(super) ed2k_connected: bool,
    pub(super) ed2k_high_id: bool,
    pub(super) kad_running: bool,
    pub(super) kad_connected: bool,
    pub(super) kad_firewall_state: FirewallState,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct KadDto {
    pub(super) running: bool,
    pub(super) connected: bool,
    pub(super) firewall_state: FirewallState,
    pub(super) bootstrapping: bool,
    pub(super) contact_count: Option<u64>,
    pub(super) users: Option<u64>,
    pub(super) files: Option<u64>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum FirewallState {
    #[default]
    Unknown,
    Open,
    Firewalled,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct TransferDto {
    pub(super) hash: String,
    pub(super) name: String,
    pub(super) size_bytes: u64,
    pub(super) completed_bytes: Option<u64>,
    pub(super) progress: Option<f64>,
    pub(super) state: String,
    pub(super) category_name: Option<String>,
    pub(super) download_speed_ki_bps: Option<f64>,
    pub(super) sources: Option<u64>,
    pub(super) sources_transferring: Option<u64>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct UploadDto {
    pub(super) client_id: String,
    pub(super) user_name: String,
    pub(super) upload_state: String,
    pub(super) upload_speed_ki_bps: f64,
    pub(super) uploaded_bytes: u64,
    pub(super) requested_file_name: Option<String>,
    pub(super) requested_file_size_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct ServerDto {
    pub(super) address: String,
    pub(super) port: u16,
    pub(super) name: String,
    pub(super) priority: String,
    #[serde(rename = "static")]
    pub(super) static_server: bool,
    pub(super) enabled: bool,
    pub(super) connected: bool,
    pub(super) connecting: bool,
    pub(super) current: bool,
    pub(super) failed_count: u64,
    pub(super) ping: u64,
    pub(super) users: u64,
    pub(super) files: u64,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct SharedFileDto {
    pub(super) hash: String,
    pub(super) name: String,
    pub(super) directory: String,
    pub(super) ed2k_link: Option<String>,
    pub(super) size_bytes: u64,
    pub(super) priority: String,
    pub(super) requests: u64,
    pub(super) accepted_requests: u64,
    pub(super) transferred_bytes: u64,
    pub(super) all_time_requests: u64,
    pub(super) all_time_accepts: u64,
    pub(super) all_time_transferred: u64,
    pub(super) rating: u64,
    pub(super) has_comment: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct LogEntryDto {
    pub(super) timestamp: Option<Value>,
    pub(super) level: Option<String>,
    pub(super) message: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchDto {
    pub(super) id: String,
    pub(super) query: String,
    pub(super) method: String,
    #[serde(rename = "type")]
    pub(super) file_type: String,
    pub(super) status: String,
    pub(super) status_reason: Option<String>,
    pub(super) total: Option<u64>,
    pub(super) items: Vec<SearchResultDto>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchListDto {
    pub(super) items: Vec<SearchSessionDto>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchSessionDto {
    pub(super) id: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchResultDto {
    pub(super) search_id: String,
    pub(super) method: String,
    #[serde(rename = "type")]
    pub(super) result_type: String,
    pub(super) hash: String,
    pub(super) name: String,
    pub(super) size_bytes: u64,
    pub(super) sources: u64,
    pub(super) complete_sources: u64,
    pub(super) file_type: String,
    pub(super) complete: bool,
    pub(super) known_type: String,
    pub(super) directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchCreateRequest {
    pub(super) query: String,
    pub(super) method: String,
    #[serde(rename = "type")]
    pub(super) file_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchResultDownloadRequest {
    pub(super) paused: bool,
}

#[derive(Debug, Clone)]
pub(super) struct PreferencesForm {
    pub(super) upload_limit_ki_bps: String,
    pub(super) download_limit_ki_bps: String,
    pub(super) max_connections: String,
    pub(super) max_connections_per_five_seconds: String,
    pub(super) max_sources_per_file: String,
    pub(super) upload_client_data_rate: String,
    pub(super) max_upload_slots: String,
    pub(super) upload_slot_elastic_percent: String,
    pub(super) queue_size: String,
    pub(super) auto_connect: bool,
    pub(super) reconnect: bool,
    pub(super) credit_system: bool,
    pub(super) safe_server_connect: bool,
    pub(super) add_servers_from_server: bool,
    pub(super) network_kademlia: bool,
    pub(super) network_ed2k: bool,
}

#[derive(Debug, Clone)]
pub(super) struct ServerForm {
    pub(super) address: String,
    pub(super) port: String,
    pub(super) name: String,
    pub(super) priority: String,
    pub(super) static_server: bool,
    pub(super) connect: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ServerCreateRequest {
    pub(super) address: String,
    pub(super) port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<String>,
    #[serde(rename = "static", skip_serializing_if = "Option::is_none")]
    pub(super) static_server: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) connect: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ServerUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<String>,
    #[serde(rename = "static", skip_serializing_if = "Option::is_none")]
    pub(super) static_server: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UrlImportRequest {
    pub(super) url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_accepts_explicit_kad_firewall_state() {
        let raw = r#"{
            "data": {
                "app": {
                    "name": "eMuleBB Rust",
                    "version": "0.1.0",
                    "lifecycle": {
                        "state": "running",
                        "startupComplete": true,
                        "acceptingRest": true,
                        "acceptingMutations": true
                    }
                },
                "status": {
                    "lifecycle": {
                        "state": "running",
                        "startupComplete": true,
                        "acceptingRest": true,
                        "acceptingMutations": true
                    },
                    "stats": {
                        "connected": false,
                        "downloadSpeedKiBps": 0.0,
                        "uploadSpeedKiBps": 0.0,
                        "sessionDownloadedBytes": 0,
                        "sessionUploadedBytes": 0,
                        "activeUploads": 0,
                        "waitingUploads": 0,
                        "downloadCount": 0,
                        "ed2kConnected": false,
                        "ed2kHighId": false,
                        "kadRunning": false,
                        "kadConnected": false,
                        "kadFirewallState": "unknown"
                    }
                },
                "transfers": [],
                "sharedFiles": [],
                "uploads": [],
                "uploadQueue": [],
                "servers": [],
                "kad": {
                    "running": false,
                    "connected": false,
                    "firewallState": "unknown",
                    "bootstrapping": false,
                    "contactCount": 0,
                    "users": null,
                    "files": null
                },
                "logs": []
            }
        }"#;

        let envelope: Envelope<Snapshot> = serde_json::from_str(raw).unwrap();

        assert_eq!(
            envelope.data.status.stats.kad_firewall_state,
            FirewallState::Unknown
        );
        assert_eq!(envelope.data.kad.firewall_state, FirewallState::Unknown);
    }

    #[test]
    fn search_result_requires_concrete_complete_flag() {
        let raw = r#"{
            "data": {
                "id": "search-1",
                "query": "sample",
                "method": "server",
                "type": "doc",
                "status": "complete",
                "createdAt": "2026-07-14T00:00:00Z",
                "updatedAt": "2026-07-14T00:00:00Z",
                "items": [{
                    "searchId": "search-1",
                    "method": "server",
                    "type": "doc",
                    "hash": "00112233445566778899aabbccddeeff",
                    "name": "sample.bin",
                    "sizeBytes": 1024,
                    "sources": 2,
                    "completeSources": 1,
                    "fileType": "doc",
                    "complete": true,
                    "knownType": "unknown",
                    "directory": null
                }]
            }
        }"#;

        let envelope: Envelope<SearchDto> = serde_json::from_str(raw).unwrap();

        assert!(envelope.data.items[0].complete);
    }
}
