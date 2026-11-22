//! REST view builders and request validators.
//!
//! Pure (non-async) helpers that build the REST response structs (`Transfer`,
//! `DownloadSource`, `NetworkStatus`, `ServerInfo`) from the
//! lower-layer manifest/live-session/server state, and the request-validation
//! helpers for transfer/source/server/shared-file mutations. Moved verbatim out
//! of `lib.rs` during the maintainability restructuring; they carry no behavior
//! beyond what they had inline. Re-exported `pub(crate)` from the crate root so
//! the `EmulebbCore` impl and the test module reach them by their bare names.

use anyhow::{Result, ensure};
use emulebb_ed2k::ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferState};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use crate::{
    DownloadFileNameObservation, DownloadSource, LibraryFileUpdate, NetworkStatus, ServerInfo,
    Transfer,
};

// MFC EncodeUrlUtf8 escapes spaces, percent signs, and UTF-8 bytes in ED2K
// file names. Escaping the field separator also keeps locally named files
// parseable without changing the surrounding stock link shape.
const ED2K_LINK_NAME_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'%').add(b'|');

/// Emit a stock-shaped eD2K link with a UTF-8-safe, delimiter-safe file name.
pub(crate) fn format_ed2k_file_link(
    name: &str,
    size: u64,
    hash: &str,
    aich_root: Option<&str>,
) -> String {
    let mut link = format!(
        "ed2k://|file|{}|{}|{}|",
        utf8_percent_encode(name, ED2K_LINK_NAME_ENCODE_SET),
        size,
        hash,
    );
    if let Some(aich_root) = aich_root.filter(|root| !root.is_empty())
        && let Ok(bytes) = hex::decode(aich_root)
        && bytes.len() == 20
    {
        link.push_str("h=");
        link.push_str(&data_encoding::BASE32_NOPAD.encode(&bytes));
        link.push('|');
    }
    link.push('/');
    link
}

// Builds one Transfer view from a resume manifest plus a handful of live-overlay
// scalars (speed/sources/parts/bytes). The inputs are distinct primitives with no
// natural grouping, so a params struct would only add indirection.
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
pub(crate) fn transfer_from_manifest(
    manifest: &Ed2kResumeManifest,
    state_name: &str,
    payload_path: String,
    download_speed_bytes_per_sec: u64,
    sources_transferring: u32,
    parts_available: u32,
    live_downloaded_bytes: u64,
    live_source_count: u32,
) -> Transfer {
    // The manifest only counts WHOLE verified 9.28 MB parts, so a large download
    // still in its first parts reports 0 there. Surface the live per-block session
    // byte count (max, never below the durable verified floor) so in-flight
    // progress is visible in REST/UI instead of sitting at 0% for the first parts.
    let completed_bytes = manifest
        .pieces
        .iter()
        .map(|piece| piece.bytes_written)
        .sum::<u64>()
        .max(live_downloaded_bytes)
        .min(manifest.file_size);
    let progress = if manifest.file_size == 0 {
        0.0
    } else {
        completed_bytes as f64 / manifest.file_size as f64
    };
    // ED2K parts (9.28 MB each) map 1:1 to manifest pieces (piece_size ==
    // ED2K_PART_SIZE). A part is "obtained" once verified.
    let parts_progress_text: String = manifest
        .pieces
        .iter()
        .map(|piece| {
            if piece.state == Ed2kTransferState::Verified {
                '#'
            } else {
                '0'
            }
        })
        .collect();
    let parts_total = manifest.pieces.len() as u32;
    let parts_obtained = parts_progress_text.bytes().filter(|&c| c == b'#').count() as u32;
    let remaining = manifest.file_size.saturating_sub(completed_bytes);
    let eta = if download_speed_bytes_per_sec > 0 && remaining > 0 {
        Some(remaining / download_speed_bytes_per_sec)
    } else {
        None
    };
    let stopped = state_name == "stopped";
    Transfer {
        id: manifest.token.job_id,
        execution_generation: manifest.token.generation,
        ed2k_link: format_ed2k_file_link(
            &manifest.display_name,
            manifest.file_size,
            &manifest.file_hash,
            manifest.aich_root.as_deref(),
        ),
        hash: manifest.file_hash.clone(),
        name: manifest.display_name.clone(),
        path: payload_path,
        delivered_path: manifest
            .delivered_path
            .as_deref()
            .map(crate::normal_path_display),
        delivery_error: None,
        size_bytes: manifest.file_size,
        completed_bytes,
        state: state_name.to_string(),
        progress,
        sources: live_source_count,
        sources_transferring,
        download_speed_ki_bps: download_speed_bytes_per_sec as f64 / 1024.0,
        upload_speed_ki_bps: 0.0,
        stopped,
        category_id: None,
        category_name: None,
        eta,
        added_at: None,
        completed_at: None,
        parts_total,
        parts_obtained,
        parts_progress_text,
        parts_available,
        // Classified by the caller (EmulebbCore::transfer_from_manifest), which
        // knows the configured incoming/category directories; this pure builder
        // has no directory context, so it defaults to false here.
        in_incoming: false,
    }
}

pub(crate) fn kad_status_from_running(running: bool) -> NetworkStatus {
    NetworkStatus {
        running,
        connected: false,
        peer_count: 0,
        firewalled: None,
        bootstrapping: Some(running),
        bootstrap_progress: (!running).then_some(0.0),
        contact_count: if running { Some(0) } else { None },
        lan_mode: Some(false),
        users: None,
        files: None,
        indexed_sources: if running { Some(0) } else { None },
        indexed_keywords: if running { Some(0) } else { None },
        operation_queued: None,
        already_running: None,
    }
}

pub(crate) fn preserve_transfer_public_metadata(transfer: &mut Transfer, existing: &Transfer) {
    transfer.category_id = existing.category_id;
    transfer.category_name = existing.category_name.clone();
}

/// Project a bounded source row. Observation backing moves into the response;
/// source history and piece geometry are never materialized by this builder.
pub(crate) fn download_source_from_record(
    hash: &str,
    entry: emulebb_metadata::MetadataDownloadSourceEntry,
    banned: bool,
    part_count: u32,
) -> DownloadSource {
    let source = entry.source;
    let endpoint = format!("{}:{}", source.ip, source.tcp_port);
    let client_id = source.user_hash.clone().unwrap_or_else(|| endpoint.clone());
    let client_software = entry
        .reported_file_names
        .iter()
        .find(|name| !name.client_software.is_empty())
        .map_or_else(|| "unknown".to_owned(), |name| name.client_software.clone());
    let reported_file_names = entry
        .reported_file_names
        .into_iter()
        .map(|name| DownloadFileNameObservation {
            raw_name: name.raw_name,
            normalized_name: name.normalized_name,
            origin: name.origin,
            reporter_endpoint: name.reporter_endpoint,
            observed_at: name.observed_at_s,
        })
        .collect();
    DownloadSource {
        client_id,
        hash: hash.to_owned(),
        endpoint: endpoint.clone(),
        ip: source.ip.clone(),
        tcp_port: source.tcp_port,
        port: source.tcp_port,
        file_comment: source.file_comment,
        file_rating: source.file_rating,
        user_hash: source.user_hash,
        user_name: endpoint,
        client_software,
        reported_file_names,
        reported_file_names_has_more: entry.reported_file_names_has_more,
        download_state: if banned { "banned" } else { "remembered" }.to_owned(),
        download_rate_bytes_per_second: 0,
        available_parts: 0,
        part_count,
        address: source.ip,
        server_ip: String::new(),
        server_port: 0,
        low_id: false,
        queue_rank: 0,
        view_shared_files: false,
        shared_files_request_pending: false,
        banned,
        status: "remembered".to_owned(),
    }
}

/// Overlay a single borrowed peer view inside an already admitted projection.
/// No complete peer bitmap or all-peer snapshot is copied for a source page.
pub(crate) fn apply_download_source_stats(
    runtime: &emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime,
    token: emulebb_metadata::JobToken,
    source: &mut DownloadSource,
    live_text_bytes: &mut usize,
) -> Result<()> {
    if source.banned {
        return Ok(());
    }
    runtime.with_live_download_source_stats(token, &source.endpoint, |live| {
        let Some(live) = live else {
            return Ok(());
        };
        if let Some(software) = live.client_software {
            ensure!(
                software.len() <= *live_text_bytes,
                emulebb_ed2k::ed2k_transfer::LocalMutationError::TooLarge
            );
            *live_text_bytes -= software.len();
            source.client_software = software.to_owned();
        }
        source.download_rate_bytes_per_second = live.download_speed_bytes_per_sec;
        source.available_parts = live.available_parts;
        if let Some(rank) = live.queue_rank {
            source.queue_rank = rank;
        }
        let state = if live.transferring {
            "downloading"
        } else {
            "connected"
        };
        source.download_state = state.to_owned();
        source.status = state.to_owned();
        Ok(())
    })
}

pub(crate) fn validate_source_client_id(client_id: &str) -> Result<()> {
    if client_id.len() == 32
        && client_id
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Ok(());
    }
    let Some((address, port)) = client_id.rsplit_once(':') else {
        anyhow::bail!("clientId must be a 32-character lowercase hex string or address:port");
    };
    ensure!(
        !address.trim().is_empty(),
        "clientId must be a 32-character lowercase hex string or address:port"
    );
    let port = port.parse::<u16>().map_err(|_| {
        anyhow::anyhow!("clientId must be a 32-character lowercase hex string or address:port")
    })?;
    ensure!(
        port != 0,
        "clientId must be a 32-character lowercase hex string or address:port"
    );
    Ok(())
}

pub(crate) fn source_friend_name(source: &DownloadSource) -> String {
    if source.user_name.trim().is_empty() {
        source.client_id.clone()
    } else {
        source.user_name.clone()
    }
}

pub(crate) fn validate_url_import(url: &str) -> Result<String> {
    let trimmed = url.trim();
    ensure!(!trimmed.is_empty(), "url must not be empty");
    ensure!(
        !trimmed.chars().any(char::is_control),
        "url must be valid UTF-8 without control characters"
    );
    ensure!(
        trimmed.chars().count() <= 2048,
        "url must be at most 2048 characters"
    );
    crate::discovery_fetch::parse_discovery_url(
        trimmed,
        crate::DiscoveryUrlPolicy::OperatorImport,
    )?;
    Ok(trimmed.to_string())
}

pub(crate) fn validate_library_upload_priority(priority: &str) -> Result<(&str, bool)> {
    match priority {
        "auto" => Ok((priority, true)),
        "verylow" | "low" | "normal" | "high" | "release" => Ok((priority, false)),
        _ => Err(anyhow::anyhow!(
            "priority must be one of auto, verylow, low, normal, high, release"
        )),
    }
}

pub(crate) fn validate_shared_file_comment_rating(
    request: &LibraryFileUpdate,
) -> Result<Option<(&str, u8)>> {
    match (&request.comment, request.rating) {
        (None, None) => Ok(None),
        (Some(comment), Some(rating)) if rating <= 5 && comment.len() <= 65_536 => {
            Ok(Some((comment.as_str(), rating)))
        }
        (Some(comment), Some(_)) if comment.len() > 65_536 => {
            anyhow::bail!("comment exceeds 65536 bytes")
        }
        (None, Some(_)) => anyhow::bail!("comment must be a string"),
        (Some(_), Some(_)) | (Some(_), None) => {
            anyhow::bail!("rating must be an integer between 0 and 5")
        }
    }
}

pub(crate) fn server_info_from_parts(
    address: &str,
    port: u16,
    name: Option<&str>,
    description: Option<&str>,
    static_server: bool,
    connected_endpoint: Option<&str>,
    connecting_endpoint: Option<&str>,
) -> ServerInfo {
    let endpoint = format!("{address}:{port}");
    let connected = connected_endpoint.is_some_and(|connected| connected == endpoint);
    let connecting = connecting_endpoint.is_some_and(|connecting| connecting == endpoint);
    let current = connected || connecting;
    ServerInfo {
        address: address.to_string(),
        port,
        endpoint,
        name: name.unwrap_or_default().to_string(),
        priority: "normal".to_owned(),
        static_server,
        enabled: true,
        connected,
        connecting,
        current,
        description: description.unwrap_or_default().to_string(),
        dyn_ip: String::new(),
        auxiliary_ports: Vec::new(),
        failed_count: 0,
        hard_files: 0,
        ip: String::new(),
        ping: 0,
        soft_files: 0,
        offer_files_mode: None,
        offer_files_batch_max: None,
        offer_files_min_interval_ms: None,
        offer_files_fallback_reason: None,
        offer_files_published_entries: 0,
        offer_files_pending_entries: 0,
        version: String::new(),
        obfuscation_tcp_port: None,
        obfuscation_udp_port: None,
        udp_flags: None,
        udp_key: None,
        udp_key_ip: None,
        max_users: 0,
        low_id_users: 0,
        users: 0,
        files: 0,
        host_name: None,
        host_name_status: None,
        host_name_resolved_at: None,
        host_name_error: None,
    }
}

pub(crate) fn apply_server_update(
    server: &mut ServerInfo,
    update: Option<&emulebb_metadata::MetadataServerUpdate>,
) {
    let Some(update) = update else {
        return;
    };
    if let Some(priority) = update.priority.as_ref() {
        server.priority = priority.clone();
    }
    if let Some(static_server) = update.static_server {
        server.static_server = static_server;
    }
}

pub(crate) fn apply_server_connection_flags(
    server: &mut ServerInfo,
    connected_endpoint: Option<&str>,
    connecting_endpoint: Option<&str>,
) {
    server.connected = connected_endpoint.is_some_and(|connected| connected == server.endpoint);
    server.connecting = connecting_endpoint.is_some_and(|connecting| connecting == server.endpoint);
    server.current = server.connected || server.connecting;
}

#[derive(Debug, Default)]
pub(crate) struct ServerLiveDetails {
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) dynamic_host: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) auxiliary_ports: Vec<u16>,
    pub(crate) users: Option<u32>,
    pub(crate) files: Option<u32>,
    pub(crate) max_users: Option<u32>,
    pub(crate) low_id_users: Option<u32>,
    pub(crate) ping_ms: Option<u32>,
    pub(crate) udp_flags: Option<u32>,
    pub(crate) soft_files: Option<u32>,
    pub(crate) hard_files: Option<u32>,
    pub(crate) offer_files_mode: Option<String>,
    pub(crate) offer_files_batch_max: Option<u32>,
    pub(crate) offer_files_min_interval_ms: Option<u32>,
    pub(crate) offer_files_fallback_reason: Option<String>,
    pub(crate) offer_files_published_entries: usize,
    pub(crate) offer_files_pending_entries: usize,
    pub(crate) obfuscation_tcp_port: Option<u16>,
    pub(crate) obfuscation_udp_port: Option<u16>,
    pub(crate) udp_key: Option<u32>,
    pub(crate) udp_key_ip: Option<u32>,
}

pub(crate) fn apply_server_live_details(server: &mut ServerInfo, live: &ServerLiveDetails) {
    if let Some(name) = live.name.as_ref() {
        server.name = name.clone();
    }
    if let Some(description) = live.description.as_ref() {
        server.description = description.clone();
    }
    if let Some(dynamic_host) = live.dynamic_host.as_ref() {
        server.dyn_ip = dynamic_host.clone();
    }
    if let Some(version) = live.version.as_ref() {
        server.version = version.clone();
    }
    if !live.auxiliary_ports.is_empty() {
        server.auxiliary_ports.clone_from(&live.auxiliary_ports);
    }
    if let Some(users) = live.users {
        server.users = u64::from(users);
    }
    if let Some(files) = live.files {
        server.files = u64::from(files);
    }
    if let Some(max_users) = live.max_users {
        server.max_users = u64::from(max_users);
    }
    if let Some(low_id_users) = live.low_id_users {
        server.low_id_users = u64::from(low_id_users);
    }
    if let Some(ping_ms) = live.ping_ms {
        server.ping = ping_ms;
    }
    if let Some(udp_flags) = live.udp_flags {
        server.udp_flags = Some(udp_flags);
    }
    if let Some(soft_files) = live.soft_files {
        server.soft_files = u64::from(soft_files);
    }
    if let Some(hard_files) = live.hard_files {
        server.hard_files = u64::from(hard_files);
    }
    server.offer_files_mode.clone_from(&live.offer_files_mode);
    server.offer_files_batch_max = live.offer_files_batch_max;
    server.offer_files_min_interval_ms = live.offer_files_min_interval_ms;
    server
        .offer_files_fallback_reason
        .clone_from(&live.offer_files_fallback_reason);
    server.offer_files_published_entries = live.offer_files_published_entries;
    server.offer_files_pending_entries = live.offer_files_pending_entries;
    if let Some(port) = live.obfuscation_tcp_port {
        server.obfuscation_tcp_port = Some(port);
    }
    if let Some(port) = live.obfuscation_udp_port {
        server.obfuscation_udp_port = Some(port);
    }
    if let Some(key) = live.udp_key {
        server.udp_key = Some(key);
    }
    if let Some(key_ip) = live.udp_key_ip {
        server.udp_key_ip = Some(key_ip);
    }
}

pub(crate) fn validate_server_priority(priority: &str) -> Result<&str> {
    match priority {
        "low" | "normal" | "high" => Ok(priority),
        _ => Err(anyhow::anyhow!("priority must be one of low, normal, high")),
    }
}

#[cfg(test)]
#[path = "views_tests.rs"]
mod tests;
