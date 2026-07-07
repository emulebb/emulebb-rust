//! REST view builders and request validators.
//!
//! Pure (non-async) helpers that build the REST response structs (`Transfer`,
//! `TransferSource`, `TransferPart`, `NetworkStatus`, `ServerInfo`) from the
//! lower-layer manifest/live-session/server state, and the request-validation
//! helpers for transfer/source/server/shared-file mutations. Moved verbatim out
//! of `lib.rs` during the maintainability restructuring; they carry no behavior
//! beyond what they had inline. Re-exported `pub(crate)` from the crate root so
//! the `EmulebbCore` impl and the test module reach them by their bare names.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, ensure};
use emulebb_ed2k::ed2k_transfer::{Ed2kLiveSource, Ed2kResumeManifest, Ed2kTransferState};

use crate::{
    NetworkStatus, ServerCreate, ServerInfo, ServerUpdate, SharedFileUpdate, Transfer,
    TransferCreate, TransferPart, TransferSource, TransferUpdate,
};

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
    // Master parity (GetTransferStateName + IsStopped): a stopped transfer is
    // reported with the `paused` state plus a separate `stopped` flag, not a
    // distinct `stopped` state token (which is not in the TransferState enum).
    let stopped = state_name == "stopped";
    let emitted_state = if stopped { "paused" } else { state_name };
    Transfer {
        ed2k_link: format!(
            "ed2k://|file|{}|{}|{}|/",
            manifest.canonical_name, manifest.file_size, manifest.file_hash
        ),
        hash: manifest.file_hash.clone(),
        name: manifest.canonical_name.clone(),
        path: payload_path,
        delivered_path: manifest.delivered_path.clone(),
        size_bytes: manifest.file_size,
        completed_bytes,
        state: emitted_state.to_string(),
        progress,
        sources: (manifest.sources.len() as u32).max(live_source_count),
        sources_transferring,
        download_speed_ki_bps: download_speed_bytes_per_sec as f64 / 1024.0,
        upload_speed_ki_bps: 0.0,
        stopped,
        priority: "normal".to_string(),
        category_id: 0,
        category_name: default_transfer_category_name().to_string(),
        eta,
        added_at: None,
        completed_at: None,
        parts_total,
        parts_obtained,
        parts_progress_text,
        parts_available,
        auto_priority: false,
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
        bootstrap_progress: Some(0),
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
    transfer.priority = existing.priority.clone();
    transfer.category_id = existing.category_id;
    transfer.category_name = existing.category_name.clone();
}

pub(crate) fn manifest_default_state_name(manifest: &Ed2kResumeManifest) -> &str {
    if manifest.completed {
        "completed"
    } else if let Some(control_state) = manifest.control_state.as_deref() {
        control_state
    } else if manifest.pieces.iter().any(|piece| piece.bytes_written != 0) {
        "downloading"
    } else {
        "queued"
    }
}

pub(crate) fn transfer_create_state_name(paused: Option<bool>) -> &'static str {
    if paused.unwrap_or(false) {
        "paused"
    } else {
        // A newly added, non-paused download starts immediately (eMule/aMule
        // parity), so it is created active rather than waiting in "queued".
        "downloading"
    }
}

pub(crate) fn validate_transfer_update_family(request: &TransferUpdate) -> Result<()> {
    let mut mutation_family_count = 0;
    if request.priority.is_some() {
        mutation_family_count += 1;
    }
    if request.category_id.is_some() || request.category_name.is_some() {
        mutation_family_count += 1;
    }
    if request.name.is_some() {
        mutation_family_count += 1;
    }
    ensure!(
        mutation_family_count != 0,
        "transfer PATCH requires priority, categoryId, categoryName, or name"
    );
    ensure!(
        mutation_family_count == 1,
        "transfer PATCH accepts only one mutation family"
    );
    if let Some(priority) = request.priority.as_deref() {
        let _ = validate_transfer_priority(priority)?;
    }
    Ok(())
}

pub(crate) fn validate_transfer_priority(priority: &str) -> Result<&str> {
    match priority {
        "auto" | "verylow" | "low" | "normal" | "high" | "veryhigh" => Ok(priority),
        _ => Err(anyhow::anyhow!(
            "priority must be one of auto, verylow, low, normal, high, veryhigh"
        )),
    }
}

pub(crate) fn download_priority_score(priority: &str) -> u32 {
    match priority {
        "verylow" => 1,
        "low" => 3,
        "high" => 7,
        "veryhigh" => 9,
        "auto" | "normal" => 5,
        _ => 5,
    }
}

pub(crate) fn normalize_transfer_name(name: Option<String>) -> Result<String> {
    let Some(name) = name else {
        anyhow::bail!("name must be a string");
    };
    let name = name.trim();
    ensure!(!name.is_empty(), "name must not be empty");
    ensure!(
        !name.chars().any(|character| matches!(
            character,
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
        ) || character.is_control()),
        "name must be a valid eD2K filename"
    );
    Ok(name.to_string())
}

pub(crate) fn default_transfer_category_name() -> &'static str {
    "All"
}

pub(crate) fn ensure_category_selector_is_unambiguous(
    category_id: Option<u32>,
    category_name: Option<&str>,
) -> Result<()> {
    ensure!(
        category_id.is_none() || category_name.is_none(),
        "categoryId and categoryName are mutually exclusive"
    );
    ensure!(
        category_name
            .map(|value| !value.trim().is_empty())
            .unwrap_or(true),
        "categoryName must not be empty"
    );
    Ok(())
}

pub(crate) fn transfer_create_links(request: TransferCreate) -> Result<Vec<String>> {
    match (request.link, request.links) {
        (Some(link), None) => {
            ensure!(!link.trim().is_empty(), "link is required");
            Ok(vec![link])
        }
        (None, Some(links)) => {
            ensure!(!links.is_empty(), "links must contain at least one entry");
            for link in &links {
                ensure!(
                    !link.trim().is_empty(),
                    "links must not contain empty entries"
                );
            }
            Ok(links)
        }
        (Some(_), Some(_)) => Err(anyhow::anyhow!("link and links are mutually exclusive")),
        (None, None) => Err(anyhow::anyhow!("link or links is required")),
    }
}

pub(crate) fn transfer_sources_from_manifest(
    manifest: &Ed2kResumeManifest,
    banned_clients: &HashSet<String>,
) -> Vec<TransferSource> {
    manifest
        .sources
        .iter()
        .map(|source| {
            let endpoint = format!("{}:{}", source.ip, source.tcp_port);
            let client_id = source.user_hash.clone().unwrap_or_else(|| endpoint.clone());
            let banned = banned_clients.contains(&client_id);
            TransferSource {
                client_id,
                hash: manifest.file_hash.clone(),
                endpoint: endpoint.clone(),
                ip: source.ip.clone(),
                tcp_port: source.tcp_port,
                port: source.tcp_port,
                user_hash: source.user_hash.clone(),
                user_name: endpoint.clone(),
                client_software: "unknown".to_string(),
                download_state: if banned { "banned" } else { "remembered" }.to_string(),
                download_speed_ki_bps: 0.0,
                available_parts: 0,
                part_count: manifest.pieces.len() as u32,
                address: source.ip.clone(),
                server_ip: String::new(),
                server_port: 0,
                low_id: false,
                queue_rank: 0,
                view_shared_files: false,
                shared_files_request_pending: false,
                banned,
                status: "remembered".to_string(),
            }
        })
        .collect()
}

/// Overlays live download-session state from the F1 registry onto the remembered
/// source list: matching a remembered source by `ip:tcp_port`, set its live
/// download state, speed, and advertised part availability. Sources with no live
/// session keep their "remembered" defaults.
pub(crate) fn enrich_sources_with_live(
    sources: &mut [TransferSource],
    live: &[Ed2kLiveSource],
    part_count: u32,
) {
    let live_by_endpoint: HashMap<String, &Ed2kLiveSource> = live
        .iter()
        .map(|source| (source.endpoint.to_string(), source))
        .collect();
    for source in sources.iter_mut() {
        let Some(live_source) = live_by_endpoint.get(&source.endpoint) else {
            continue;
        };
        source.download_speed_ki_bps = live_source.download_speed_bytes_per_sec as f64 / 1024.0;
        source.available_parts = live_source.available_parts;
        source.part_count = part_count;
        if let Some(rank) = live_source.queue_rank {
            source.queue_rank = rank;
        }
        let state = if live_source.transferring {
            "downloading"
        } else {
            "connected"
        };
        source.download_state = state.to_string();
        source.status = state.to_string();
    }
}

/// Builds the per-part download breakdown from the resume manifest. ED2K parts
/// map 1:1 to manifest pieces (piece_size == ED2K_PART_SIZE). Geometry and
/// completion are real (per-piece `bytes_written`/`state`); `availableSources`
/// and `corrupted` are live-session-only signals the persistent manifest does
/// not track, so they are honestly reported as 0/false rather than fabricated.
pub(crate) fn transfer_parts_from_manifest(
    manifest: &Ed2kResumeManifest,
    available_sources_per_part: &[u32],
) -> Vec<TransferPart> {
    let part_size = manifest.piece_size.max(1);
    let file_size = manifest.file_size;
    manifest
        .pieces
        .iter()
        .map(|piece| {
            let start = u64::from(piece.piece_index) * part_size;
            let end_exclusive = (start + part_size).min(file_size).max(start);
            let size = end_exclusive - start;
            let end = end_exclusive.saturating_sub(1);
            let verified = matches!(piece.state, Ed2kTransferState::Verified);
            let completed_bytes = if verified {
                size
            } else {
                piece.bytes_written.min(size)
            };
            let gap_bytes = size - completed_bytes;
            TransferPart {
                index: piece.piece_index,
                start,
                end,
                size,
                completed_bytes,
                gap_bytes,
                complete: size > 0 && gap_bytes == 0,
                requested: matches!(piece.state, Ed2kTransferState::Requested),
                corrupted: false,
                available_sources: available_sources_per_part
                    .get(piece.piece_index as usize)
                    .copied()
                    .unwrap_or(0),
            }
        })
        .collect()
}

pub(crate) fn source_by_client_id(
    sources: Vec<TransferSource>,
    client_id: &str,
) -> Option<TransferSource> {
    sources.into_iter().find(|source| {
        source.client_id == client_id
            || source.endpoint == client_id
            || source.user_hash.as_deref() == Some(client_id)
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

pub(crate) fn source_friend_name(source: &TransferSource) -> String {
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
    Ok(trimmed.to_string())
}

pub(crate) fn validate_shared_upload_priority(priority: &str) -> Result<(&str, bool)> {
    match priority {
        "auto" => Ok((priority, true)),
        "verylow" | "low" | "normal" | "high" | "release" => Ok((priority, false)),
        _ => Err(anyhow::anyhow!(
            "priority must be one of auto, verylow, low, normal, high, release"
        )),
    }
}

pub(crate) fn validate_shared_file_comment_rating(
    request: &SharedFileUpdate,
) -> Result<Option<(String, u8)>> {
    match (&request.comment, request.rating) {
        (None, None) => Ok(None),
        (Some(comment), Some(rating)) if rating <= 5 => Ok(Some((comment.clone(), rating))),
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
        priority: "normal".to_string(),
        static_server,
        connected,
        connecting,
        current,
        description: description.unwrap_or_default().to_string(),
        dyn_ip: String::new(),
        failed_count: 0,
        hard_files: 0,
        ip: String::new(),
        ping: 0,
        soft_files: 0,
        version: String::new(),
        users: 0,
        files: 0,
    }
}

pub(crate) fn apply_server_update(server: &mut ServerInfo, update: Option<&ServerUpdate>) {
    let Some(update) = update else {
        return;
    };
    if let Some(name) = update.name.as_ref() {
        server.name = name.clone();
    }
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
    pub(crate) users: Option<u32>,
    pub(crate) files: Option<u32>,
}

pub(crate) fn apply_server_live_details(server: &mut ServerInfo, live: &ServerLiveDetails) {
    if let Some(name) = live.name.as_ref() {
        server.name = name.clone();
    }
    if let Some(description) = live.description.as_ref() {
        server.description = description.clone();
    }
    if let Some(users) = live.users {
        server.users = u64::from(users);
    }
    if let Some(files) = live.files {
        server.files = u64::from(files);
    }
}

pub(crate) fn validate_server_update(update: &ServerUpdate) -> Result<()> {
    if let Some(priority) = update.priority.as_deref() {
        let _ = validate_server_priority(priority)?;
    }
    Ok(())
}

pub(crate) fn validate_server_priority(priority: &str) -> Result<&str> {
    match priority {
        "low" | "normal" | "high" => Ok(priority),
        _ => Err(anyhow::anyhow!("priority must be one of low, normal, high")),
    }
}

pub(crate) fn server_endpoint_from_create(request: &ServerCreate) -> Result<String> {
    ensure!(!request.address.trim().is_empty(), "address is required");
    ensure!(request.port != 0, "port must be in the range 1..65535");
    if let Some(priority) = request.priority.as_deref() {
        let _ = validate_server_priority(priority)?;
    }
    Ok(format!("{}:{}", request.address, request.port))
}

#[cfg(test)]
#[path = "views_tests.rs"]
mod tests;
