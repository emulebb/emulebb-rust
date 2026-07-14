use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct SortSpec {
    column: i32,
    descending: bool,
}

pub(super) fn sort_spec(column: i32, descending: bool) -> Option<SortSpec> {
    (column >= 0).then_some(SortSpec { column, descending })
}

pub(super) fn sorted_transfers(items: &[TransferDto], spec: Option<SortSpec>) -> Vec<TransferDto> {
    let mut items = items.to_vec();
    if let Some(spec) = spec {
        items.sort_by(|a, b| {
            sort_order(
                match spec.column {
                    0 => cmp_text(display_or(&a.name, &a.hash), display_or(&b.name, &b.hash)),
                    1 => cmp_text(&a.state, &b.state),
                    2 => cmp_f64(transfer_progress(a), transfer_progress(b)),
                    3 => a.size_bytes.cmp(&b.size_bytes),
                    4 => cmp_f64(
                        a.download_speed_ki_bps.unwrap_or(0.0),
                        b.download_speed_ki_bps.unwrap_or(0.0),
                    ),
                    5 => a.sources.unwrap_or(0).cmp(&b.sources.unwrap_or(0)),
                    6 => cmp_text(
                        a.category_name.as_deref().unwrap_or("Uncategorized"),
                        b.category_name.as_deref().unwrap_or("Uncategorized"),
                    ),
                    _ => cmp_text(&a.hash, &b.hash),
                }
                .then_with(|| cmp_text(&a.hash, &b.hash)),
                spec.descending,
            )
        });
    }
    items
}

pub(super) fn sorted_search_results(
    items: &[SearchResultDto],
    spec: Option<SortSpec>,
) -> Vec<SearchResultDto> {
    let mut items = items.to_vec();
    if let Some(spec) = spec {
        items.sort_by(|a, b| {
            sort_order(
                match spec.column {
                    0 => cmp_text(display_or(&a.name, &a.hash), display_or(&b.name, &b.hash)),
                    1 => a.size_bytes.cmp(&b.size_bytes),
                    2 => a.sources.cmp(&b.sources),
                    3 => a.complete_sources.cmp(&b.complete_sources),
                    4 => cmp_text(
                        display_or(&a.file_type, &a.result_type),
                        display_or(&b.file_type, &b.result_type),
                    ),
                    5 => cmp_text(&a.method, &b.method),
                    6 => cmp_text(&a.known_type, &b.known_type),
                    7 => cmp_text(&a.hash, &b.hash),
                    _ => cmp_text(&a.hash, &b.hash),
                }
                .then_with(|| cmp_text(&a.hash, &b.hash)),
                spec.descending,
            )
        });
    }
    items
}

pub(super) fn sorted_uploads(items: &[UploadDto], spec: Option<SortSpec>) -> Vec<UploadDto> {
    let mut items = items.to_vec();
    if let Some(spec) = spec {
        items.sort_by(|a, b| {
            sort_order(
                match spec.column {
                    0 => cmp_text(
                        display_or(&a.user_name, &a.client_id),
                        display_or(&b.user_name, &b.client_id),
                    ),
                    1 => cmp_text(&a.client_id, &b.client_id),
                    2 => cmp_text(
                        a.requested_file_name.as_deref().unwrap_or("-"),
                        b.requested_file_name.as_deref().unwrap_or("-"),
                    ),
                    3 => cmp_text(&a.upload_state, &b.upload_state),
                    4 => cmp_f64(a.upload_speed_ki_bps, b.upload_speed_ki_bps),
                    5 => a.uploaded_bytes.cmp(&b.uploaded_bytes),
                    6 => a
                        .requested_file_size_bytes
                        .unwrap_or(0)
                        .cmp(&b.requested_file_size_bytes.unwrap_or(0)),
                    7 => cmp_f64(
                        progress_ratio(a.uploaded_bytes, a.requested_file_size_bytes.unwrap_or(0)),
                        progress_ratio(b.uploaded_bytes, b.requested_file_size_bytes.unwrap_or(0)),
                    ),
                    _ => cmp_text(&a.client_id, &b.client_id),
                }
                .then_with(|| cmp_text(&a.client_id, &b.client_id)),
                spec.descending,
            )
        });
    }
    items
}

pub(super) fn sorted_servers(items: &[ServerDto], spec: Option<SortSpec>) -> Vec<ServerDto> {
    let mut items = items.to_vec();
    if let Some(spec) = spec {
        items.sort_by(|a, b| {
            let a_endpoint = server_endpoint(a);
            let b_endpoint = server_endpoint(b);
            sort_order(
                match spec.column {
                    0 => cmp_text(
                        display_or(&a.name, &a_endpoint),
                        display_or(&b.name, &b_endpoint),
                    ),
                    1 => cmp_text(&a_endpoint, &b_endpoint),
                    2 => cmp_text(server_status(a), server_status(b)),
                    3 => a.users.cmp(&b.users),
                    4 => a.files.cmp(&b.files),
                    5 => a.ping.cmp(&b.ping),
                    6 => cmp_text(&a.priority, &b.priority),
                    7 => a.failed_count.cmp(&b.failed_count),
                    _ => cmp_text(&a_endpoint, &b_endpoint),
                }
                .then_with(|| cmp_text(&a_endpoint, &b_endpoint)),
                spec.descending,
            )
        });
    }
    items
}

pub(super) fn sorted_shared_files(
    items: &[SharedFileDto],
    spec: Option<SortSpec>,
) -> Vec<SharedFileDto> {
    let mut items = items.to_vec();
    if let Some(spec) = spec {
        items.sort_by(|a, b| {
            sort_order(
                match spec.column {
                    0 => cmp_text(display_or(&a.name, &a.hash), display_or(&b.name, &b.hash)),
                    1 => a.size_bytes.cmp(&b.size_bytes),
                    2 => cmp_text(&a.priority, &b.priority),
                    3 => a.rating.cmp(&b.rating),
                    4 => a
                        .all_time_requests
                        .max(a.requests)
                        .cmp(&b.all_time_requests.max(b.requests)),
                    5 => a
                        .all_time_transferred
                        .max(a.transferred_bytes)
                        .cmp(&b.all_time_transferred.max(b.transferred_bytes)),
                    6 => cmp_text(&a.directory, &b.directory),
                    _ => cmp_text(&a.hash, &b.hash),
                }
                .then_with(|| cmp_text(&a.hash, &b.hash)),
                spec.descending,
            )
        });
    }
    items
}

pub(super) fn sorted_logs(items: &[LogEntryDto], spec: Option<SortSpec>) -> Vec<LogEntryDto> {
    let mut items = items.to_vec();
    if let Some(spec) = spec {
        items.sort_by(|a, b| {
            sort_order(
                match spec.column {
                    0 => cmp_text(
                        &timestamp_text(a.timestamp.as_ref()),
                        &timestamp_text(b.timestamp.as_ref()),
                    ),
                    1 => cmp_text(
                        a.level.as_deref().unwrap_or("info"),
                        b.level.as_deref().unwrap_or("info"),
                    ),
                    2 => cmp_text(&a.message, &b.message),
                    _ => cmp_text(&a.message, &b.message),
                },
                spec.descending,
            )
        });
    }
    items
}

pub(super) fn transfer_progress(item: &TransferDto) -> f64 {
    item.progress
        .unwrap_or_else(|| progress_ratio(item.completed_bytes.unwrap_or(0), item.size_bytes))
}

pub(super) fn server_endpoint(item: &ServerDto) -> String {
    format!("{}:{}", item.address, item.port)
}

pub(super) fn server_status(item: &ServerDto) -> &'static str {
    if item.connected {
        "connected"
    } else if item.connecting {
        "connecting"
    } else {
        "known"
    }
}

pub(super) fn cmp_text(a: &str, b: &str) -> Ordering {
    a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase())
}

pub(super) fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

pub(super) fn sort_order(ordering: Ordering, descending: bool) -> Ordering {
    if descending {
        ordering.reverse()
    } else {
        ordering
    }
}

pub(super) fn transfer_items(transfers: &[TransferDto]) -> Vec<TransferItem> {
    transfers
        .iter()
        .map(|item| {
            let progress = item.progress.unwrap_or_else(|| {
                progress_ratio(item.completed_bytes.unwrap_or(0), item.size_bytes)
            });
            let done = item
                .completed_bytes
                .unwrap_or((item.size_bytes as f64 * progress) as u64);
            let detail = format!(
                "Hash: {}\nState: {}\nProgress: {:.1}%\nSize: {} / {}\nSpeed: {:.1} KiB/s\nSources: {} total, {} active\nCategory: {}",
                item.hash,
                item.state,
                ratio(progress) * 100.0,
                bytes(done),
                bytes(item.size_bytes),
                item.download_speed_ki_bps.unwrap_or(0.0),
                item.sources.unwrap_or(0),
                item.sources_transferring.unwrap_or(0),
                item.category_name.as_deref().unwrap_or("Uncategorized")
            );
            TransferItem {
                hash: text(&item.hash),
                name: text(display_or(&item.name, &item.hash)),
                state: text(&item.state),
                progress: ratio(progress),
                progress_text: text(format!("{:.1}%", ratio(progress) * 100.0)),
                size_text: text(format!("{} / {}", bytes(done), bytes(item.size_bytes))),
                speed_text: text(format!(
                    "{:.1} KiB/s",
                    item.download_speed_ki_bps.unwrap_or(0.0)
                )),
                sources_text: text(format!(
                    "{} sources, {} active",
                    item.sources.unwrap_or(0),
                    item.sources_transferring.unwrap_or(0)
                )),
                category: text(item.category_name.as_deref().unwrap_or("Uncategorized")),
                detail: text(detail),
            }
        })
        .collect()
}

pub(super) fn search_result_items_for(
    search: &SearchDto,
    items: &[SearchResultDto],
) -> Vec<SearchResultItem> {
    items
        .iter()
        .map(|item| {
            let detail = format!(
                "Search: {} ({})\nHash: {}\nName: {}\nSize: {}\nSources: {} total, {} complete\nMethod: {}\nKnown state: {}\nType: {}\nDirectory: {}",
                search.id,
                search.query,
                item.hash,
                item.name,
                bytes(item.size_bytes),
                item.sources,
                item.complete_sources,
                item.method,
                item.known_type,
                display_or(&item.file_type, &item.result_type),
                item.directory.as_deref().unwrap_or("-")
            );
            SearchResultItem {
                search_id: text(&item.search_id),
                hash: text(&item.hash),
                name: text(display_or(&item.name, &item.hash)),
                size_text: text(bytes(item.size_bytes)),
                sources_text: text(item.sources.to_string()),
                complete_sources_text: text(item.complete_sources.to_string()),
                file_type: text(display_or(&item.file_type, &item.result_type)),
                method: text(&item.method),
                known_type: text(if item.complete.unwrap_or(false) {
                    "complete"
                } else {
                    display_or(&item.known_type, "unknown")
                }),
                detail: text(detail),
            }
        })
        .collect()
}

pub(super) fn upload_items(items: &[UploadDto]) -> Vec<UploadItem> {
    items
        .iter()
        .map(|item| {
            let requested_size = item.requested_file_size_bytes.unwrap_or(0);
            let file = item.requested_file_name.as_deref().unwrap_or("-");
            let progress = progress_ratio(item.uploaded_bytes, requested_size);
            let detail = format!(
                "Client: {}\nUser: {}\nState: {}\nRequested file: {}\nRequested size: {}\nUploaded: {}\nProgress: {:.1}%\nSpeed: {:.1} KiB/s",
                item.client_id,
                display_or(&item.user_name, &item.client_id),
                item.upload_state,
                file,
                if requested_size == 0 {
                    "-".to_string()
                } else {
                    bytes(requested_size)
                },
                bytes(item.uploaded_bytes),
                ratio(progress) * 100.0,
                item.upload_speed_ki_bps
            );
            UploadItem {
                client_id: text(&item.client_id),
                user: text(display_or(&item.user_name, &item.client_id)),
                state: text(&item.upload_state),
                file: text(file),
                file_size_text: text(if requested_size == 0 {
                    "-".to_string()
                } else {
                    bytes(requested_size)
                }),
                speed_text: text(format!("{:.1} KiB/s", item.upload_speed_ki_bps)),
                uploaded_text: text(bytes(item.uploaded_bytes)),
                progress_text: text(format!("{:.1}%", ratio(progress) * 100.0)),
                ratio: ratio(progress),
                detail: text(detail),
            }
        })
        .collect()
}

pub(super) fn server_items(servers: &[ServerDto]) -> Vec<ServerItem> {
    servers
        .iter()
        .map(|item| {
            let endpoint = format!("{}:{}", item.address, item.port);
            let detail = format!(
                "Endpoint: {}\nStatus: {}\nUsers: {}\nFiles: {}\nPing: {}\nPriority: {}\nStatic: {}\nFailed count: {}",
                endpoint,
                if item.connected {
                    "connected"
                } else if item.connecting {
                    "connecting"
                } else {
                    "known"
                },
                item.users,
                item.files,
                if item.ping == 0 { "-".to_string() } else { format!("{} ms", item.ping) },
                item.priority,
                yes_no(item.static_server),
                item.failed_count
            );
            ServerItem {
                name: text(display_or(&item.name, &endpoint)),
                endpoint_id: text(&endpoint),
                address: text(&item.address),
                port_text: text(item.port.to_string()),
                endpoint: text(format!(
                "{}:{}{}",
                item.address,
                item.port,
                if item.static_server { " | static" } else { "" }
                )),
                status: text(if item.connected {
                    "connected"
                } else if item.connecting {
                    "connecting"
                } else {
                    "known"
                }),
                users_text: text(format_count(item.users, "users")),
                files_text: text(format_count(item.files, "files")),
                ping_text: text(if item.ping == 0 {
                    "-".to_string()
                } else {
                    format!("{} ms", item.ping)
                }),
                priority: text(&item.priority),
                failed_text: text(format!("{} fails", item.failed_count)),
                static_server: item.static_server,
                current: item.current,
                detail: text(detail),
            }
        })
        .collect()
}

pub(super) fn shared_file_items(files: &[SharedFileDto]) -> Vec<SharedFileItem> {
    let max_requests = files
        .iter()
        .map(|file| file.all_time_requests.max(file.requests))
        .max()
        .unwrap_or(1)
        .max(1);
    files
        .iter()
        .map(|item| {
            let requests = item.all_time_requests.max(item.requests);
            let accepts = item.all_time_accepts.max(item.accepted_requests);
            let transferred = item.all_time_transferred.max(item.transferred_bytes);
            let detail = format!(
                "Hash: {}\nDirectory: {}\nSize: {}\nPriority: {}\nRequests: {} total, {} accepted\nTransferred: {}\nRating: {}\nED2K: {}",
                item.hash,
                item.directory,
                bytes(item.size_bytes),
                item.priority,
                requests,
                accepts,
                bytes(transferred),
                item.rating,
                item.ed2k_link.as_deref().unwrap_or("-")
            );
            SharedFileItem {
                hash: text(&item.hash),
                name: text(display_or(&item.name, &item.hash)),
                directory: text(&item.directory),
                size_text: text(bytes(item.size_bytes)),
                requests_text: text(format!("{requests} req / {accepts} ok")),
                transferred_text: text(bytes(transferred)),
                priority: text(&item.priority),
                rating_text: text(if item.has_comment {
                    format!("{} + note", item.rating)
                } else {
                    item.rating.to_string()
                }),
                demand_ratio: ratio(requests as f64 / max_requests as f64),
                detail: text(detail),
            }
        })
        .collect()
}

pub(super) fn log_items(logs: &[LogEntryDto]) -> Vec<LogItem> {
    logs.iter()
        .map(|entry| LogItem {
            timestamp: text(timestamp_text(entry.timestamp.as_ref())),
            level: text(entry.level.as_deref().unwrap_or("info")),
            message: text(&entry.message),
        })
        .collect()
}

pub(super) fn transfer_columns() -> Vec<TableColumn> {
    columns(&[
        ("Name", 360.0, 2.0),
        ("State", 92.0, 0.0),
        ("Progress", 86.0, 0.0),
        ("Size", 138.0, 0.0),
        ("Down", 92.0, 0.0),
        ("Sources", 132.0, 0.0),
        ("Category", 128.0, 1.0),
    ])
}

pub(super) fn search_result_columns() -> Vec<TableColumn> {
    columns(&[
        ("Name", 410.0, 2.0),
        ("Size", 96.0, 0.0),
        ("Sources", 82.0, 0.0),
        ("Complete", 86.0, 0.0),
        ("Type", 92.0, 0.0),
        ("Method", 92.0, 0.0),
        ("Known", 112.0, 0.0),
        ("Hash", 260.0, 1.0),
    ])
}

pub(super) fn server_columns() -> Vec<TableColumn> {
    columns(&[
        ("Name", 230.0, 2.0),
        ("Endpoint", 190.0, 1.0),
        ("Status", 96.0, 0.0),
        ("Users", 100.0, 0.0),
        ("Files", 100.0, 0.0),
        ("Ping", 78.0, 0.0),
        ("Priority", 90.0, 0.0),
        ("Fails", 82.0, 0.0),
    ])
}

pub(super) fn shared_file_columns() -> Vec<TableColumn> {
    columns(&[
        ("Name", 360.0, 2.0),
        ("Size", 96.0, 0.0),
        ("Priority", 82.0, 0.0),
        ("Rating", 82.0, 0.0),
        ("Requests", 132.0, 0.0),
        ("Transferred", 120.0, 0.0),
        ("Directory", 280.0, 1.0),
    ])
}

pub(super) fn upload_columns() -> Vec<TableColumn> {
    columns(&[
        ("User", 190.0, 1.0),
        ("Client", 180.0, 0.0),
        ("File", 360.0, 2.0),
        ("State", 110.0, 0.0),
        ("Up", 92.0, 0.0),
        ("Uploaded", 110.0, 0.0),
        ("File Size", 110.0, 0.0),
        ("Progress", 90.0, 0.0),
    ])
}

pub(super) fn log_columns() -> Vec<TableColumn> {
    columns(&[
        ("Time", 180.0, 0.0),
        ("Level", 82.0, 0.0),
        ("Message", 780.0, 2.0),
    ])
}

pub(super) fn columns(specs: &[(&str, f32, f32)]) -> Vec<TableColumn> {
    specs
        .iter()
        .map(|(title, width, stretch)| {
            let mut column = TableColumn::default();
            column.title = text(*title);
            column.width = *width;
            column.min_width = *width;
            column.horizontal_stretch = *stretch;
            column
        })
        .collect()
}

pub(super) fn transfer_table_rows(items: &[TransferItem]) -> Vec<Vec<StandardListViewItem>> {
    items
        .iter()
        .map(|item| {
            row([
                item.name.clone(),
                item.state.clone(),
                item.progress_text.clone(),
                item.size_text.clone(),
                item.speed_text.clone(),
                item.sources_text.clone(),
                item.category.clone(),
            ])
        })
        .collect()
}

pub(super) fn search_result_table_rows(
    items: &[SearchResultItem],
) -> Vec<Vec<StandardListViewItem>> {
    items
        .iter()
        .map(|item| {
            row([
                item.name.clone(),
                item.size_text.clone(),
                item.sources_text.clone(),
                item.complete_sources_text.clone(),
                item.file_type.clone(),
                item.method.clone(),
                item.known_type.clone(),
                item.hash.clone(),
            ])
        })
        .collect()
}

pub(super) fn server_table_rows(items: &[ServerItem]) -> Vec<Vec<StandardListViewItem>> {
    items
        .iter()
        .map(|item| {
            row([
                item.name.clone(),
                item.endpoint.clone(),
                item.status.clone(),
                item.users_text.clone(),
                item.files_text.clone(),
                item.ping_text.clone(),
                item.priority.clone(),
                item.failed_text.clone(),
            ])
        })
        .collect()
}

pub(super) fn shared_file_table_rows(items: &[SharedFileItem]) -> Vec<Vec<StandardListViewItem>> {
    items
        .iter()
        .map(|item| {
            row([
                item.name.clone(),
                item.size_text.clone(),
                item.priority.clone(),
                item.rating_text.clone(),
                item.requests_text.clone(),
                item.transferred_text.clone(),
                item.directory.clone(),
            ])
        })
        .collect()
}

pub(super) fn upload_table_rows(items: &[UploadItem]) -> Vec<Vec<StandardListViewItem>> {
    items
        .iter()
        .map(|item| {
            row([
                item.user.clone(),
                item.client_id.clone(),
                item.file.clone(),
                item.state.clone(),
                item.speed_text.clone(),
                item.uploaded_text.clone(),
                item.file_size_text.clone(),
                item.progress_text.clone(),
            ])
        })
        .collect()
}

pub(super) fn log_table_rows(items: &[LogItem]) -> Vec<Vec<StandardListViewItem>> {
    items
        .iter()
        .map(|item| {
            row([
                item.timestamp.clone(),
                item.level.clone(),
                item.message.clone(),
            ])
        })
        .collect()
}

pub(super) fn row<const N: usize>(values: [SharedString; N]) -> Vec<StandardListViewItem> {
    values.into_iter().map(StandardListViewItem::from).collect()
}

pub(super) fn lifecycle_line(app: &AppInfo, status: &StatusInfo) -> String {
    let source = if app.lifecycle.state.is_empty() {
        &status.lifecycle
    } else {
        &app.lifecycle
    };
    format!(
        "{} | startup {} | REST {} | mutations {}",
        display_or(&source.state, "unknown"),
        yes_no(source.startup_complete),
        yes_no(source.accepting_rest),
        yes_no(source.accepting_mutations)
    )
}

pub(super) fn network_line(stats: &Stats, kad: &KadDto) -> String {
    let firewall_state = if kad.firewall_state == FirewallState::Unknown {
        stats.kad_firewall_state
    } else {
        kad.firewall_state
    };
    let kad_mode = if kad.bootstrapping {
        "bootstrapping"
    } else if kad.connected || stats.kad_connected {
        "connected"
    } else if kad.running || stats.kad_running {
        "running"
    } else {
        "stopped"
    };
    format!(
        "Core {} | ED2K {} {} | Kad {} {} | {} contacts",
        yes_no(stats.connected),
        yes_no(stats.ed2k_connected),
        if stats.ed2k_high_id {
            "high-id"
        } else {
            "low-id"
        },
        kad_mode,
        kad_firewall_label(firewall_state),
        kad.contact_count.unwrap_or(0)
    )
}

fn kad_firewall_label(state: FirewallState) -> &'static str {
    match state {
        FirewallState::Unknown => "unknown",
        FirewallState::Open => "open",
        FirewallState::Firewalled => "firewalled",
    }
}

pub(super) fn speed_line(stats: &Stats) -> String {
    format!(
        "{:.1} down / {:.1} up KiB/s",
        stats.download_speed_ki_bps, stats.upload_speed_ki_bps
    )
}

pub(super) fn counts_line(snapshot: &Snapshot) -> String {
    format!(
        "Session {} down, {} up | Kad {} users / {} files",
        bytes(snapshot.status.stats.session_downloaded_bytes),
        bytes(snapshot.status.stats.session_uploaded_bytes),
        snapshot.kad.users.unwrap_or(0),
        snapshot.kad.files.unwrap_or(0)
    )
}

pub(super) fn transfer_summary(snapshot: &Snapshot) -> String {
    format!(
        "{} loaded / {} total | {} active",
        snapshot.transfers.len(),
        snapshot.status.stats.download_count,
        snapshot.status.stats.active_downloads.unwrap_or(0)
    )
}

pub(super) fn upload_summary(snapshot: &Snapshot) -> String {
    format!(
        "{} loaded / {} active / {} queued",
        snapshot.uploads.len(),
        snapshot.status.stats.active_uploads,
        snapshot
            .status
            .stats
            .waiting_uploads
            .max(snapshot.upload_queue.len() as u64)
    )
}

pub(super) fn server_summary(snapshot: &Snapshot) -> String {
    let connected = snapshot
        .servers
        .iter()
        .filter(|server| server.connected)
        .count();
    format!("{} known | {} connected", snapshot.servers.len(), connected)
}

pub(super) fn shared_summary(snapshot: &Snapshot) -> String {
    let total_size = snapshot
        .shared_files
        .iter()
        .map(|file| file.size_bytes)
        .sum::<u64>();
    format!(
        "{} files | {}",
        snapshot.shared_files.len(),
        bytes(total_size)
    )
}

pub(super) fn search_status_line(search: &SearchDto) -> String {
    let total = search.total.unwrap_or(search.items.len() as u64);
    let reason = search
        .status_reason
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" | {value}"))
        .unwrap_or_default();
    let search_type = search
        .file_type
        .trim()
        .is_empty()
        .then(String::new)
        .unwrap_or_else(|| format!(" | {}", search.file_type));
    format!(
        "{} | {}{} | {} | {} results{}",
        search.query,
        display_or(&search.method, "automatic"),
        search_type,
        display_or(&search.status, "unknown"),
        total,
        reason
    )
}

pub(super) fn normalize_search_method(method: &str) -> String {
    match method.trim().to_ascii_lowercase().as_str() {
        "" => "automatic".to_string(),
        "auto" => "automatic".to_string(),
        "automatic" | "server" | "global" | "kad" => method.trim().to_ascii_lowercase(),
        _ => method.trim().to_ascii_lowercase(),
    }
}

pub(super) fn normalize_search_type(file_type: &str) -> String {
    file_type.trim().to_ascii_lowercase()
}

pub(super) fn latest_search_id(items: &[SearchSessionDto]) -> Option<String> {
    items
        .iter()
        .filter(|item| !item.id.trim().is_empty())
        .max_by_key(|item| item.id.parse::<u64>().unwrap_or(0))
        .map(|item| item.id.clone())
}

pub(super) fn empty_model<T: Clone + 'static>() -> ModelRc<T> {
    model(Vec::<T>::new())
}

pub(super) fn empty_table_model() -> ModelRc<ModelRc<StandardListViewItem>> {
    table_model(Vec::new())
}

pub(super) fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(Rc::new(VecModel::from(items)))
}

pub(super) fn table_model(
    items: Vec<Vec<StandardListViewItem>>,
) -> ModelRc<ModelRc<StandardListViewItem>> {
    let rows = items.into_iter().map(model).collect::<Vec<_>>();
    model(rows)
}

pub(super) fn timestamp_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(timestamp)) => timestamp.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

pub(super) fn progress_ratio(done: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        done as f64 / total as f64
    }
}

pub(super) fn ratio(value: f64) -> f32 {
    value.clamp(0.0, 1.0) as f32
}

pub(super) fn bytes(value: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    let value = value as f64;
    if value >= GIB {
        format!("{:.1} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.1} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{value:.0} B")
    }
}

pub(super) fn format_count(value: u64, unit: &str) -> String {
    if value >= 1_000_000 {
        format!("{:.1}M {unit}", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}K {unit}", value as f64 / 1_000.0)
    } else {
        format!("{value} {unit}")
    }
}

pub(super) fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub(super) fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

pub(super) fn text(value: impl Into<SharedString>) -> SharedString {
    value.into()
}
