use std::collections::VecDeque;
use std::env;
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::Value;
use slint::language::{StandardListViewItem, TableColumn};
use slint::{ModelRc, SharedString, VecModel};

slint::include_modules!();

const DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;
const SNAPSHOT_LIMIT: usize = 200;
const SPEED_HISTORY_LIMIT: usize = 36;

#[derive(Debug, Parser)]
#[command(
    name = "emulebb-rust-ui",
    about = "Native UI for the emulebb-rust REST API"
)]
struct Cli {
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long, default_value = "")]
    api_key: String,
    #[arg(long, default_value_t = DEFAULT_POLL_INTERVAL_MS)]
    poll_interval_ms: u64,
}

#[derive(Debug, Clone)]
struct ConnectionConfig {
    base_url: String,
    api_key: String,
}

#[derive(Debug)]
enum UiCommand {
    Connect(ConnectionConfig),
    Refresh,
    TransferAction { hash: String, action: String },
    ServerAction { action: String },
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ApiError,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    app: AppInfo,
    status: StatusInfo,
    transfers: Vec<TransferDto>,
    shared_files: Vec<SharedFileDto>,
    uploads: Vec<UploadDto>,
    upload_queue: Vec<UploadDto>,
    servers: Vec<ServerDto>,
    kad: KadDto,
    logs: Vec<LogEntryDto>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    name: String,
    version: String,
    lifecycle: Lifecycle,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StatusInfo {
    lifecycle: Lifecycle,
    stats: Stats,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Lifecycle {
    state: String,
    startup_complete: bool,
    accepting_rest: bool,
    accepting_mutations: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Stats {
    connected: bool,
    download_speed_ki_bps: f64,
    upload_speed_ki_bps: f64,
    session_downloaded_bytes: u64,
    session_uploaded_bytes: u64,
    active_downloads: Option<u64>,
    active_uploads: u64,
    waiting_uploads: u64,
    download_count: u64,
    ed2k_connected: bool,
    ed2k_high_id: bool,
    kad_running: bool,
    kad_connected: bool,
    kad_firewalled: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct KadDto {
    running: bool,
    connected: bool,
    firewalled: bool,
    bootstrapping: bool,
    contact_count: Option<u64>,
    users: Option<u64>,
    files: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TransferDto {
    hash: String,
    name: String,
    size_bytes: u64,
    completed_bytes: Option<u64>,
    progress: Option<f64>,
    state: String,
    category_name: Option<String>,
    download_speed_ki_bps: Option<f64>,
    sources: Option<u64>,
    sources_transferring: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UploadDto {
    client_id: String,
    user_name: String,
    upload_state: String,
    upload_speed_ki_bps: f64,
    uploaded_bytes: u64,
    requested_file_name: Option<String>,
    requested_file_size_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ServerDto {
    address: String,
    port: u16,
    name: String,
    priority: String,
    #[serde(rename = "static")]
    static_server: bool,
    connected: bool,
    connecting: bool,
    current: bool,
    failed_count: u64,
    ping: u64,
    users: u64,
    files: u64,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SharedFileDto {
    hash: String,
    name: String,
    directory: String,
    ed2k_link: Option<String>,
    size_bytes: u64,
    priority: String,
    requests: u64,
    accepted_requests: u64,
    transferred_bytes: u64,
    all_time_requests: u64,
    all_time_accepts: u64,
    all_time_transferred: u64,
    rating: u64,
    has_comment: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LogEntryDto {
    timestamp: Option<Value>,
    level: Option<String>,
    message: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let initial_config = ConnectionConfig {
        base_url: cli.base_url.unwrap_or_else(default_base_url),
        api_key: cli.api_key,
    };
    let ui = MainWindow::new().context("failed to create Slint window")?;
    ui.set_base_url(initial_config.base_url.clone().into());
    ui.set_api_key(initial_config.api_key.clone().into());
    ui.set_connection_state("Idle".into());
    ui.set_lifecycle_line("No daemon".into());
    ui.set_network_line("No data".into());
    ui.set_speed_line("0.0 down / 0.0 up KiB/s".into());
    ui.set_counts_line("Waiting for snapshot".into());
    ui.set_transfer_summary("0 transfers".into());
    ui.set_upload_summary("0 active / 0 queued".into());
    ui.set_server_summary("0 known".into());
    ui.set_shared_summary("0 shared".into());
    ui.set_transfers(empty_model());
    ui.set_uploads(empty_model());
    ui.set_servers(empty_model());
    ui.set_shared_files(empty_model());
    ui.set_logs(empty_model());
    ui.set_speed_samples(empty_model());
    ui.set_transfer_columns(model(transfer_columns()));
    ui.set_server_columns(model(server_columns()));
    ui.set_shared_file_columns(model(shared_file_columns()));
    ui.set_upload_columns(model(upload_columns()));
    ui.set_log_columns(model(log_columns()));
    ui.set_transfer_rows(empty_table_model());
    ui.set_server_rows(empty_table_model());
    ui.set_shared_file_rows(empty_table_model());
    ui.set_upload_rows(empty_table_model());
    ui.set_log_rows(empty_table_model());
    ui.set_selected_kind("".into());
    ui.set_selected_id("".into());
    ui.set_inspector_title("Inspector".into());
    ui.set_inspector_detail("Select a row to inspect details and actions.".into());

    let (tx, rx) = mpsc::channel::<UiCommand>();
    let weak = ui.as_weak();
    let poll_interval = Duration::from_millis(cli.poll_interval_ms.max(1_000));
    thread::spawn(move || worker_loop(weak, rx, poll_interval));
    let _ = tx.send(UiCommand::Connect(initial_config));

    let connect_tx = tx.clone();
    let refresh_tx = tx.clone();
    let transfer_tx = tx.clone();
    let server_tx = tx.clone();
    ui.on_connect_requested(move |base_url, api_key| {
        let _ = connect_tx.send(UiCommand::Connect(ConnectionConfig {
            base_url: base_url.to_string(),
            api_key: api_key.to_string(),
        }));
    });

    ui.on_refresh_requested(move || {
        let _ = refresh_tx.send(UiCommand::Refresh);
    });

    ui.on_transfer_action_requested(move |hash, action| {
        let _ = transfer_tx.send(UiCommand::TransferAction {
            hash: hash.to_string(),
            action: action.to_string(),
        });
    });

    ui.on_server_action_requested(move |action| {
        let _ = server_tx.send(UiCommand::ServerAction {
            action: action.to_string(),
        });
    });

    ui.run().context("Slint event loop failed")
}

fn default_base_url() -> String {
    match env::var("X_LOCAL_IP") {
        Ok(ip) if !ip.trim().is_empty() => format!("http://{}:4711/api/v1", ip.trim()),
        _ => "http://192.0.2.1:4711/api/v1".to_string(),
    }
}

fn worker_loop(
    weak: slint::Weak<MainWindow>,
    rx: mpsc::Receiver<UiCommand>,
    poll_interval: Duration,
) {
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        publish_error(&weak, "Failed to start async runtime".to_string(), true);
        return;
    };
    let client = Client::new();
    let mut config: Option<ConnectionConfig> = None;
    let mut speed_history = VecDeque::<(f64, f64)>::new();
    let mut consecutive_failures = 0_u32;

    loop {
        let command = match rx.recv_timeout(poll_interval) {
            Ok(command) => Some(command),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };

        let command = match command {
            Some(UiCommand::Connect(next_config)) => {
                config = Some(next_config.clone());
                speed_history.clear();
                consecutive_failures = 0;
                publish_refreshing(&weak, true);
                let result = runtime.block_on(fetch_snapshot(&client, &next_config));
                match result {
                    Ok(snapshot) => {
                        push_speed_sample(&mut speed_history, &snapshot.status.stats);
                        publish_snapshot(&weak, snapshot, &speed_history);
                    }
                    Err(error) => {
                        consecutive_failures += 1;
                        publish_poll_error(&weak, error.to_string(), consecutive_failures, true);
                    }
                }
                publish_refreshing(&weak, false);
                continue;
            }
            other => other,
        };

        let Some(config_for_command) = config.clone() else {
            continue;
        };

        let visible_refresh = command.is_some();
        if visible_refresh {
            publish_refreshing(&weak, true);
        }

        let result = match command {
            Some(UiCommand::TransferAction { hash, action }) => runtime.block_on(async {
                if hash.trim().is_empty() {
                    anyhow::bail!("select a transfer before running an action");
                }
                post_operation(
                    &client,
                    &config_for_command,
                    &format!("transfers/{hash}/operations/{action}"),
                )
                .await?;
                fetch_snapshot(&client, &config_for_command).await
            }),
            Some(UiCommand::ServerAction { action }) => runtime.block_on(async {
                post_operation(
                    &client,
                    &config_for_command,
                    &format!("servers/operations/{action}"),
                )
                .await?;
                fetch_snapshot(&client, &config_for_command).await
            }),
            Some(UiCommand::Refresh) | None => {
                runtime.block_on(fetch_snapshot(&client, &config_for_command))
            }
            Some(UiCommand::Connect(_)) => unreachable!("connect commands are handled separately"),
        };
        match result {
            Ok(snapshot) => {
                consecutive_failures = 0;
                push_speed_sample(&mut speed_history, &snapshot.status.stats);
                publish_snapshot(&weak, snapshot, &speed_history);
            }
            Err(error) => {
                consecutive_failures += 1;
                publish_poll_error(
                    &weak,
                    error.to_string(),
                    consecutive_failures,
                    visible_refresh,
                );
            }
        }

        if visible_refresh {
            publish_refreshing(&weak, false);
        }
    }
}

async fn fetch_snapshot(client: &Client, config: &ConnectionConfig) -> Result<Snapshot> {
    get(client, config, &format!("snapshot?limit={SNAPSHOT_LIMIT}")).await
}

async fn get<T>(client: &Client, config: &ConnectionConfig, path: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.get(url);
    if !config.api_key.trim().is_empty() {
        request = request.header("X-API-Key", config.api_key.trim());
    }

    let response = request.send().await.context("REST request failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read REST response")?;
    if status.is_success() {
        let envelope: Envelope<T> =
            serde_json::from_slice(&bytes).context("failed to decode REST envelope")?;
        Ok(envelope.data)
    } else {
        Err(decode_error(status, &bytes))
    }
}

async fn post_operation(client: &Client, config: &ConnectionConfig, path: &str) -> Result<()> {
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.post(url);
    if !config.api_key.trim().is_empty() {
        request = request.header("X-API-Key", config.api_key.trim());
    }
    let response = request.send().await.context("REST operation failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read REST operation response")?;
    if status.is_success() {
        Ok(())
    } else {
        Err(decode_error(status, &bytes))
    }
}

fn endpoint(base_url: &str, path: &str) -> Result<Url> {
    let base = if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    };
    let url = Url::parse(&base).with_context(|| format!("invalid REST base URL: {base_url}"))?;
    url.join(path)
        .with_context(|| format!("invalid REST path: {path}"))
}

fn decode_error(status: StatusCode, bytes: &[u8]) -> anyhow::Error {
    match serde_json::from_slice::<ErrorEnvelope>(bytes) {
        Ok(error) => anyhow::anyhow!(
            "REST error {}: {} ({})",
            status.as_u16(),
            error.error.message,
            error.error.code
        ),
        Err(_) => anyhow::anyhow!("REST error {}", status.as_u16()),
    }
}

fn push_speed_sample(history: &mut VecDeque<(f64, f64)>, stats: &Stats) {
    history.push_back((stats.download_speed_ki_bps, stats.upload_speed_ki_bps));
    while history.len() > SPEED_HISTORY_LIMIT {
        let _ = history.pop_front();
    }
}

fn publish_snapshot(
    weak: &slint::Weak<MainWindow>,
    snapshot: Snapshot,
    speed_history: &VecDeque<(f64, f64)>,
) {
    let speed_samples = speed_samples(speed_history);
    let update = move |ui: MainWindow| {
        ui.set_connection_state(
            format!(
                "Connected to {} {}",
                snapshot.app.name, snapshot.app.version
            )
            .into(),
        );
        ui.set_error_message("".into());
        ui.set_lifecycle_line(lifecycle_line(&snapshot.app, &snapshot.status).into());
        ui.set_network_line(network_line(&snapshot.status.stats, &snapshot.kad).into());
        ui.set_speed_line(speed_line(&snapshot.status.stats).into());
        ui.set_counts_line(counts_line(&snapshot).into());
        ui.set_transfer_summary(transfer_summary(&snapshot).into());
        ui.set_upload_summary(upload_summary(&snapshot).into());
        ui.set_server_summary(server_summary(&snapshot).into());
        ui.set_shared_summary(shared_summary(&snapshot).into());
        let transfers = transfer_items(&snapshot.transfers);
        let uploads = upload_items(&snapshot.uploads, &snapshot.upload_queue);
        let servers = server_items(&snapshot.servers);
        let shared_files = shared_file_items(&snapshot.shared_files);
        let logs = log_items(&snapshot.logs);
        ui.set_transfer_rows(table_model(transfer_table_rows(&transfers)));
        ui.set_upload_rows(table_model(upload_table_rows(&uploads)));
        ui.set_server_rows(table_model(server_table_rows(&servers)));
        ui.set_shared_file_rows(table_model(shared_file_table_rows(&shared_files)));
        ui.set_log_rows(table_model(log_table_rows(&logs)));
        ui.set_transfers(model(transfers));
        ui.set_uploads(model(uploads));
        ui.set_servers(model(servers));
        ui.set_shared_files(model(shared_files));
        ui.set_logs(model(logs));
        ui.set_speed_samples(model(speed_samples));
    };
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            update(ui);
        }
    });
}

fn publish_poll_error(
    weak: &slint::Weak<MainWindow>,
    message: String,
    consecutive_failures: u32,
    visible_refresh: bool,
) {
    let disconnected = consecutive_failures >= 3;
    let message = if disconnected {
        format!("REST polling failed {consecutive_failures} times: {message}")
    } else if visible_refresh {
        message
    } else {
        format!("Last REST poll failed: {message}")
    };
    publish_error(weak, message, disconnected);
}

fn publish_error(weak: &slint::Weak<MainWindow>, message: String, disconnected: bool) {
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            if disconnected {
                ui.set_connection_state("Disconnected".into());
            }
            ui.set_error_message(message.into());
        }
    });
}

fn publish_refreshing(weak: &slint::Weak<MainWindow>, refreshing: bool) {
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_is_refreshing(refreshing);
        }
    });
}

fn transfer_items(transfers: &[TransferDto]) -> Vec<TransferItem> {
    transfers
        .iter()
        .map(|item| {
            let progress = item.progress.unwrap_or_else(|| {
                progress_ratio(item.completed_bytes.unwrap_or(0), item.size_bytes)
            });
            let done = item
                .completed_bytes
                .unwrap_or_else(|| (item.size_bytes as f64 * progress) as u64);
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

fn upload_items(active: &[UploadDto], queued: &[UploadDto]) -> Vec<UploadItem> {
    active
        .iter()
        .chain(queued.iter())
        .map(|item| {
            let requested_size = item.requested_file_size_bytes.unwrap_or(0);
            let file = item.requested_file_name.as_deref().unwrap_or("-");
            let detail = format!(
                "Client: {}\nUser: {}\nState: {}\nRequested file: {}\nUploaded: {}\nSpeed: {:.1} KiB/s",
                item.client_id,
                display_or(&item.user_name, &item.client_id),
                item.upload_state,
                file,
                bytes(item.uploaded_bytes),
                item.upload_speed_ki_bps
            );
            UploadItem {
                client_id: text(&item.client_id),
                user: text(display_or(&item.user_name, &item.client_id)),
                state: text(&item.upload_state),
                file: text(file),
                speed_text: text(format!("{:.1} KiB/s", item.upload_speed_ki_bps)),
                uploaded_text: text(bytes(item.uploaded_bytes)),
                ratio: ratio(progress_ratio(item.uploaded_bytes, requested_size)),
                detail: text(detail),
            }
        })
        .collect()
}

fn server_items(servers: &[ServerDto]) -> Vec<ServerItem> {
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
                current: item.current,
                detail: text(detail),
            }
        })
        .collect()
}

fn shared_file_items(files: &[SharedFileDto]) -> Vec<SharedFileItem> {
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

fn log_items(logs: &[LogEntryDto]) -> Vec<LogItem> {
    logs.iter()
        .map(|entry| LogItem {
            timestamp: text(timestamp_text(entry.timestamp.as_ref())),
            level: text(entry.level.as_deref().unwrap_or("info")),
            message: text(&entry.message),
        })
        .collect()
}

fn transfer_columns() -> Vec<TableColumn> {
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

fn server_columns() -> Vec<TableColumn> {
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

fn shared_file_columns() -> Vec<TableColumn> {
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

fn upload_columns() -> Vec<TableColumn> {
    columns(&[
        ("User", 220.0, 1.0),
        ("File", 420.0, 2.0),
        ("State", 110.0, 0.0),
        ("Up", 92.0, 0.0),
        ("Uploaded", 110.0, 0.0),
        ("Ratio", 90.0, 0.0),
    ])
}

fn log_columns() -> Vec<TableColumn> {
    columns(&[
        ("Time", 180.0, 0.0),
        ("Level", 82.0, 0.0),
        ("Message", 780.0, 2.0),
    ])
}

fn columns(specs: &[(&str, f32, f32)]) -> Vec<TableColumn> {
    specs
        .iter()
        .map(|(title, width, stretch)| {
            let mut column = TableColumn::default();
            column.title = text(*title);
            column.width = (*width).into();
            column.min_width = (*width).into();
            column.horizontal_stretch = *stretch;
            column
        })
        .collect()
}

fn transfer_table_rows(items: &[TransferItem]) -> Vec<Vec<StandardListViewItem>> {
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

fn server_table_rows(items: &[ServerItem]) -> Vec<Vec<StandardListViewItem>> {
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

fn shared_file_table_rows(items: &[SharedFileItem]) -> Vec<Vec<StandardListViewItem>> {
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

fn upload_table_rows(items: &[UploadItem]) -> Vec<Vec<StandardListViewItem>> {
    items
        .iter()
        .map(|item| {
            row([
                item.user.clone(),
                item.file.clone(),
                item.state.clone(),
                item.speed_text.clone(),
                item.uploaded_text.clone(),
                format!("{:.0}%", item.ratio * 100.0).into(),
            ])
        })
        .collect()
}

fn log_table_rows(items: &[LogItem]) -> Vec<Vec<StandardListViewItem>> {
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

fn row<const N: usize>(values: [SharedString; N]) -> Vec<StandardListViewItem> {
    values.into_iter().map(StandardListViewItem::from).collect()
}

fn speed_samples(history: &VecDeque<(f64, f64)>) -> Vec<SpeedSample> {
    let max_speed = history
        .iter()
        .map(|(down, up)| down.max(*up))
        .fold(1.0_f64, f64::max);
    history
        .iter()
        .map(|(down, up)| SpeedSample {
            down: ratio(down / max_speed).max(0.04),
            up: ratio(up / max_speed).max(0.04),
        })
        .collect()
}

fn lifecycle_line(app: &AppInfo, status: &StatusInfo) -> String {
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

fn network_line(stats: &Stats, kad: &KadDto) -> String {
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
        if kad.firewalled || stats.kad_firewalled {
            "firewalled"
        } else {
            "open"
        },
        kad.contact_count.unwrap_or(0)
    )
}

fn speed_line(stats: &Stats) -> String {
    format!(
        "{:.1} down / {:.1} up KiB/s",
        stats.download_speed_ki_bps, stats.upload_speed_ki_bps
    )
}

fn counts_line(snapshot: &Snapshot) -> String {
    format!(
        "Session {} down, {} up | Kad {} users / {} files",
        bytes(snapshot.status.stats.session_downloaded_bytes),
        bytes(snapshot.status.stats.session_uploaded_bytes),
        snapshot.kad.users.unwrap_or(0),
        snapshot.kad.files.unwrap_or(0)
    )
}

fn transfer_summary(snapshot: &Snapshot) -> String {
    format!(
        "{} loaded / {} total | {} active",
        snapshot.transfers.len(),
        snapshot.status.stats.download_count,
        snapshot.status.stats.active_downloads.unwrap_or(0)
    )
}

fn upload_summary(snapshot: &Snapshot) -> String {
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

fn server_summary(snapshot: &Snapshot) -> String {
    let connected = snapshot
        .servers
        .iter()
        .filter(|server| server.connected)
        .count();
    format!("{} known | {} connected", snapshot.servers.len(), connected)
}

fn shared_summary(snapshot: &Snapshot) -> String {
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

fn empty_model<T: Clone + 'static>() -> ModelRc<T> {
    model(Vec::<T>::new())
}

fn empty_table_model() -> ModelRc<ModelRc<StandardListViewItem>> {
    table_model(Vec::new())
}

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(Rc::new(VecModel::from(items)))
}

fn table_model(items: Vec<Vec<StandardListViewItem>>) -> ModelRc<ModelRc<StandardListViewItem>> {
    let rows = items.into_iter().map(model).collect::<Vec<_>>();
    model(rows)
}

fn timestamp_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(timestamp)) => timestamp.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

fn progress_ratio(done: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        done as f64 / total as f64
    }
}

fn ratio(value: f64) -> f32 {
    value.clamp(0.0, 1.0) as f32
}

fn bytes(value: u64) -> String {
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

fn format_count(value: u64, unit: &str) -> String {
    if value >= 1_000_000 {
        format!("{:.1}M {unit}", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}K {unit}", value as f64 / 1_000.0)
    } else {
        format!("{value} {unit}")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

fn text(value: impl Into<SharedString>) -> SharedString {
    value.into()
}
