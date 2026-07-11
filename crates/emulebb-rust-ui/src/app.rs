#[path = "presentation.rs"]
mod presentation;

use std::cmp::Ordering;
use std::env;
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::ui_state;
use anyhow::{Context, Result};
use clap::Parser;
use presentation::*;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use slint::language::{StandardListViewItem, TableColumn};
use slint::{
    CloseRequestResponse, ComponentHandle, Model, ModelRc, PhysicalPosition, PhysicalSize,
    SharedString, VecModel,
};

slint::include_modules!();

const DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;
const SNAPSHOT_LIMIT: usize = 200;
const TABLE_TRANSFERS: &str = "transfers";
const TABLE_SEARCH_RESULTS: &str = "search-results";
const TABLE_SERVERS: &str = "servers";
const TABLE_SHARED_FILES: &str = "shared-files";
const TABLE_UPLOADS: &str = "uploads";
const TABLE_QUEUED_CLIENTS: &str = "queued-clients";
const TABLE_LOGS: &str = "logs";

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
    SearchStart {
        query: String,
        method: String,
        file_type: String,
    },
    SearchRefresh,
    SearchDownload {
        search_id: String,
        hash: String,
        paused: bool,
    },
    TransferAction {
        hash: String,
        action: String,
    },
    ServerAction {
        action: String,
    },
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

#[derive(Debug, Clone, Default)]
struct DataCache {
    snapshot: Option<Snapshot>,
    search: Option<SearchDto>,
}

#[derive(Debug, Deserialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    name: String,
    version: String,
    lifecycle: Lifecycle,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct StatusInfo {
    lifecycle: Lifecycle,
    stats: Stats,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct Lifecycle {
    state: String,
    startup_complete: bool,
    accepting_rest: bool,
    accepting_mutations: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct LogEntryDto {
    timestamp: Option<Value>,
    level: Option<String>,
    message: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct SearchDto {
    id: String,
    query: String,
    method: String,
    #[serde(rename = "type")]
    file_type: String,
    status: String,
    status_reason: Option<String>,
    total: Option<u64>,
    items: Vec<SearchResultDto>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct SearchListDto {
    items: Vec<SearchSessionDto>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct SearchSessionDto {
    id: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct SearchResultDto {
    search_id: String,
    method: String,
    #[serde(rename = "type")]
    result_type: String,
    hash: String,
    name: String,
    size_bytes: u64,
    sources: u64,
    complete_sources: u64,
    file_type: String,
    complete: Option<bool>,
    known_type: String,
    directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchCreateRequest {
    query: String,
    method: String,
    #[serde(rename = "type")]
    file_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchResultDownloadRequest {
    paused: bool,
}

pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    let initial_config = ConnectionConfig {
        base_url: cli.base_url.unwrap_or_else(default_base_url),
        api_key: cli.api_key,
    };
    let saved_state = ui_state::load();
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
    ui.set_search_query("".into());
    ui.set_search_method("automatic".into());
    ui.set_search_type("".into());
    ui.set_search_status_line("No active search".into());
    ui.set_transfers(empty_model());
    ui.set_search_results(empty_model());
    ui.set_uploads(empty_model());
    ui.set_queued_uploads(empty_model());
    ui.set_servers(empty_model());
    ui.set_shared_files(empty_model());
    ui.set_logs(empty_model());
    ui.set_transfer_columns(model(columns_for_state(
        TABLE_TRANSFERS,
        transfer_columns(),
        &saved_state,
    )));
    ui.set_search_result_columns(model(columns_for_state(
        TABLE_SEARCH_RESULTS,
        search_result_columns(),
        &saved_state,
    )));
    ui.set_server_columns(model(columns_for_state(
        TABLE_SERVERS,
        server_columns(),
        &saved_state,
    )));
    ui.set_shared_file_columns(model(columns_for_state(
        TABLE_SHARED_FILES,
        shared_file_columns(),
        &saved_state,
    )));
    ui.set_upload_columns(model(columns_for_state(
        TABLE_UPLOADS,
        upload_columns(),
        &saved_state,
    )));
    ui.set_queued_client_columns(model(columns_for_state(
        TABLE_QUEUED_CLIENTS,
        upload_columns(),
        &saved_state,
    )));
    ui.set_log_columns(model(columns_for_state(
        TABLE_LOGS,
        log_columns(),
        &saved_state,
    )));
    ui.set_transfer_rows(empty_table_model());
    ui.set_search_result_rows(empty_table_model());
    ui.set_server_rows(empty_table_model());
    ui.set_shared_file_rows(empty_table_model());
    ui.set_upload_rows(empty_table_model());
    ui.set_queued_client_rows(empty_table_model());
    ui.set_log_rows(empty_table_model());
    ui.set_selected_kind("".into());
    ui.set_selected_id("".into());
    ui.set_selected_search_id("".into());
    ui.set_inspector_title("Inspector".into());
    ui.set_inspector_detail("Select a row to inspect details and actions.".into());
    apply_saved_state(&ui, &saved_state);

    let (tx, rx) = mpsc::channel::<UiCommand>();
    let weak = ui.as_weak();
    let cache = Arc::new(Mutex::new(DataCache::default()));
    let poll_interval = Duration::from_millis(cli.poll_interval_ms.max(1_000));
    thread::spawn({
        let cache = Arc::clone(&cache);
        move || worker_loop(weak, rx, poll_interval, cache)
    });
    let _ = tx.send(UiCommand::Connect(initial_config));

    let connect_tx = tx.clone();
    let refresh_tx = tx.clone();
    let search_tx = tx.clone();
    let search_refresh_tx = tx.clone();
    let search_download_tx = tx.clone();
    let transfer_tx = tx.clone();
    let server_tx = tx.clone();
    let close_ui = ui.as_weak();
    ui.window().on_close_requested(move || {
        if let Some(ui) = close_ui.upgrade() {
            save_current_ui_state(&ui);
        }
        CloseRequestResponse::HideWindow
    });

    ui.on_connect_requested(move |base_url, api_key| {
        let _ = connect_tx.send(UiCommand::Connect(ConnectionConfig {
            base_url: base_url.to_string(),
            api_key: api_key.to_string(),
        }));
    });

    ui.on_refresh_requested(move || {
        let _ = refresh_tx.send(UiCommand::Refresh);
    });

    let quit_ui = ui.as_weak();
    ui.on_quit_requested(move || {
        if let Some(ui) = quit_ui.upgrade() {
            save_current_ui_state(&ui);
            let _ = ui.hide();
        }
    });

    let tab_ui = ui.as_weak();
    ui.on_tab_requested(move |tab| {
        if let Some(ui) = tab_ui.upgrade() {
            ui.set_selected_tab(tab);
            save_current_ui_state(&ui);
        }
    });

    let reset_ui = ui.as_weak();
    let reset_cache = Arc::clone(&cache);
    ui.on_reset_layout_requested(move || {
        if let Some(ui) = reset_ui.upgrade() {
            reset_layout(&ui);
            rerender_from_cache(&ui, &reset_cache);
            if let Err(error) = ui_state::reset() {
                ui.set_error_message(format!("Layout reset failed: {error}").into());
            } else {
                ui.set_error_message("Layout reset to defaults".into());
            }
        }
    });

    let about_ui = ui.as_weak();
    ui.on_about_requested(move || {
        if let Some(ui) = about_ui.upgrade() {
            ui.set_selected_kind("".into());
            ui.set_selected_id("".into());
            ui.set_inspector_title("eMuleBB Rust UI".into());
            ui.set_inspector_detail(
                "Native Slint UI for the emulebb-rust REST API.\nLayout state is stored per user and does not persist API keys."
                    .into(),
            );
        }
    });

    let sort_ui = ui.as_weak();
    let sort_cache = Arc::clone(&cache);
    ui.on_table_sort_requested(move |table, column, descending| {
        if let Some(ui) = sort_ui.upgrade() {
            set_table_sort(&ui, table.as_str(), column, descending);
            rerender_from_cache(&ui, &sort_cache);
            save_current_ui_state(&ui);
        }
    });

    ui.on_search_requested(move |query, method, file_type| {
        let _ = search_tx.send(UiCommand::SearchStart {
            query: query.to_string(),
            method: method.to_string(),
            file_type: file_type.to_string(),
        });
    });

    ui.on_search_refresh_requested(move || {
        let _ = search_refresh_tx.send(UiCommand::SearchRefresh);
    });

    ui.on_search_download_requested(move |search_id, hash, paused| {
        let _ = search_download_tx.send(UiCommand::SearchDownload {
            search_id: search_id.to_string(),
            hash: hash.to_string(),
            paused,
        });
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
    cache: Arc<Mutex<DataCache>>,
) {
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        publish_error(&weak, "Failed to start async runtime".to_string(), true);
        return;
    };
    let client = Client::new();
    let mut config: Option<ConnectionConfig> = None;
    let mut active_search_id: Option<String> = None;
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
                active_search_id = None;
                consecutive_failures = 0;
                publish_refreshing(&weak, true);
                let result = runtime.block_on(async {
                    let snapshot = fetch_snapshot(&client, &next_config).await?;
                    let search = fetch_latest_search(&client, &next_config)
                        .await
                        .ok()
                        .flatten();
                    Ok::<_, anyhow::Error>((snapshot, search))
                });
                match result {
                    Ok((snapshot, search)) => {
                        if let Some(search) = search {
                            active_search_id = Some(search.id.clone());
                            store_search(&cache, Some(search.clone()));
                            publish_search(&weak, search);
                        } else {
                            store_search(&cache, None);
                            publish_empty_search(&weak, "No active search");
                        }
                        store_snapshot(&cache, snapshot.clone());
                        publish_snapshot(&weak, snapshot);
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

        let active_search_id_for_poll = active_search_id.clone();
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
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None))
            }),
            Some(UiCommand::ServerAction { action }) => runtime.block_on(async {
                post_operation(
                    &client,
                    &config_for_command,
                    &format!("servers/operations/{action}"),
                )
                .await?;
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, None, None))
            }),
            Some(UiCommand::SearchStart {
                query,
                method,
                file_type,
            }) => runtime.block_on(async {
                let created =
                    create_search(&client, &config_for_command, query, method, file_type).await?;
                let search_id = created.id.clone();
                let search = fetch_search(&client, &config_for_command, &search_id)
                    .await
                    .unwrap_or(created);
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, Some(search), Some(search_id)))
            }),
            Some(UiCommand::SearchRefresh) => runtime.block_on(async {
                let search = match active_search_id_for_poll {
                    Some(search_id) => {
                        fetch_search(&client, &config_for_command, &search_id).await?
                    }
                    None => fetch_latest_search(&client, &config_for_command)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("start a search before polling"))?,
                };
                let search_id = search.id.clone();
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, Some(search), Some(search_id)))
            }),
            Some(UiCommand::SearchDownload {
                search_id,
                hash,
                paused,
            }) => runtime.block_on(async {
                if search_id.trim().is_empty() || hash.trim().is_empty() {
                    anyhow::bail!("select a search result before downloading");
                }
                download_search_result(&client, &config_for_command, &search_id, &hash, paused)
                    .await?;
                let search = fetch_search(&client, &config_for_command, &search_id)
                    .await
                    .ok();
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, search, Some(search_id)))
            }),
            Some(UiCommand::Refresh) | None => runtime.block_on(async {
                let search = match active_search_id_for_poll.as_deref() {
                    Some(search_id) => fetch_search(&client, &config_for_command, search_id)
                        .await
                        .ok(),
                    None => fetch_latest_search(&client, &config_for_command)
                        .await
                        .ok()
                        .flatten(),
                };
                let next_search_id = active_search_id_for_poll.or_else(|| {
                    search
                        .as_ref()
                        .filter(|search| !search.id.trim().is_empty())
                        .map(|search| search.id.clone())
                });
                let snapshot = fetch_snapshot(&client, &config_for_command).await?;
                Ok((snapshot, search, next_search_id))
            }),
            Some(UiCommand::Connect(_)) => unreachable!("connect commands are handled separately"),
        };
        match result {
            Ok((snapshot, search, next_active_search_id)) => {
                consecutive_failures = 0;
                if let Some(search_id) = next_active_search_id {
                    active_search_id = Some(search_id);
                }
                if let Some(search) = search {
                    store_search(&cache, Some(search.clone()));
                    publish_search(&weak, search);
                }
                store_snapshot(&cache, snapshot.clone());
                publish_snapshot(&weak, snapshot);
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

async fn create_search(
    client: &Client,
    config: &ConnectionConfig,
    query: String,
    method: String,
    file_type: String,
) -> Result<SearchDto> {
    let query = query.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
    if query.is_empty() {
        anyhow::bail!("enter a search query");
    }
    let request = SearchCreateRequest {
        query,
        method: normalize_search_method(&method),
        file_type: normalize_search_type(&file_type),
    };
    post_json(client, config, "searches", &request).await
}

async fn fetch_search(
    client: &Client,
    config: &ConnectionConfig,
    search_id: &str,
) -> Result<SearchDto> {
    get(
        client,
        config,
        &format!("searches/{search_id}?limit=200&includeEvidence=false&exactTotal=true"),
    )
    .await
}

async fn fetch_latest_search(
    client: &Client,
    config: &ConnectionConfig,
) -> Result<Option<SearchDto>> {
    let searches: SearchListDto = get(client, config, "searches").await?;
    let Some(search_id) = latest_search_id(&searches.items) else {
        return Ok(None);
    };
    fetch_search(client, config, &search_id).await.map(Some)
}

async fn download_search_result(
    client: &Client,
    config: &ConnectionConfig,
    search_id: &str,
    hash: &str,
    paused: bool,
) -> Result<()> {
    let request = SearchResultDownloadRequest { paused };
    let _: Value = post_json(
        client,
        config,
        &format!("searches/{search_id}/results/{hash}/operations/download"),
        &request,
    )
    .await?;
    Ok(())
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

async fn post_json<T, U>(
    client: &Client,
    config: &ConnectionConfig,
    path: &str,
    body: &U,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    U: Serialize + ?Sized,
{
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.post(url).json(body);
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

fn publish_snapshot(weak: &slint::Weak<MainWindow>, snapshot: Snapshot) {
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
        render_snapshot_tables(&ui, &snapshot);
    };
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            update(ui);
        }
    });
}

fn publish_search(weak: &slint::Weak<MainWindow>, search: SearchDto) {
    let update = move |ui: MainWindow| {
        ui.set_search_query(search.query.clone().into());
        ui.set_search_method(search.method.clone().into());
        ui.set_search_type(search.file_type.clone().into());
        ui.set_search_status_line(search_status_line(&search).into());
        render_search_table(&ui, &search);
    };
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            update(ui);
        }
    });
}

fn publish_empty_search(weak: &slint::Weak<MainWindow>, status: &str) {
    let status = status.to_string();
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_search_status_line(status.into());
            ui.set_search_result_rows(empty_table_model());
            ui.set_search_results(empty_model());
            ui.set_selected_search_id("".into());
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

fn store_snapshot(cache: &Arc<Mutex<DataCache>>, snapshot: Snapshot) {
    if let Ok(mut cache) = cache.lock() {
        cache.snapshot = Some(snapshot);
    }
}

fn store_search(cache: &Arc<Mutex<DataCache>>, search: Option<SearchDto>) {
    if let Ok(mut cache) = cache.lock() {
        cache.search = search;
    }
}

fn rerender_from_cache(ui: &MainWindow, cache: &Arc<Mutex<DataCache>>) {
    let Ok(cache) = cache.lock() else {
        return;
    };
    if let Some(snapshot) = cache.snapshot.as_ref() {
        render_snapshot_tables(ui, snapshot);
    }
    if let Some(search) = cache.search.as_ref() {
        render_search_table(ui, search);
    }
}

fn render_snapshot_tables(ui: &MainWindow, snapshot: &Snapshot) {
    let selected = current_selection(ui);
    let transfers = transfer_items(&sorted_transfers(
        &snapshot.transfers,
        sort_spec(
            ui.get_transfer_sort_column(),
            ui.get_transfer_sort_descending(),
        ),
    ));
    let uploads = upload_items(&sorted_uploads(
        &snapshot.uploads,
        sort_spec(ui.get_upload_sort_column(), ui.get_upload_sort_descending()),
    ));
    let queued_uploads = upload_items(&sorted_uploads(
        &snapshot.upload_queue,
        sort_spec(
            ui.get_queued_client_sort_column(),
            ui.get_queued_client_sort_descending(),
        ),
    ));
    let servers = server_items(&sorted_servers(
        &snapshot.servers,
        sort_spec(ui.get_server_sort_column(), ui.get_server_sort_descending()),
    ));
    let shared_files = shared_file_items(&sorted_shared_files(
        &snapshot.shared_files,
        sort_spec(
            ui.get_shared_file_sort_column(),
            ui.get_shared_file_sort_descending(),
        ),
    ));
    let logs = log_items(&sorted_logs(
        &snapshot.logs,
        sort_spec(ui.get_log_sort_column(), ui.get_log_sort_descending()),
    ));
    ui.set_transfer_rows(table_model(transfer_table_rows(&transfers)));
    ui.set_upload_rows(table_model(upload_table_rows(&uploads)));
    ui.set_queued_client_rows(table_model(upload_table_rows(&queued_uploads)));
    ui.set_server_rows(table_model(server_table_rows(&servers)));
    ui.set_shared_file_rows(table_model(shared_file_table_rows(&shared_files)));
    ui.set_log_rows(table_model(log_table_rows(&logs)));
    ui.set_transfers(model(transfers));
    ui.set_uploads(model(uploads));
    ui.set_queued_uploads(model(queued_uploads));
    ui.set_servers(model(servers));
    ui.set_shared_files(model(shared_files));
    ui.set_logs(model(logs));
    restore_selection(ui, selected);
}

fn render_search_table(ui: &MainWindow, search: &SearchDto) {
    let selected = current_selection(ui);
    let sorted = sorted_search_results(
        &search.items,
        sort_spec(
            ui.get_search_result_sort_column(),
            ui.get_search_result_sort_descending(),
        ),
    );
    let results = search_result_items_for(search, &sorted);
    ui.set_search_result_rows(table_model(search_result_table_rows(&results)));
    ui.set_search_results(model(results));
    restore_selection(ui, selected);
}

#[derive(Debug, Clone)]
struct Selection {
    kind: String,
    id: String,
    search_id: String,
}

fn current_selection(ui: &MainWindow) -> Selection {
    Selection {
        kind: ui.get_selected_kind().to_string(),
        id: ui.get_selected_id().to_string(),
        search_id: ui.get_selected_search_id().to_string(),
    }
}

fn restore_selection(ui: &MainWindow, selected: Selection) {
    if selected.kind.is_empty() || selected.id.is_empty() {
        return;
    }
    let mut restored = false;
    match selected.kind.as_str() {
        "transfer" => {
            let items = model_items(ui.get_transfers());
            if let Some(item) = items.iter().find(|item| item.hash == selected.id.as_str()) {
                ui.set_selected_kind(selected.kind.into());
                ui.set_selected_id(item.hash.clone());
                ui.set_inspector_title(item.name.clone());
                ui.set_inspector_detail(item.detail.clone());
                restored = true;
            }
        }
        "upload" => {
            let mut items = model_items(ui.get_uploads());
            items.extend(model_items(ui.get_queued_uploads()));
            if let Some(item) = items
                .iter()
                .find(|item| item.client_id == selected.id.as_str())
            {
                ui.set_selected_kind(selected.kind.into());
                ui.set_selected_id(item.client_id.clone());
                ui.set_inspector_title(item.user.clone());
                ui.set_inspector_detail(item.detail.clone());
                restored = true;
            }
        }
        "server" => {
            let items = model_items(ui.get_servers());
            if let Some(item) = items
                .iter()
                .find(|item| item.endpoint_id == selected.id.as_str())
            {
                ui.set_selected_kind(selected.kind.into());
                ui.set_selected_id(item.endpoint_id.clone());
                ui.set_inspector_title(item.name.clone());
                ui.set_inspector_detail(item.detail.clone());
                restored = true;
            }
        }
        "shared" => {
            let items = model_items(ui.get_shared_files());
            if let Some(item) = items.iter().find(|item| item.hash == selected.id.as_str()) {
                ui.set_selected_kind(selected.kind.into());
                ui.set_selected_id(item.hash.clone());
                ui.set_inspector_title(item.name.clone());
                ui.set_inspector_detail(item.detail.clone());
                restored = true;
            }
        }
        "search-result" => {
            let items = model_items(ui.get_search_results());
            if let Some(item) = items.iter().find(|item| {
                item.hash == selected.id.as_str() && item.search_id == selected.search_id.as_str()
            }) {
                ui.set_selected_kind(selected.kind.into());
                ui.set_selected_id(item.hash.clone());
                ui.set_selected_search_id(item.search_id.clone());
                ui.set_inspector_title(item.name.clone());
                ui.set_inspector_detail(item.detail.clone());
                restored = true;
            }
        }
        _ => {}
    }
    if !restored {
        ui.set_selected_kind("".into());
        ui.set_selected_id("".into());
        ui.set_selected_search_id("".into());
        ui.set_inspector_title("Inspector".into());
        ui.set_inspector_detail("Select a row to inspect details and actions.".into());
    }
}

fn model_items<T: Clone + 'static>(items: ModelRc<T>) -> Vec<T> {
    (0..items.row_count())
        .filter_map(|index| items.row_data(index))
        .collect()
}

fn apply_saved_state(ui: &MainWindow, state: &ui_state::UiState) {
    ui.set_selected_tab(state.selected_tab.unwrap_or(0).clamp(0, 8));
    apply_saved_table_sort(ui, state, TABLE_TRANSFERS);
    apply_saved_table_sort(ui, state, TABLE_SEARCH_RESULTS);
    apply_saved_table_sort(ui, state, TABLE_SERVERS);
    apply_saved_table_sort(ui, state, TABLE_SHARED_FILES);
    apply_saved_table_sort(ui, state, TABLE_UPLOADS);
    apply_saved_table_sort(ui, state, TABLE_QUEUED_CLIENTS);
    apply_saved_table_sort(ui, state, TABLE_LOGS);
    if let Some(window) = state.window.as_ref() {
        ui.window().set_size(PhysicalSize::new(
            window.width.max(980),
            window.height.max(620),
        ));
        ui.window()
            .set_position(PhysicalPosition::new(window.x, window.y));
        if window.maximized {
            ui.window().set_maximized(true);
        }
    }
}

fn apply_saved_table_sort(ui: &MainWindow, state: &ui_state::UiState, table: &str) {
    let Some(table_state) = state.tables.get(table) else {
        return;
    };
    let column = table_state.sort_column.unwrap_or(-1);
    set_table_sort(ui, table, column, table_state.sort_descending);
}

fn columns_for_state(
    table: &str,
    mut columns: Vec<TableColumn>,
    state: &ui_state::UiState,
) -> Vec<TableColumn> {
    if let Some(table_state) = state.tables.get(table) {
        for (column, width) in columns.iter_mut().zip(table_state.column_widths.iter()) {
            if *width >= 24.0 {
                column.width = *width;
            }
        }
    }
    columns
}

fn reset_layout(ui: &MainWindow) {
    ui.set_selected_tab(0);
    ui.set_transfer_columns(model(transfer_columns()));
    ui.set_search_result_columns(model(search_result_columns()));
    ui.set_server_columns(model(server_columns()));
    ui.set_shared_file_columns(model(shared_file_columns()));
    ui.set_upload_columns(model(upload_columns()));
    ui.set_queued_client_columns(model(upload_columns()));
    ui.set_log_columns(model(log_columns()));
    set_table_sort(ui, TABLE_TRANSFERS, -1, false);
    set_table_sort(ui, TABLE_SEARCH_RESULTS, -1, false);
    set_table_sort(ui, TABLE_SERVERS, -1, false);
    set_table_sort(ui, TABLE_SHARED_FILES, -1, false);
    set_table_sort(ui, TABLE_UPLOADS, -1, false);
    set_table_sort(ui, TABLE_QUEUED_CLIENTS, -1, false);
    set_table_sort(ui, TABLE_LOGS, -1, false);
    ui.window().set_size(PhysicalSize::new(1240, 820));
    ui.window().set_maximized(false);
}

fn save_current_ui_state(ui: &MainWindow) {
    let state = capture_ui_state(ui);
    if let Err(error) = ui_state::save(&state) {
        ui.set_error_message(format!("Failed to save UI layout: {error}").into());
    }
}

fn capture_ui_state(ui: &MainWindow) -> ui_state::UiState {
    let position = ui.window().position();
    let size = ui.window().size();
    let mut state = ui_state::UiState {
        window: Some(ui_state::WindowState {
            x: position.x,
            y: position.y,
            width: size.width,
            height: size.height,
            maximized: ui.window().is_maximized(),
        }),
        selected_tab: Some(ui.get_selected_tab()),
        tables: Default::default(),
    };
    capture_table_state(
        &mut state,
        TABLE_TRANSFERS,
        ui.get_transfer_columns(),
        ui.get_transfer_sort_column(),
        ui.get_transfer_sort_descending(),
    );
    capture_table_state(
        &mut state,
        TABLE_SEARCH_RESULTS,
        ui.get_search_result_columns(),
        ui.get_search_result_sort_column(),
        ui.get_search_result_sort_descending(),
    );
    capture_table_state(
        &mut state,
        TABLE_SERVERS,
        ui.get_server_columns(),
        ui.get_server_sort_column(),
        ui.get_server_sort_descending(),
    );
    capture_table_state(
        &mut state,
        TABLE_SHARED_FILES,
        ui.get_shared_file_columns(),
        ui.get_shared_file_sort_column(),
        ui.get_shared_file_sort_descending(),
    );
    capture_table_state(
        &mut state,
        TABLE_UPLOADS,
        ui.get_upload_columns(),
        ui.get_upload_sort_column(),
        ui.get_upload_sort_descending(),
    );
    capture_table_state(
        &mut state,
        TABLE_QUEUED_CLIENTS,
        ui.get_queued_client_columns(),
        ui.get_queued_client_sort_column(),
        ui.get_queued_client_sort_descending(),
    );
    capture_table_state(
        &mut state,
        TABLE_LOGS,
        ui.get_log_columns(),
        ui.get_log_sort_column(),
        ui.get_log_sort_descending(),
    );
    state
}

fn capture_table_state(
    state: &mut ui_state::UiState,
    table: &str,
    columns: ModelRc<TableColumn>,
    sort_column: i32,
    sort_descending: bool,
) {
    let column_widths = model_items(columns)
        .into_iter()
        .map(|column| column.width)
        .collect();
    state.tables.insert(
        table.to_string(),
        ui_state::TableState {
            sort_column: (sort_column >= 0).then_some(sort_column),
            sort_descending,
            column_widths,
        },
    );
}

fn set_table_sort(ui: &MainWindow, table: &str, column: i32, descending: bool) {
    match table {
        TABLE_TRANSFERS => {
            ui.set_transfer_sort_column(column);
            ui.set_transfer_sort_descending(descending);
        }
        TABLE_SEARCH_RESULTS => {
            ui.set_search_result_sort_column(column);
            ui.set_search_result_sort_descending(descending);
        }
        TABLE_SERVERS => {
            ui.set_server_sort_column(column);
            ui.set_server_sort_descending(descending);
        }
        TABLE_SHARED_FILES => {
            ui.set_shared_file_sort_column(column);
            ui.set_shared_file_sort_descending(descending);
        }
        TABLE_UPLOADS => {
            ui.set_upload_sort_column(column);
            ui.set_upload_sort_descending(descending);
        }
        TABLE_QUEUED_CLIENTS => {
            ui.set_queued_client_sort_column(column);
            ui.set_queued_client_sort_descending(descending);
        }
        TABLE_LOGS => {
            ui.set_log_sort_column(column);
            ui.set_log_sort_descending(descending);
        }
        _ => {}
    }
}
