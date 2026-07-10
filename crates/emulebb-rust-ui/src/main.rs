mod ui_state;

use std::cmp::Ordering;
use std::env;
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
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

fn main() -> Result<()> {
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
                column.width = (*width).into();
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

#[derive(Debug, Clone, Copy)]
struct SortSpec {
    column: i32,
    descending: bool,
}

fn sort_spec(column: i32, descending: bool) -> Option<SortSpec> {
    (column >= 0).then_some(SortSpec { column, descending })
}

fn sorted_transfers(items: &[TransferDto], spec: Option<SortSpec>) -> Vec<TransferDto> {
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

fn sorted_search_results(
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

fn sorted_uploads(items: &[UploadDto], spec: Option<SortSpec>) -> Vec<UploadDto> {
    let mut items = items.to_vec();
    if let Some(spec) = spec {
        items.sort_by(|a, b| {
            sort_order(
                match spec.column {
                    0 => cmp_text(
                        display_or(&a.user_name, &a.client_id),
                        display_or(&b.user_name, &b.client_id),
                    ),
                    1 => cmp_text(
                        a.requested_file_name.as_deref().unwrap_or("-"),
                        b.requested_file_name.as_deref().unwrap_or("-"),
                    ),
                    2 => cmp_text(&a.upload_state, &b.upload_state),
                    3 => cmp_f64(a.upload_speed_ki_bps, b.upload_speed_ki_bps),
                    4 => a.uploaded_bytes.cmp(&b.uploaded_bytes),
                    5 => cmp_f64(
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

fn sorted_servers(items: &[ServerDto], spec: Option<SortSpec>) -> Vec<ServerDto> {
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

fn sorted_shared_files(items: &[SharedFileDto], spec: Option<SortSpec>) -> Vec<SharedFileDto> {
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

fn sorted_logs(items: &[LogEntryDto], spec: Option<SortSpec>) -> Vec<LogEntryDto> {
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

fn transfer_progress(item: &TransferDto) -> f64 {
    item.progress
        .unwrap_or_else(|| progress_ratio(item.completed_bytes.unwrap_or(0), item.size_bytes))
}

fn server_endpoint(item: &ServerDto) -> String {
    format!("{}:{}", item.address, item.port)
}

fn server_status(item: &ServerDto) -> &'static str {
    if item.connected {
        "connected"
    } else if item.connecting {
        "connecting"
    } else {
        "known"
    }
}

fn cmp_text(a: &str, b: &str) -> Ordering {
    a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase())
}

fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

fn sort_order(ordering: Ordering, descending: bool) -> Ordering {
    if descending {
        ordering.reverse()
    } else {
        ordering
    }
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

fn search_result_items_for(search: &SearchDto, items: &[SearchResultDto]) -> Vec<SearchResultItem> {
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

fn upload_items(items: &[UploadDto]) -> Vec<UploadItem> {
    items
        .iter()
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

fn search_result_columns() -> Vec<TableColumn> {
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

fn search_result_table_rows(items: &[SearchResultItem]) -> Vec<Vec<StandardListViewItem>> {
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

fn search_status_line(search: &SearchDto) -> String {
    let total = search.total.unwrap_or(search.items.len() as u64);
    let reason = search
        .status_reason
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" | {value}"))
        .unwrap_or_default();
    format!(
        "{} | {} | {} results{}",
        search.query,
        display_or(&search.status, "unknown"),
        total,
        reason
    )
}

fn normalize_search_method(method: &str) -> String {
    match method.trim().to_ascii_lowercase().as_str() {
        "" => "automatic".to_string(),
        "auto" => "automatic".to_string(),
        "automatic" | "server" | "global" | "kad" => method.trim().to_ascii_lowercase(),
        _ => method.trim().to_ascii_lowercase(),
    }
}

fn normalize_search_type(file_type: &str) -> String {
    file_type.trim().to_ascii_lowercase()
}

fn latest_search_id(items: &[SearchSessionDto]) -> Option<String> {
    items
        .iter()
        .filter(|item| !item.id.trim().is_empty())
        .max_by_key(|item| item.id.parse::<u64>().unwrap_or(0))
        .map(|item| item.id.clone())
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
