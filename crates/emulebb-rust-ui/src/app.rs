#[path = "api.rs"]
mod api;
#[path = "models.rs"]
mod models;
#[path = "presentation.rs"]
mod presentation;
#[path = "rendering.rs"]
mod rendering;
#[path = "worker.rs"]
mod worker;

use std::cmp::Ordering;
use std::env;
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::ui_state;
use anyhow::{Context, Result};
use api::*;
use clap::Parser;
use emulebb_settings::{
    AppSettings, AppSettingsUpdate, FIELD_DOWNLOAD_LIMIT_KIBPS, FIELD_MAX_CONNECTIONS,
    FIELD_MAX_CONNECTIONS_PER_FIVE_SECONDS, FIELD_MAX_SOURCES_PER_FILE, FIELD_MAX_UPLOAD_SLOTS,
    FIELD_QUEUE_SIZE, FIELD_UPLOAD_CLIENT_DATA_RATE, FIELD_UPLOAD_LIMIT_KIBPS,
    FIELD_UPLOAD_SLOT_ELASTIC_PERCENT, Preferences, PreferencesUpdate, changed_preferences_update,
    parse_u32_preference, preferences_update_is_empty,
};
use models::*;
use presentation::*;
use rendering::*;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use slint::language::{StandardListViewItem, TableColumn};
use slint::{
    CloseRequestResponse, ComponentHandle, Model, ModelRc, PhysicalPosition, PhysicalSize,
    SharedString, VecModel,
};
use worker::*;

slint::include_modules!();

const DEFAULT_POLL_INTERVAL_MS: u64 = 10_000;
const SNAPSHOT_LIMIT: usize = 100;
const SEARCH_RESULT_LIMIT: usize = 100;
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
    PreferencesReload,
    PreferencesApply {
        form: PreferencesForm,
        settings_form: AppSettingsForm,
    },
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
        endpoint: String,
    },
    ServerAdd {
        form: ServerForm,
    },
    ServerUpdate {
        endpoint: String,
        form: ServerForm,
    },
    ServerDelete {
        endpoint: String,
    },
    ServerImport {
        url: String,
    },
    KadAction {
        action: String,
    },
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
    ui.set_settings_status_line("Connect to load settings".into());
    ui.set_pref_upload_limit("".into());
    ui.set_pref_download_limit("".into());
    ui.set_pref_max_connections("".into());
    ui.set_pref_max_connections_per_five("".into());
    ui.set_pref_max_sources("".into());
    ui.set_pref_upload_client_rate("".into());
    ui.set_pref_max_upload_slots("".into());
    ui.set_pref_upload_elastic_percent("".into());
    ui.set_pref_queue_size("".into());
    ui.set_settings_incoming_dir("".into());
    ui.set_settings_p2p_bind_ip("".into());
    ui.set_settings_p2p_bind_interface("".into());
    ui.set_settings_ed2k_listen_port("".into());
    ui.set_settings_ed2k_connect_timeout_secs("".into());
    ui.set_settings_ed2k_reconnect_interval_secs("".into());
    ui.set_settings_kad_listen_port("".into());
    ui.set_settings_kad_bootstrap_min_routing_contacts("".into());
    ui.set_settings_nat_bind_ip("".into());
    ui.set_settings_nat_external_ip_override("".into());
    ui.set_settings_vpn_guard_mode("".into());
    ui.set_settings_vpn_guard_allowed_public_ip_cidrs("".into());
    ui.set_settings_ip_filter_path("".into());
    ui.set_settings_ip_filter_level("".into());
    ui.set_server_address("".into());
    ui.set_server_port("4661".into());
    ui.set_server_name("".into());
    ui.set_server_priority("normal".into());
    ui.set_server_enabled(true);
    ui.set_server_import_url("".into());
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
    ui.set_selected_server_enabled(false);
    ui.set_selected_server_connected(false);
    ui.set_selected_server_connecting(false);
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
    let server_add_tx = tx.clone();
    let server_update_tx = tx.clone();
    let server_delete_tx = tx.clone();
    let server_import_tx = tx.clone();
    let settings_reload_tx = tx.clone();
    let settings_apply_tx = tx.clone();
    let kad_tx = tx.clone();
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
            ui.set_selected_server_enabled(false);
            ui.set_selected_server_connected(false);
            ui.set_selected_server_connecting(false);
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

    ui.on_settings_reload_requested(move || {
        let _ = settings_reload_tx.send(UiCommand::PreferencesReload);
    });

    let settings_apply_ui = ui.as_weak();
    ui.on_settings_apply_requested(move || {
        if let Some(ui) = settings_apply_ui.upgrade() {
            let _ = settings_apply_tx.send(UiCommand::PreferencesApply {
                form: preferences_form(&ui),
                settings_form: app_settings_form(&ui),
            });
        }
    });

    let settings_revert_ui = ui.as_weak();
    let settings_revert_cache = Arc::clone(&cache);
    ui.on_settings_revert_requested(move || {
        if let Some(ui) = settings_revert_ui.upgrade() {
            if !rerender_preferences_from_cache(&ui, &settings_revert_cache) {
                ui.set_settings_status_line("No settings snapshot is loaded".into());
            }
        }
    });

    ui.on_kad_action_requested(move |action| {
        let _ = kad_tx.send(UiCommand::KadAction {
            action: action.to_string(),
        });
    });

    ui.on_transfer_action_requested(move |hash, action| {
        let _ = transfer_tx.send(UiCommand::TransferAction {
            hash: hash.to_string(),
            action: action.to_string(),
        });
    });

    ui.on_server_action_requested(move |action, endpoint| {
        let _ = server_tx.send(UiCommand::ServerAction {
            action: action.to_string(),
            endpoint: endpoint.to_string(),
        });
    });

    let server_add_ui = ui.as_weak();
    ui.on_server_add_requested(move || {
        if let Some(ui) = server_add_ui.upgrade() {
            let _ = server_add_tx.send(UiCommand::ServerAdd {
                form: server_form(&ui),
            });
        }
    });

    let server_update_ui = ui.as_weak();
    ui.on_server_update_requested(move || {
        if let Some(ui) = server_update_ui.upgrade() {
            let _ = server_update_tx.send(UiCommand::ServerUpdate {
                endpoint: ui.get_selected_id().to_string(),
                form: server_form(&ui),
            });
        }
    });

    let server_delete_ui = ui.as_weak();
    ui.on_server_delete_requested(move || {
        if let Some(ui) = server_delete_ui.upgrade() {
            let _ = server_delete_tx.send(UiCommand::ServerDelete {
                endpoint: ui.get_selected_id().to_string(),
            });
        }
    });

    let server_import_ui = ui.as_weak();
    ui.on_server_import_requested(move || {
        if let Some(ui) = server_import_ui.upgrade() {
            let _ = server_import_tx.send(UiCommand::ServerImport {
                url: ui.get_server_import_url().to_string(),
            });
        }
    });

    ui.run().context("Slint event loop failed")
}

fn preferences_form(ui: &MainWindow) -> PreferencesForm {
    PreferencesForm {
        upload_limit_ki_bps: ui.get_pref_upload_limit().to_string(),
        download_limit_ki_bps: ui.get_pref_download_limit().to_string(),
        max_connections: ui.get_pref_max_connections().to_string(),
        max_connections_per_five_seconds: ui.get_pref_max_connections_per_five().to_string(),
        max_sources_per_file: ui.get_pref_max_sources().to_string(),
        upload_client_data_rate: ui.get_pref_upload_client_rate().to_string(),
        max_upload_slots: ui.get_pref_max_upload_slots().to_string(),
        upload_slot_elastic_percent: ui.get_pref_upload_elastic_percent().to_string(),
        queue_size: ui.get_pref_queue_size().to_string(),
        auto_connect: ui.get_pref_auto_connect(),
        reconnect: ui.get_pref_reconnect(),
        credit_system: ui.get_pref_credit_system(),
        safe_server_connect: ui.get_pref_safe_server_connect(),
        add_servers_from_server: ui.get_pref_add_servers_from_server(),
        network_kademlia: ui.get_pref_network_kademlia(),
        network_ed2k: ui.get_pref_network_ed2k(),
    }
}

fn app_settings_form(ui: &MainWindow) -> AppSettingsForm {
    AppSettingsForm {
        incoming_dir: ui.get_settings_incoming_dir().to_string(),
        p2p_bind_ip: ui.get_settings_p2p_bind_ip().to_string(),
        p2p_bind_interface: ui.get_settings_p2p_bind_interface().to_string(),
        ed2k_listen_port: ui.get_settings_ed2k_listen_port().to_string(),
        ed2k_obfuscation_enabled: ui.get_settings_ed2k_obfuscation_enabled(),
        ed2k_connect_timeout_secs: ui.get_settings_ed2k_connect_timeout_secs().to_string(),
        ed2k_reconnect_interval_secs: ui.get_settings_ed2k_reconnect_interval_secs().to_string(),
        ed2k_enable_udp_reask: ui.get_settings_ed2k_enable_udp_reask(),
        ed2k_publish_emule_rust_identity: ui.get_settings_ed2k_publish_emule_rust_identity(),
        kad_listen_port: ui.get_settings_kad_listen_port().to_string(),
        kad_bootstrap_min_routing_contacts: ui
            .get_settings_kad_bootstrap_min_routing_contacts()
            .to_string(),
        kad_publish_shared_files_enabled: ui.get_settings_kad_publish_shared_files_enabled(),
        kad_routing_maintenance_enabled: ui.get_settings_kad_routing_maintenance_enabled(),
        nat_enabled: ui.get_settings_nat_enabled(),
        nat_require_initial_mapping: ui.get_settings_nat_require_initial_mapping(),
        nat_bind_ip: ui.get_settings_nat_bind_ip().to_string(),
        nat_external_ip_override: ui.get_settings_nat_external_ip_override().to_string(),
        vpn_guard_enabled: ui.get_settings_vpn_guard_enabled(),
        vpn_guard_mode: ui.get_settings_vpn_guard_mode().to_string(),
        vpn_guard_allowed_public_ip_cidrs: ui
            .get_settings_vpn_guard_allowed_public_ip_cidrs()
            .to_string(),
        ip_filter_enabled: ui.get_settings_ip_filter_enabled(),
        ip_filter_path: ui.get_settings_ip_filter_path().to_string(),
        ip_filter_level: ui.get_settings_ip_filter_level().to_string(),
    }
}

fn server_form(ui: &MainWindow) -> ServerForm {
    ServerForm {
        address: ui.get_server_address().to_string(),
        port: ui.get_server_port().to_string(),
        name: ui.get_server_name().to_string(),
        priority: ui.get_server_priority().to_string(),
        static_server: ui.get_server_static(),
        enabled: ui.get_server_enabled(),
        connect: ui.get_server_connect_after_add(),
    }
}

fn default_base_url() -> String {
    match env::var("X_LOCAL_IP") {
        Ok(ip) if !ip.trim().is_empty() => format!("http://{}:4711/api/v1", ip.trim()),
        _ => "http://192.0.2.1:4711/api/v1".to_string(),
    }
}

fn apply_saved_state(ui: &MainWindow, state: &ui_state::UiState) {
    ui.set_selected_tab(state.selected_tab.unwrap_or(0).clamp(0, 9));
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
    }
    ui.window().set_maximized(true);
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
    ui.window().set_maximized(true);
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
