use super::*;

pub(super) fn publish_snapshot(weak: &slint::Weak<MainWindow>, snapshot: Snapshot) {
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

pub(super) fn publish_search(weak: &slint::Weak<MainWindow>, search: SearchDto) {
    let update = move |ui: MainWindow| {
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

pub(super) fn publish_empty_search(weak: &slint::Weak<MainWindow>, status: &str) {
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

pub(super) fn publish_poll_error(
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

pub(super) fn publish_error(weak: &slint::Weak<MainWindow>, message: String, disconnected: bool) {
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

pub(super) fn publish_refreshing(weak: &slint::Weak<MainWindow>, refreshing: bool) {
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_is_refreshing(refreshing);
        }
    });
}

pub(super) fn store_snapshot(cache: &Arc<Mutex<DataCache>>, snapshot: Snapshot) {
    if let Ok(mut cache) = cache.lock() {
        cache.snapshot = Some(snapshot);
    }
}

pub(super) fn store_search(cache: &Arc<Mutex<DataCache>>, search: Option<SearchDto>) {
    if let Ok(mut cache) = cache.lock() {
        cache.search = search;
    }
}

pub(super) fn rerender_from_cache(ui: &MainWindow, cache: &Arc<Mutex<DataCache>>) {
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

pub(super) fn render_snapshot_tables(ui: &MainWindow, snapshot: &Snapshot) {
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

pub(super) fn render_search_table(ui: &MainWindow, search: &SearchDto) {
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

pub(super) fn model_items<T: Clone + 'static>(items: ModelRc<T>) -> Vec<T> {
    (0..items.row_count())
        .filter_map(|index| items.row_data(index))
        .collect()
}
