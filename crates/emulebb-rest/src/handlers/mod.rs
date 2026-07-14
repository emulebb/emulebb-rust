//! Axum route handlers, grouped by REST domain.
//!
//! Each submodule holds the `async fn` handlers for one route family. They were
//! extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged. The handler functions are re-exported here so the
//! router wiring in `lib.rs` references them unqualified.

/// Items shared by every handler submodule: the shared state plus the crate's
/// dto/envelope/responses helper families (glob re-exports, so unused entries do
/// not warn). Submodules `use crate::handlers::prelude::*;` and add the exact
/// axum/serde_json imports and extra `emulebb_core` types each domain needs.
pub(crate) mod prelude {
    pub(crate) use crate::RestState;
    pub(crate) use crate::dto::*;
    pub(crate) use crate::envelope::*;
    pub(crate) use crate::responses::*;
}

pub(crate) mod app;
pub(crate) mod categories;
pub(crate) mod friends;
pub(crate) mod kad;
pub(crate) mod logs;
pub(crate) mod searches;
pub(crate) mod servers;
pub(crate) mod shared_files;
pub(crate) mod transfers;
pub(crate) mod uploads;

pub(crate) use app::{
    app, capabilities, capture_diagnostic_dump, preferences, preferences_schema, settings,
    shutdown_app, snapshot, stats, status, trigger_diagnostic_crash_test, update_preferences,
    update_settings,
};
pub(crate) use categories::{
    categories, category, create_category, delete_category, update_category,
};
pub(crate) use friends::{create_friend, delete_friend, friends};
pub(crate) use kad::{
    kad, kad_bootstrap, kad_import_nodes_url, kad_recheck_firewall, kad_start, kad_stop,
};
pub(crate) use logs::{clear_logs, logs};
pub(crate) use searches::{
    create_search, delete_search, delete_searches, download_search_result, search, searches,
};
pub(crate) use servers::{
    connect_server, create_server, delete_server, server, servers, servers_connect,
    servers_disconnect, servers_import_met_url, update_server,
};
pub(crate) use shared_files::{
    create_shared_file, delete_shared_file, delete_shared_file_payload, reload_shared_directories,
    shared_directories, shared_file, shared_file_comments, shared_file_ed2k_link, shared_files,
    update_shared_directories, update_shared_file,
};
pub(crate) use transfers::{
    clear_completed_transfers, create_transfer, transfer, transfer_delete, transfer_delete_files,
    transfer_details, transfer_pause, transfer_recheck, transfer_resume, transfer_source,
    transfer_source_add_friend, transfer_source_ban, transfer_source_browse,
    transfer_source_release_slot, transfer_source_remove, transfer_source_remove_friend,
    transfer_source_unban, transfer_sources, transfer_stop, transfers, update_transfer,
};
pub(crate) use uploads::{
    upload, upload_add_friend, upload_ban, upload_queue, upload_queue_client, upload_release_slot,
    upload_remove, upload_remove_friend, upload_unban, uploads, without_score_breakdown,
};
