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
pub(crate) mod downloads;
pub(crate) mod friends;
pub(crate) mod ip_filter;
pub(crate) mod kad;
mod library_sharing;
mod library_tags;
pub(crate) use library_sharing::set_library_sharing;
pub(crate) mod logs;
pub(crate) mod persistence;
mod resource;
pub(crate) mod searches;
pub(crate) use library_tags::{
    add_library_file_tags, create_library_tag, delete_library_tag, library_file_tags, library_tag,
    library_tags, remove_library_file_tags,
};
pub(crate) mod servers;
pub(crate) mod shared_files;
pub(crate) mod uploads;

pub(crate) use app::{
    app, capabilities, capture_diagnostic_bundle, diagnostics, event_status, events, nat, network,
    probe_vpn_guard, refresh_nat, settings, settings_surface, shutdown_app, snapshot, stats,
    status, trigger_diagnostic_crash_test, update_settings, vpn_guard,
};
pub(crate) use categories::{
    categories, category, create_category, delete_category, update_category,
};
pub(crate) use downloads::{
    create_download, download, download_comments, download_parts, download_remove, download_source,
    download_source_add_friend, download_source_ban, download_source_browse,
    download_source_remove, download_source_remove_friend, download_source_unban, download_sources,
    download_start, download_stop, download_verify, downloads, update_download,
};
pub(crate) use friends::{create_friend, delete_friend, friends};
pub(crate) use ip_filter::{ip_filter, reload_ip_filter};
pub(crate) use kad::{
    kad, kad_bootstrap, kad_import_nodes_url, kad_nodes, kad_recheck_firewall, kad_start, kad_stop,
};
pub(crate) use logs::{clear_logs, logs};
pub(crate) use searches::{
    create_search, delete_search, delete_searches, download_search_result, search, search_result,
    search_result_observations, search_results, searches, stop_search,
};
pub(crate) use servers::{
    connect_server, create_server, delete_server, server, servers, servers_connect,
    servers_disconnect, servers_import_met_url, update_server,
};
pub(crate) use shared_files::{
    add_shared_directory_root, add_shared_file_ignore_pattern, reload_shared_directories,
    remove_shared_directory_root, remove_shared_file_ignore_pattern, shared_directories,
    shared_file, shared_file_comments, shared_file_ed2k_link, shared_file_ignores, shared_files,
    update_shared_directories, update_shared_file, update_shared_file_ignore_rule,
};
pub(crate) use uploads::{
    upload, upload_add_friend, upload_ban, upload_queue, upload_queue_client, upload_release_slot,
    upload_remove, upload_remove_friend, upload_unban, uploads, without_score_breakdown,
};
