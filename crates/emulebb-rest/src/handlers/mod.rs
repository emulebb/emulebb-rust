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
pub(crate) mod kad;
pub(crate) mod logs;
pub(crate) mod uploads;

pub(crate) use app::{
    app, capture_diagnostic_dump, preferences, shutdown_app, snapshot, stats, status,
    trigger_diagnostic_crash_test, update_preferences,
};
pub(crate) use kad::{kad, kad_bootstrap, kad_import_nodes_url, kad_recheck_firewall, kad_start, kad_stop};
pub(crate) use logs::{clear_logs, logs};
pub(crate) use uploads::{
    upload, upload_add_friend, upload_ban, upload_queue, upload_queue_client, upload_release_slot,
    upload_remove, upload_remove_friend, upload_unban, uploads, without_score_breakdown,
};
