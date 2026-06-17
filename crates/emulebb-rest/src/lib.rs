use std::sync::Arc;

use emulebb_core::EmulebbCore;
use tokio::sync::watch;

mod log_buffer;
pub use log_buffer::record_log;

mod dto;
mod envelope;
mod handlers;
mod responses;
mod route_metadata;
mod routes;
pub use routes::{router, router_with_shutdown};

#[cfg(test)]
#[path = "tests/app.rs"]
mod app_tests;
#[cfg(test)]
#[path = "tests/logs.rs"]
mod logs_tests;
#[cfg(test)]
#[path = "tests/servers.rs"]
mod server_tests;

// Re-exported at the crate root so the sibling modules can reach the shared
// dto types and the upload list helper via `crate::...` paths.
pub(crate) use dto::*;
pub(crate) use handlers::without_score_breakdown;

#[derive(Debug, Clone)]
pub struct RestConfig {
    pub api_key: String,
}

#[derive(Debug, Clone)]
pub struct RestState {
    core: Arc<EmulebbCore>,
    api_key: Arc<String>,
    shutdown: Option<watch::Sender<bool>>,
}
#[cfg(test)]
#[path = "tests/support.rs"]
mod rest_test_support;
#[cfg(test)]
#[path = "tests/route_app.rs"]
mod route_app_tests;
#[cfg(test)]
#[path = "tests/route_entities.rs"]
mod route_entities_tests;
#[cfg(test)]
#[path = "tests/route_transfers.rs"]
mod route_transfers_tests;
#[cfg(test)]
#[path = "tests/route_validation.rs"]
mod route_validation_tests;
