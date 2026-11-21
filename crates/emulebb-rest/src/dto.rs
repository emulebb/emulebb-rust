//! REST request/response data-transfer objects.
//!
//! These serde structs define the wire shapes the REST layer parses from
//! request bodies/query strings and serializes into responses, plus the small
//! `page()` projections onto the shared `PageQuery`. Extracted verbatim from
//! `lib.rs` during the maintainability restructuring; behavior is unchanged.

use emulebb_core::SharedFilePublicationStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SharedFileResponse {
    pub(crate) hash: String,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) directory: String,
    pub(crate) size_bytes: u64,
    pub(crate) priority: String,
    pub(crate) auto_upload_priority: bool,
    pub(crate) requests: u64,
    pub(crate) accepted_requests: u64,
    pub(crate) transferred_bytes: u64,
    pub(crate) all_time_requests: u64,
    pub(crate) all_time_accepts: u64,
    pub(crate) all_time_transferred: u64,
    pub(crate) part_count: u32,
    pub(crate) part_file: bool,
    pub(crate) complete: bool,
    pub(crate) comment: String,
    pub(crate) rating: u8,
    pub(crate) has_comment: bool,
    pub(crate) user_rating: u8,
    pub(crate) published_ed2k: bool,
    pub(crate) publication: Option<SharedFilePublicationStatus>,
    pub(crate) shared_by_rule: bool,
    pub(crate) ed2k_link: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Ed2kLinkResult {
    pub(crate) hash: String,
    pub(crate) link: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfirmQuery {
    pub(crate) confirm: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SnapshotQuery {
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SharedFileIgnorePatternQuery {
    pub(crate) pattern: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PageQuery {
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SharedFilesQuery {
    pub(crate) limit: Option<usize>,
    pub(crate) cursor: Option<String>,
    pub(crate) q: Option<String>,
    pub(crate) priority: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UploadQueueQuery {
    pub(crate) limit: Option<usize>,
    pub(crate) cursor: Option<String>,
    pub(crate) count_total: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LogsClearRequest {
    pub(crate) confirm_clear_logs: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LogsQuery {
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShutdownRequest {
    pub(crate) confirm_shutdown: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiagnosticBundleCaptureRequest {
    pub(crate) confirm_capture: bool,
    pub(crate) max_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiagnosticCrashTestRequest {
    pub(crate) confirm_crash: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UrlImportRequest {
    pub(crate) url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KadBootstrapRequest {
    pub(crate) address: String,
    pub(crate) port: u16,
}
