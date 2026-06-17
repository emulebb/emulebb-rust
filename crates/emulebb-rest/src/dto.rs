//! REST request/response data-transfer objects.
//!
//! These serde structs define the wire shapes the REST layer parses from
//! request bodies/query strings and serializes into responses, plus the small
//! `page()` projections onto the shared `PageQuery`. Extracted verbatim from
//! `lib.rs` during the maintainability restructuring; behavior is unchanged.

use emulebb_core::SearchResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BulkOperationResult {
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SearchResultDownloadResult {
    pub(crate) ok: bool,
    pub(crate) search_id: String,
    pub(crate) hash: String,
}

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
    pub(crate) shared_by_rule: bool,
    pub(crate) ed2k_link: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SharedFileCreateRequest {
    pub(crate) path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SharedFileCreateResult {
    pub(crate) ok: bool,
    pub(crate) path: String,
    pub(crate) already_shared: bool,
    pub(crate) queued: bool,
    pub(crate) file: SharedFileResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Ed2kLinkResult {
    pub(crate) hash: String,
    pub(crate) link: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SharedFileRemoveResult {
    pub(crate) ok: bool,
    pub(crate) deleted_files: bool,
    pub(crate) path: String,
    pub(crate) hash: String,
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

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PageQuery {
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TransfersQuery {
    pub(crate) state: Option<String>,
    pub(crate) category_id: Option<u32>,
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UploadQueueQuery {
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) include_score_breakdown: Option<bool>,
}

impl TransfersQuery {
    pub(crate) fn page(&self) -> PageQuery {
        PageQuery {
            offset: self.offset,
            limit: self.limit,
        }
    }
}

impl UploadQueueQuery {
    pub(crate) fn page(&self) -> PageQuery {
        PageQuery {
            offset: self.offset,
            limit: self.limit,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SearchResultsQuery {
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) include_evidence: Option<bool>,
    #[serde(default)]
    pub(crate) exact_total: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SearchResultsPage {
    pub(crate) id: String,
    pub(crate) query: String,
    pub(crate) method: String,
    #[serde(rename = "type")]
    pub(crate) file_type: String,
    pub(crate) status: String,
    pub(crate) total: usize,
    pub(crate) offset: usize,
    pub(crate) limit: usize,
    pub(crate) results: Vec<SearchResult>,
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
pub(crate) struct DiagnosticDumpRequest {
    pub(crate) confirm_dump: bool,
    #[serde(default)]
    pub(crate) full_memory: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiagnosticCrashTestRequest {
    pub(crate) confirm_crash: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ClearCompletedTransfersRequest {
    pub(crate) confirm_clear_completed: bool,
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
