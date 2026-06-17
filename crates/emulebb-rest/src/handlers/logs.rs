//! Log buffer REST handlers (`/logs`, `/logs/operations/clear`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{body::Bytes, extract::RawQuery, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};

use crate::handlers::prelude::*;
use crate::log_buffer;

pub(crate) async fn logs(RawQuery(raw_query): RawQuery) -> impl IntoResponse {
    let query = match parse_optional_query::<LogsQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let limit = query.limit.unwrap_or(200).max(1);
    let entries: Vec<Value> = log_buffer::recent_logs()
        .into_iter()
        .take(limit)
        .map(|record| {
            json!({
                "timestamp": record.timestamp,
                "level": record.level,
                "message": record.message,
                "debug": record.debug,
            })
        })
        .collect();
    api_collection(entries).into_response()
}

pub(crate) async fn clear_logs(body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<LogsClearRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_clear_logs {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "confirmClearLogs must be true",
        )
        .into_response();
    }
    log_buffer::clear_logs();
    api_ok(json!({ "ok": true })).into_response()
}
