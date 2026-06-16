//! Log buffer REST handlers (`/logs`, `/logs/operations/clear`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};

use crate::dto::LogsClearRequest;
use crate::envelope::{api_collection, api_error, api_ok, parse_required_json_body};
use crate::log_buffer;

pub(crate) async fn logs() -> impl IntoResponse {
    let entries: Vec<Value> = log_buffer::recent_logs()
        .into_iter()
        .map(|record| {
            json!({
                "timestamp": record.timestamp,
                "level": record.level,
                "message": record.message,
                "debug": record.debug,
            })
        })
        .collect();
    api_collection(entries)
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
