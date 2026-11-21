//! Upload and upload-queue REST handlers (`/uploads`, `/upload-queue`).

use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::handlers::prelude::*;

pub(crate) async fn uploads(State(state): State<RestState>, RawQuery(raw): RawQuery) -> Response {
    upload_page(state, raw, false).await
}

pub(crate) async fn upload_queue(
    State(state): State<RestState>,
    RawQuery(raw): RawQuery,
) -> Response {
    upload_page(state, raw, true).await
}

fn upload_read_error(error: anyhow::Error) -> Response {
    use emulebb_core::Ed2kUploadQueuePageError;
    match error.downcast_ref::<Ed2kUploadQueuePageError>() {
        Some(Ed2kUploadQueuePageError::CursorExpired) => api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "upload cursor expired; refresh from the first page",
        )
        .into_response(),
        Some(Ed2kUploadQueuePageError::RowTooLarge) => api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PERSISTENCE_TOO_LARGE",
            "upload row exceeds read allowance",
        )
        .into_response(),
        Some(Ed2kUploadQueuePageError::InvalidLimit) => out_of_range_response("limit", 1, 200),
        None => super::persistence::persistence_error(error),
    }
}

async fn upload_page(state: RestState, raw: Option<String>, waiting: bool) -> Response {
    let query = match parse_optional_query::<UploadPageQuery>(raw.as_deref()) {
        Ok(query) => query,
        Err(error) => return *error,
    };
    let limit = query.limit.unwrap_or(100);
    if !(1..=200).contains(&limit) {
        return out_of_range_response("limit", 1, 200);
    }
    let scope = if waiting { "upload-queue" } else { "uploads" };
    let after = match query
        .cursor
        .as_deref()
        .map(|value| super::resource::decode_cursor(value, scope))
        .transpose()
    {
        Ok(Some(value)) => match uuid::Uuid::try_parse(&value)
            .ok()
            .filter(|id| id.to_string() == value)
        {
            Some(id) => Some(id),
            None => return super::resource::invalid("cursor is invalid for this collection"),
        },
        Ok(None) => None,
        Err(error) => return *error,
    };
    let result = if waiting {
        state
            .core
            .upload_queue_page(after, limit, query.count_total.unwrap_or(false))
            .await
    } else {
        state
            .core
            .active_upload_page(after, limit, query.count_total.unwrap_or(false))
            .await
    };
    let page = match result {
        Ok(page) => page,
        Err(error) => return upload_read_error(error),
    };
    let next = page
        .next_after
        .map(|id| super::resource::encode_cursor(scope, &id.to_string()));
    super::resource::retained_json(
        &page,
        &super::resource::page_document(&page.uploads, next, page.has_more, page.total),
    )
}

pub(crate) async fn upload(State(state): State<RestState>, Path(id): Path<String>) -> Response {
    upload_by_id(state, id, false).await
}

pub(crate) async fn upload_queue_client(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Response {
    upload_by_id(state, id, true).await
}

pub(crate) async fn upload_by_id(state: RestState, id: String, waiting_queue: bool) -> Response {
    match state.core.upload(&id, waiting_queue).await {
        Ok(Some(upload)) => {
            super::resource::retained_json(&upload, &super::resource::item_document(&*upload))
        }
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            if waiting_queue {
                "upload queue client not found"
            } else {
                "active upload client not found"
            },
        )
        .into_response(),
        Err(error) => upload_read_error(error),
    }
}
pub(crate) async fn upload_remove(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.core.remove_upload_client(&id).await {
        Ok(Some(removed)) => api_ok(json!({"ok": true, "removed": removed})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn upload_release_slot(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.core.release_upload_slot(&id).await {
        Ok(Some(())) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn upload_add_friend(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.core.add_upload_client_friend(&id).await {
        Ok(Some(friend)) => api_ok(friend).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn upload_remove_friend(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.core.remove_upload_client_friend(&id).await {
        Ok(Some(_friend)) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "friend not found").into_response()
        }
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn upload_ban(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.core.ban_upload_client(&id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn upload_unban(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.core.unban_upload_client(&id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn upload_summary_serializes_current_fields_and_full_management_rank() {
        let upload = emulebb_core::Upload {
            id: "12345678-1234-4234-8234-123456789abc".into(),
            user_hash: None,
            client_software: None,
            upload_state: "queued".into(),
            upload_rate_bytes_per_sec: 8192,
            session_uploaded_bytes: 1024,
            wait_time_seconds: 123,
            upload_duration_seconds: None,
            address: "192.0.2.10".into(),
            port: 4662,
            low_id: None,
            friend_slot: false,
            connected: false,
            requested_file_hash: "01".repeat(16),
            requested_file_name: None,
            requested_file_size_bytes: None,
            file_parts_available: None,
            file_parts_total: None,
            score_breakdown: None,
            queue_rank: Some(65536),
        };
        let value = serde_json::to_value(upload).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "id":"12345678-1234-4234-8234-123456789abc","userHash":null,"clientSoftware":null,
                "uploadState":"queued","uploadRateBytesPerSec":8192,"sessionUploadedBytes":1024,
                "waitTimeSeconds":123,"uploadDurationSeconds":null,"address":"192.0.2.10","port":4662,
                "lowId":null,"friendSlot":false,"connected":false,"requestedFileHash":"01".repeat(16),
                "requestedFileName":null,"requestedFileSizeBytes":null,"filePartsAvailable":null,"filePartsTotal":null,
                "queueRank":65536
            })
        );
    }
}
