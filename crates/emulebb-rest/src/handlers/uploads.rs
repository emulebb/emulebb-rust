//! Upload and upload-queue REST handlers (`/uploads`, `/upload-queue`).

use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::json;

use emulebb_core::Upload;

use crate::handlers::prelude::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadQueueEntry {
    #[serde(flatten)]
    upload: Upload,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_rank: Option<u16>,
}

fn upload_queue_entry(upload: Upload) -> UploadQueueEntry {
    UploadQueueEntry {
        queue_rank: upload.queue_rank,
        upload,
    }
}

/// Compact lists fetch score evidence through the detail resource.
pub(crate) fn without_score_breakdown(mut uploads: Vec<Upload>) -> Vec<Upload> {
    for upload in &mut uploads {
        upload.score_breakdown = None;
    }
    uploads
}

pub(crate) async fn uploads(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(without_score_breakdown(state.core.uploads().await))
}

pub(crate) async fn upload(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    upload_by_id(state, id, false).await
}

pub(crate) async fn upload_queue(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<UploadQueueQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let limit = query.limit.unwrap_or(100);
    if !(1..=200).contains(&limit) {
        return out_of_range_response("limit", 1, 200);
    }
    let after = match query
        .cursor
        .as_deref()
        .map(|value| super::resource::decode_cursor(value, "upload-queue"))
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
    let page = match state
        .core
        .upload_queue_page(after, limit, query.count_total.unwrap_or(false))
        .await
    {
        Ok(page) => page,
        Err(error)
            if error.downcast_ref::<emulebb_core::Ed2kUploadQueuePageError>()
                == Some(&emulebb_core::Ed2kUploadQueuePageError::CursorExpired) =>
        {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "upload queue cursor expired; refresh from the first page",
            )
            .into_response();
        }
        Err(error) => return super::persistence::persistence_error(error),
    };
    let next = page
        .next_after
        .map(|id| super::resource::encode_cursor("upload-queue", &id.to_string()));
    let more = page.has_more;
    let total = page.total;
    let encoded = page
        .try_project(emulebb_core::UPLOAD_QUEUE_PAGE_BYTES + 4096, |page| {
            let rows = page
                .uploads
                .into_iter()
                .map(upload_queue_entry)
                .collect::<Vec<_>>();
            Ok(super::resource::page_document(rows, next, more, total))
        })
        .and_then(|page| page.serialize_json());
    match encoded {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            axum::body::Body::from(axum::body::Bytes::from_owner(bytes)),
        )
            .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn upload_queue_client(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    upload_by_id(state, id, true).await
}

pub(crate) async fn upload_by_id(state: RestState, id: String, waiting_queue: bool) -> Response {
    match state.core.upload(&id, waiting_queue).await {
        Some(upload) if waiting_queue => api_ok(upload_queue_entry(upload)).into_response(),
        Some(upload) => api_ok(upload).into_response(),
        None if waiting_queue => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload queue client not found",
        )
        .into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "active upload client not found",
        )
        .into_response(),
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
    use emulebb_core::Upload;

    use super::{upload_queue_entry, without_score_breakdown};

    #[test]
    fn without_score_breakdown_strips_the_diagnostics() {
        let breakdown = emulebb_core::UploadScoreBreakdown {
            availability: "available".to_string(),
            base_score: 100,
            effective_score: 100,
            core_score: 100.0,
            effective_score_float: 100.0,
            credit_ratio: 1.0,
            file_priority: 1,
            low_ratio_applied: false,
            low_ratio_bonus: 0,
            low_id_penalty_applied: false,
            low_id_divisor: 1,
            old_client_penalty_applied: false,
            cooldown_remaining_ms: 0,
        };
        let upload = Upload {
            id: "12345678-1234-4234-8234-123456789abc".to_string(),
            user_name: "peer".to_string(),
            user_hash: None,
            client_software: "eMule".to_string(),
            client_mod: String::new(),
            upload_state: "uploading".to_string(),
            upload_speed_ki_bps: 8.0,
            uploaded_bytes: 1024,
            queue_session_uploaded: 1024,
            payload_buffered: 0,
            wait_time_ms: 0,
            wait_started_tick: 0,
            score: 100,
            address: "192.0.2.10".to_string(),
            port: 4662,
            server_ip: String::new(),
            server_port: 0,
            low_id: false,
            friend_slot: false,
            uploading: true,
            waiting_queue: false,
            requested_file_hash: None,
            requested_file_name: None,
            requested_file_size_bytes: None,
            requested_parts_obtained: 0,
            requested_parts_total: 0,
            requested_parts_progress_text: String::new(),
            score_breakdown: Some(breakdown),
            queue_rank: None,
        };

        // With the breakdown kept, the JSON carries scoreBreakdown.
        let kept = serde_json::to_value(upload.clone()).unwrap();
        assert!(kept.get("scoreBreakdown").is_some());

        // The list helper strips it (master omits it unless opted in).
        let stripped = without_score_breakdown(vec![upload]);
        assert!(stripped[0].score_breakdown.is_none());
        let value = serde_json::to_value(&stripped[0]).unwrap();
        assert!(value.get("scoreBreakdown").is_none());
    }

    #[test]
    fn upload_queue_entry_serializes_wait_rank() {
        let upload = Upload {
            id: "12345678-1234-4234-8234-123456789abc".to_string(),
            user_name: "peer".to_string(),
            user_hash: None,
            client_software: "eMule".to_string(),
            client_mod: String::new(),
            upload_state: "queued".to_string(),
            upload_speed_ki_bps: 0.0,
            uploaded_bytes: 0,
            queue_session_uploaded: 0,
            payload_buffered: 0,
            wait_time_ms: 123,
            wait_started_tick: 0,
            score: 100,
            address: "192.0.2.10".to_string(),
            port: 4662,
            server_ip: String::new(),
            server_port: 0,
            low_id: false,
            friend_slot: false,
            uploading: false,
            waiting_queue: true,
            requested_file_hash: None,
            requested_file_name: None,
            requested_file_size_bytes: None,
            requested_parts_obtained: 0,
            requested_parts_total: 0,
            requested_parts_progress_text: String::new(),
            score_breakdown: None,
            queue_rank: Some(7),
        };

        let plain = serde_json::to_value(&upload).unwrap();
        assert!(plain.get("queueRank").is_none());
        let queued = serde_json::to_value(upload_queue_entry(upload)).unwrap();
        assert_eq!(queued["queueRank"], 7);
    }
}
