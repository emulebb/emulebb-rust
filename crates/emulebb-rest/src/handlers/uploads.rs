//! Upload and upload-queue REST handlers (`/uploads`, `/upload-queue`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use emulebb_core::Upload;

use crate::handlers::prelude::*;

/// Drops `scoreBreakdown` from every upload so list endpoints stay parity-exact
/// with master, which omits the breakdown unless the caller opts in.
pub(crate) fn without_score_breakdown(mut uploads: Vec<Upload>) -> Vec<Upload> {
    for upload in &mut uploads {
        upload.score_breakdown = None;
    }
    uploads
}

pub(crate) async fn uploads(State(state): State<RestState>) -> impl IntoResponse {
    // Master's /uploads list never attaches scoreBreakdown.
    api_collection(without_score_breakdown(state.core.uploads().await))
}

pub(crate) async fn upload(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    upload_by_client_id(state, client_id, false).await
}

pub(crate) async fn upload_queue(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<UploadQueueQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    // Master gates scoreBreakdown on the includeScoreBreakdown query (default
    // off) for the /upload-queue list.
    let include_score_breakdown = query.include_score_breakdown.unwrap_or(false);
    let items = state.core.upload_queue().await;
    let items = if include_score_breakdown {
        items
    } else {
        without_score_breakdown(items)
    };
    api_collection_page(items, query.page()).into_response()
}

pub(crate) async fn upload_queue_client(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    upload_by_client_id(state, client_id, true).await
}

pub(crate) async fn upload_by_client_id(
    state: RestState,
    client_id: String,
    waiting_queue: bool,
) -> Response {
    match state.core.upload(&client_id, waiting_queue).await {
        Some(upload) => api_ok(upload).into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload queue client not found",
        )
        .into_response(),
    }
}

pub(crate) async fn upload_remove(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    match state.core.remove_upload_client(&client_id).await {
        Ok(Some(removed)) => api_ok(json!({"ok": true, "removed": removed})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn upload_release_slot(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    match state.core.release_upload_slot(&client_id).await {
        Ok(Some(())) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn upload_add_friend(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    match state.core.add_upload_client_friend(&client_id).await {
        Ok(Some(friend)) => api_ok(friend).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn upload_remove_friend(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    match state.core.remove_upload_client_friend(&client_id).await {
        Ok(Some(_friend)) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "friend not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn upload_ban(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    match state.core.ban_upload_client(&client_id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn upload_unban(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    match state.core.unban_upload_client(&client_id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload client not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use emulebb_core::Upload;

    use super::without_score_breakdown;

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
            client_id: "0102030405060708090a0b0c0d0e0f10".to_string(),
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
}
