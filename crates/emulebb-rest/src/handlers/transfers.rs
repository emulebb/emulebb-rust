//! Transfer + transfer-source REST handlers (`/transfers`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use emulebb_core::{TransferCreate, TransferUpdate};

use crate::handlers::prelude::*;

pub(crate) async fn transfers(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<TransfersQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let items = state
        .core
        .transfers()
        .await
        .into_iter()
        .filter(|transfer| {
            query
                .state
                .as_deref()
                .is_none_or(|state| transfer.state == state)
        })
        .filter(|transfer| {
            query
                .category_id
                .is_none_or(|category_id| transfer.category_id == category_id)
        })
        .collect::<Vec<_>>();
    api_collection_page(items, query.page()).into_response()
}

pub(crate) async fn create_transfer(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<TransferCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.create_transfers(request).await {
        Ok(transfers) => api_bulk_operation(
            transfers
                .iter()
                .map(bulk_result_from_transfer)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn clear_completed_transfers(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<ClearCompletedTransfersRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_clear_completed {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "confirmClearCompleted must be true",
        )
        .into_response();
    }
    match state.core.clear_completed_transfer_rows().await {
        Ok(()) => api_ok(json!({ "ok": true })).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.transfer(&hash).await {
        Some(transfer) => api_ok(transfer).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response(),
    }
}

pub(crate) async fn transfer_details(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.transfer_details(&hash).await {
        Ok(Some(details)) => api_ok(details).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMULE_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn update_transfer(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<TransferUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_transfer(&hash, request).await {
        Ok(Some(transfer)) => api_ok(transfer).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_sources(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.transfer_sources(&hash).await {
        Ok(Some(sources)) => api_collection(sources).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.transfer_source(&hash, &client_id).await {
        Ok(Some(source)) => api_ok(source).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source_browse(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.browse_transfer_source(&hash, &client_id).await {
        Ok(true) => {
            api_ok(json!({"ok": true, "alreadyPending": false, "searchId": null})).into_response()
        }
        Ok(false) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source_add_friend(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state
        .core
        .add_transfer_source_friend(&hash, &client_id)
        .await
    {
        Ok(Some(friend)) => api_ok(friend).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source_remove_friend(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state
        .core
        .remove_transfer_source_friend(&hash, &client_id)
        .await
    {
        Ok(Some(_friend)) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "friend not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source_remove(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.remove_transfer_source(&hash, &client_id).await {
        Ok(Some(())) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source_ban(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.ban_transfer_source(&hash, &client_id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source_unban(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.unban_transfer_source(&hash, &client_id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_source_release_slot(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.transfer_source(&hash, &client_id).await {
        Ok(Some(_source)) => api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "client does not currently hold an upload slot",
        )
        .into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_pause(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.pause_transfer(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_resume(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.resume_transfer(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_stop(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.stop_transfer(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_recheck(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.recheck_transfer(&hash).await {
        Ok(Some(())) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_preview(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.preview_transfer(&hash).await {
        Ok(Some(transfer)) => api_ok(transfer).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_delete(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.delete_completed_transfer_row(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn transfer_delete_files(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<ConfirmQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    if query.confirm != Some(true) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "transfer file deletion requires confirm=true",
        )
        .into_response();
    }
    match state.core.delete_transfer_files(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}
