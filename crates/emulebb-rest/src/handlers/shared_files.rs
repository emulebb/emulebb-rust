//! Shared-file and shared-directory REST handlers (`/shared-files`,
//! `/shared-directories`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};

use emulebb_core::{SharedDirectoriesUpdate, SharedFileUpdate};

use crate::handlers::prelude::*;

pub(crate) async fn shared_files(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<PageQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let (offset, limit) = match resolve_page_bounds(query.offset, query.limit) {
        Ok(bounds) => bounds,
        Err(response) => return *response,
    };
    let (shares, total) = state.core.shares_page(offset, limit).await;
    let items = shares.iter().map(shared_file_response).collect::<Vec<_>>();
    api_ok(json!({
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit
    }))
    .into_response()
}

pub(crate) async fn shared_directories(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.shared_directories().await)
}

pub(crate) async fn update_shared_directories(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedDirectoriesUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.set_shared_directories(request).await {
        Ok(directories) => api_ok(directories).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn reload_shared_directories(State(state): State<RestState>) -> impl IntoResponse {
    // Hashing a large shared library takes far longer than any HTTP timeout, so
    // the scan + MD4/ed2k hash runs on a detached background task: the request
    // returns promptly with the queued count while hashing continues to
    // completion independent of this connection. Progress is observable via
    // `hashingCount` on `GET /api/v1/shared-directories` and the growing
    // `GET /api/v1/shared-files` total.
    match state.core.reload_shared_directories_detached().await {
        Ok(queued) => {
            api_ok(json!({ "ok": true, "started": true, "queued": queued })).into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn shared_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.share(&hash).await {
        Some(share) => api_ok(shared_file_response(&share)).into_response(),
        None => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
    }
}

pub(crate) async fn update_shared_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedFileUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_shared_file(&hash, request).await {
        Ok(Some(share)) => api_ok(shared_file_response(&share)).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn shared_file_comments(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.share(&hash).await {
        Some(share) => {
            let items = if share.comment.is_empty() && share.rating == 0 {
                Vec::<Value>::new()
            } else {
                vec![json!({
                    "source": "local",
                    "userName": null,
                    "fileName": share.name,
                    "comment": share.comment,
                    "rating": share.rating
                })]
            };
            api_collection(items).into_response()
        }
        None => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
    }
}

pub(crate) async fn shared_file_ed2k_link(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.share(&hash).await {
        Some(share) => api_ok(Ed2kLinkResult {
            hash: share.hash,
            link: share.ed2k_link,
        })
        .into_response(),
        None => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
    }
}
