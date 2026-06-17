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

use emulebb_core::{LocalShareCreate, SharedDirectoriesUpdate, SharedFileUpdate};

use crate::handlers::prelude::*;

pub(crate) async fn shared_files(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<PageQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let items = state
        .core
        .shares()
        .await
        .iter()
        .map(shared_file_response)
        .collect::<Vec<_>>();
    api_collection_page(items, query).into_response()
}

pub(crate) async fn create_shared_file(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedFileCreateRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if request.path.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "path is required")
            .into_response();
    }
    let path = request.path;
    match state
        .core
        .share_local_file(LocalShareCreate {
            path: path.clone(),
            name: None,
        })
        .await
    {
        Ok(share) => api_ok(SharedFileCreateResult {
            ok: true,
            path,
            already_shared: false,
            queued: false,
            file: shared_file_response(&share),
        })
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
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
    match state.core.reload_shared_directories().await {
        Ok(_shares) => api_ok(json!({ "ok": true })).into_response(),
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

pub(crate) async fn delete_shared_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let Some(share) = state.core.share(&hash).await else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found")
            .into_response();
    };
    let path = managed_shared_file_path(&share);
    match state.core.unshare_file(&hash).await {
        Ok(Some(_share)) => api_ok(SharedFileRemoveResult {
            ok: true,
            deleted_files: false,
            path,
            hash: share.hash,
        })
        .into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn delete_shared_file_payload(
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
            "shared file deletion requires confirm=true",
        )
        .into_response();
    }
    let Some(share) = state.core.share(&hash).await else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found")
            .into_response();
    };
    let path = managed_shared_file_path(&share);
    match state.core.delete_transfer_files(&hash).await {
        Ok(Some(_transfer)) => api_ok(SharedFileRemoveResult {
            ok: true,
            deleted_files: true,
            path,
            hash: share.hash,
        })
        .into_response(),
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
