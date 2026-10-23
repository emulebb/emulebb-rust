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

use emulebb_core::{
    SharedDirectoriesUpdate, SharedDirectoryRootUpdate, SharedFileExclusionUpdate,
    SharedFileIgnoreRuleUpdate, SharedFileListCursor, SharedFileListQuery, SharedFileUpdate,
};

use crate::handlers::prelude::*;

pub(crate) async fn shared_files(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SharedFilesQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let (_, limit) = match resolve_page_bounds(None, query.limit) {
        Ok(bounds) => bounds,
        Err(response) => return *response,
    };
    if let Err(message) = validate_shared_file_query(&query) {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message).into_response();
    }
    let cursor = match query.cursor.as_deref().map(decode_shared_file_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(message) => {
            return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message).into_response();
        }
    };
    match state
        .core
        .query_shared_files(SharedFileListQuery {
            search: query.q,
            priority: query.priority.map(|value| value.to_lowercase()),
            after: cursor,
            limit,
        })
        .await
    {
        Ok(page) => api_ok(json!({
            "items": page.items.iter().map(shared_file_list_response).collect::<Vec<_>>(),
            "total": page.total,
            "limit": limit,
            "nextCursor": page.next_cursor.as_ref().map(encode_shared_file_cursor),
        }))
        .into_response(),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

fn encode_shared_file_cursor(cursor: &SharedFileListCursor) -> String {
    serde_json::to_string(cursor).expect("shared-file cursor serialization is infallible")
}

fn decode_shared_file_cursor(cursor: &str) -> Result<SharedFileListCursor, String> {
    let cursor = serde_json::from_str::<SharedFileListCursor>(cursor)
        .map_err(|_| "cursor is invalid".to_string())?;
    if cursor.sort_path.is_empty()
        || cursor.hash.len() != 32
        || !cursor.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("cursor is invalid".to_string());
    }
    Ok(cursor)
}

fn validate_shared_file_query(query: &SharedFilesQuery) -> Result<(), String> {
    validate_optional_token(
        "priority",
        query.priority.as_deref(),
        &["auto", "verylow", "low", "normal", "high", "release", "not-published"],
    )?;
    Ok(())
}

fn validate_optional_token(
    field: &str,
    value: Option<&str>,
    allowed: &[&str],
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    if allowed.iter().any(|allowed| value.eq_ignore_ascii_case(allowed)) {
        return Ok(());
    }
    Err(format!("{field} has an unsupported value"))
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

pub(crate) async fn add_shared_directory_root(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedDirectoryRootUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.add_shared_directory_root(&request.path).await {
        Ok(directories) => api_ok(directories).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn remove_shared_directory_root(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SharedDirectoryRootQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let Some(path) = query.path else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "path is required",
        )
        .into_response();
    };
    match state.core.remove_shared_directory_root(&path).await {
        Ok(directories) => api_ok(directories).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn shared_file_exclusions(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.shared_file_exclusions() {
        Ok(exclusions) => api_ok(exclusions).into_response(),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn add_shared_file_exclusion(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedFileExclusionUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.add_shared_file_exclusion(&request.path).await {
        Ok(exclusions) => api_ok(exclusions).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn remove_shared_file_exclusion(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SharedDirectoryRootQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let Some(path) = query.path else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "path is required",
        )
        .into_response();
    };
    match state.core.remove_shared_file_exclusion(&path).await {
        Ok(exclusions) => api_ok(exclusions).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn update_shared_file_ignore_rule(
    State(state): State<RestState>,
    Path(rule_key): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedFileIgnoreRuleUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state
        .core
        .set_shared_file_ignore_rule_enabled(&rule_key, request.enabled)
        .await
    {
        Ok(exclusions) => api_ok(exclusions).into_response(),
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
