//! Search REST handlers (`/searches` and the search-result download op).
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

use emulebb_core::{SearchCreate, SearchResultDownloadCreate};

use crate::handlers::prelude::*;

pub(crate) async fn searches(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(
        state
            .core
            .searches()
            .await
            .iter()
            .map(search_session_response)
            .collect::<Vec<_>>(),
    )
}

pub(crate) async fn create_search(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let mut request = match parse_required_json_body::<SearchCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    normalize_search_create(&mut request);
    match state.core.create_search(request).await {
        Ok(search) => api_ok(search_response(&search)).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

fn normalize_search_create(request: &mut SearchCreate) {
    request.query = request
        .query
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
}

pub(crate) async fn search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SearchResultsQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    match state.core.search(&search_id).await {
        Some(search) => match search_results_page(search, query) {
            Ok(page) => api_ok(search_page_response(&page)).into_response(),
            Err(response) => *response,
        },
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response(),
    }
}

pub(crate) async fn delete_search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
) -> impl IntoResponse {
    match state.core.delete_search(&search_id).await {
        Ok(true) => api_ok(json!({ "deleted": true })).into_response(),
        Ok(false) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response()
        }
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn delete_searches(
    State(state): State<RestState>,
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
            "confirm must be true",
        )
        .into_response();
    }
    match state.core.clear_searches().await {
        Ok(()) => api_ok(json!({ "ok": true })).into_response(),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn download_search_result(
    State(state): State<RestState>,
    Path((search_id, hash)): Path<(String, String)>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match optional_json_body::<SearchResultDownloadCreate>(&body) {
        Ok(request) => request,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                json_error_message(&error),
            )
            .into_response();
        }
    };
    match state
        .core
        .download_search_result(&search_id, &hash, request)
        .await
    {
        Ok(Some(_transfer)) => api_ok(SearchResultDownloadResult {
            ok: true,
            search_id,
            hash,
        })
        .into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "search result not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}
