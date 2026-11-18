//! Search resources and selected-result actions.
mod browse;
mod observations;
pub(crate) use browse::{search, search_result, search_results, searches};
pub(crate) use observations::search_result_observations;

use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use emulebb_core::{SearchCreate, SearchResultDownloadCreate};

use crate::handlers::prelude::*;

pub(crate) async fn create_search(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SearchCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.create_search(request).await {
        Ok(search) => {
            let mut response =
                super::resource::item(StatusCode::CREATED, search_created_response(&search));
            response.headers_mut().insert(
                axum::http::header::LOCATION,
                format!("/api/v1/searches/{}", search.id)
                    .parse()
                    .expect("allocated search identity is a valid path"),
            );
            response
        }
        Err(error) if error.is::<emulebb_metadata::MissingSearchParent>() => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "parent search not found",
        )
        .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn stop_search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
) -> impl IntoResponse {
    match state.core.stop_search(&search_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response()
        }
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn delete_search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
) -> impl IntoResponse {
    match state.core.delete_search(&search_id).await {
        Ok(true) => api_ok(json!({ "ok": true })).into_response(),
        Ok(false) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response()
        }
        Err(error) => super::persistence::persistence_error(error),
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
            "INVALID_ARGUMENT",
            "confirm must be true",
        )
        .into_response();
    }
    match state.core.clear_searches().await {
        Ok(()) => api_ok(json!({ "ok": true })).into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn download_search_result(
    State(state): State<RestState>,
    Path((search_id, result_id)): Path<(String, String)>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match optional_json_body::<SearchResultDownloadCreate>(&body) {
        Ok(request) => request,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                json_error_message(&error),
            )
            .into_response();
        }
    };
    match state
        .core
        .download_search_result(&search_id, &result_id, request)
        .await
    {
        Ok(Some((created, download))) => super::resource::item(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            &*download,
        ),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "search result not found",
        )
        .into_response(),
        Err(error) => download_creation_error(error),
    }
}
