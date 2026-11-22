//! Library ignore-policy handlers.
use crate::handlers::prelude::*;
use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
};
use emulebb_core::{SharedFileIgnorePatternUpdate, SharedFileIgnoreRuleUpdate};

pub(crate) async fn shared_file_ignores(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.shared_file_ignores() {
        Ok(exclusions) => api_ok(exclusions).into_response(),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn add_shared_file_ignore_pattern(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedFileIgnorePatternUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state
        .core
        .add_shared_file_ignore_pattern(&request.pattern)
        .await
    {
        Ok(exclusions) => api_ok(exclusions).into_response(),
        Err(error) => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn remove_shared_file_ignore_pattern(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SharedFileIgnorePatternQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let Some(pattern) = query.pattern else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "pattern is required",
        )
        .into_response();
    };
    match state.core.remove_shared_file_ignore_pattern(&pattern).await {
        Ok(exclusions) => api_ok(exclusions).into_response(),
        Err(error) => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
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
        Err(error) => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
    }
}
