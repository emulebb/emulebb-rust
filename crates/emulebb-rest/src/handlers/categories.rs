//! Download-category REST handlers (`/categories`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use emulebb_core::{CategoryCreate, CategoryUpdate};

use crate::handlers::prelude::*;

pub(crate) async fn categories(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(state.core.categories().await)
}

pub(crate) async fn create_category(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<CategoryCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.create_category(request).await {
        Ok(category) => api_ok(category).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn category(
    State(state): State<RestState>,
    Path(category_id): Path<u32>,
) -> impl IntoResponse {
    match state.core.category(category_id).await {
        Some(category) => api_ok(category).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found").into_response(),
    }
}

pub(crate) async fn update_category(
    State(state): State<RestState>,
    Path(category_id): Path<u32>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<CategoryUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_category(category_id, request).await {
        Ok(Some(category)) => api_ok(category).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn delete_category(
    State(state): State<RestState>,
    Path(category_id): Path<u32>,
) -> impl IntoResponse {
    match state.core.delete_category(category_id).await {
        Ok(Some(_category)) => api_ok(json!({ "ok": true })).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}
