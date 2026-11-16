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
    match state.core.categories().await {
        Ok(categories) => api_collection(categories).into_response(),
        Err(error) => category_error(error),
    }
}

pub(crate) async fn create_category(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<CategoryCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.create_category(request).await {
        Ok(category) => api_ok(category).into_response(),
        Err(error) => category_error(error),
    }
}

pub(crate) async fn category(
    State(state): State<RestState>,
    Path(category_name): Path<String>,
) -> impl IntoResponse {
    match state.core.category_by_name(&category_name).await {
        Ok(Some(category)) => api_ok(category).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found").into_response()
        }
        Err(error) => category_error(error),
    }
}

pub(crate) async fn update_category(
    State(state): State<RestState>,
    Path(category_name): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<CategoryUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let category_id = match state.core.category_by_name(&category_name).await {
        Ok(Some(category)) => category.id,
        Ok(None) => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found")
                .into_response();
        }
        Err(error) => return category_error(error),
    };
    match state.core.update_category(category_id, request).await {
        Ok(Some(category)) => api_ok(category).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found").into_response()
        }
        Err(error) => category_error(error),
    }
}

pub(crate) async fn delete_category(
    State(state): State<RestState>,
    Path(category_name): Path<String>,
) -> impl IntoResponse {
    let category_id = match state.core.category_by_name(&category_name).await {
        Ok(Some(category)) => category.id,
        Ok(None) => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found")
                .into_response();
        }
        Err(error) => return category_error(error),
    };
    match state.core.delete_category(category_id).await {
        Ok(Some(_category)) => api_ok(json!({ "ok": true })).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "category not found").into_response()
        }
        Err(error) => category_error(error),
    }
}

fn category_error(error: anyhow::Error) -> axum::response::Response {
    if error
        .downcast_ref::<emulebb_core::CategoryNameConflict>()
        .is_some()
    {
        api_error(
            StatusCode::CONFLICT,
            "CATEGORY_NAME_CONFLICT",
            error.to_string(),
        )
        .into_response()
    } else {
        super::persistence::persistence_error(error)
    }
}
