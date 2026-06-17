//! eD2K server REST handlers (`/servers`).
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

use emulebb_core::{ServerCreate, ServerUpdate};

use crate::handlers::prelude::*;

pub(crate) async fn servers(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(server_responses(state.core.servers().await))
}

pub(crate) async fn create_server(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<ServerCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.add_server(request).await {
        Ok(server) => api_ok(server_response(&server)).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn servers_connect(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.connect_ed2k().await {
        Ok(_status) => api_ok(server_status_response(&state).await).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn servers_disconnect(State(state): State<RestState>) -> impl IntoResponse {
    state.core.disconnect_ed2k().await;
    api_ok(server_status_response(&state).await)
}

pub(crate) async fn servers_import_met_url(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<UrlImportRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.import_server_met_url(&request.url).await {
        Ok(true) => api_ok(json!({ "ok": true, "imported": true })).into_response(),
        Ok(false) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMULE_ERROR",
            "failed to update server.met from URL",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn server(
    State(state): State<RestState>,
    Path(server_id): Path<String>,
) -> impl IntoResponse {
    match state.core.server(&server_id).await {
        Some(server) => api_ok(server_response(&server)).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response(),
    }
}

pub(crate) async fn update_server(
    State(state): State<RestState>,
    Path(server_id): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<ServerUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_server(&server_id, request).await {
        Ok(Some(server)) => api_ok(server_response(&server)).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn delete_server(
    State(state): State<RestState>,
    Path(server_id): Path<String>,
) -> impl IntoResponse {
    match state.core.remove_server(&server_id).await {
        Ok(Some(server)) => api_ok(server_response(&server)).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn connect_server(
    State(state): State<RestState>,
    Path(server_id): Path<String>,
) -> impl IntoResponse {
    match state.core.connect_ed2k_server(&server_id).await {
        Ok(Some(_status)) => api_ok(server_status_response(&state).await).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}
