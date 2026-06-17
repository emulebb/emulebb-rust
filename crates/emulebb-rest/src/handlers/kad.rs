//! Kademlia REST handlers (`/kad` and its operations).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::handlers::prelude::*;

pub(crate) async fn kad(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(kad_response(
        &state.core.status().await.kad,
        &state.core.vpn_guard_status(),
    ))
}

pub(crate) async fn kad_start(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.start_kad().await {
        Ok(_) => api_ok(kad_response(
            &state.core.status().await.kad,
            &state.core.vpn_guard_status(),
        ))
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn kad_stop(State(state): State<RestState>) -> impl IntoResponse {
    state.core.set_kad_running(false).await;
    api_ok(kad_response(
        &state.core.status().await.kad,
        &state.core.vpn_guard_status(),
    ))
}

pub(crate) async fn kad_import_nodes_url(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<UrlImportRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.import_kad_nodes_url(&request.url).await {
        Ok(true) => api_ok(json!({ "ok": true, "imported": true })).into_response(),
        Ok(false) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMULE_ERROR",
            "failed to update nodes.dat from URL",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn kad_bootstrap(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<KadBootstrapRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if request.address.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "address must not be empty",
        )
        .into_response();
    }
    if request.port == 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "port must be between 1 and 65535",
        )
        .into_response();
    }
    match state
        .core
        .bootstrap_kad(&request.address, request.port)
        .await
    {
        Ok(_) => api_ok(kad_response(
            &state.core.status().await.kad,
            &state.core.vpn_guard_status(),
        ))
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn kad_recheck_firewall(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(kad_response(
        &state.core.recheck_kad_firewall().await,
        &state.core.vpn_guard_status(),
    ))
}
