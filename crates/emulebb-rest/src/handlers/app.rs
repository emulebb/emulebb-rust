//! App lifecycle, diagnostics, preferences, and dashboard REST handlers
//! (`/app`, `/app/shutdown`, `/app/preferences`, `/diagnostics/*`, `/status`,
//! `/stats`, `/snapshot`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};

use emulebb_core::PreferencesUpdate;

use crate::handlers::prelude::*;
use crate::without_score_breakdown;

pub(crate) async fn app(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(app_info_response(state.core.app_info()))
}

pub(crate) async fn capabilities(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(capabilities_response(state.core.app_info()))
}

pub(crate) async fn shutdown_app(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<ShutdownRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_shutdown {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "confirmShutdown must be true",
        )
        .into_response();
    }
    if let Some(shutdown) = state.shutdown.as_ref() {
        let _ = shutdown.send(true);
    }
    api_ok(json!({"ok": true})).into_response()
}

pub(crate) async fn capture_diagnostic_dump(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<DiagnosticDumpRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_dump {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "confirmDump must be true",
        )
        .into_response();
    }
    match state
        .core
        .capture_diagnostic_dump(request.full_memory)
        .await
    {
        Ok(result) => api_ok(result).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn trigger_diagnostic_crash_test(body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<DiagnosticCrashTestRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_crash {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "confirmCrash must be true",
        )
        .into_response();
    }
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::process::abort();
    });
    api_ok(json!({"ok": true})).into_response()
}

pub(crate) async fn preferences(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.preferences().await)
}

pub(crate) async fn update_preferences(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<PreferencesUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_preferences(request).await {
        Ok(preferences) => api_ok(preferences).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn status(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(status_response(&state).await)
}

pub(crate) async fn stats(State(state): State<RestState>) -> impl IntoResponse {
    let status = state.core.status().await;
    let upload_policy = state.core.upload_policy_metrics().await;
    let throughput = state.core.transfer_throughput_stats();
    api_ok(stats_response(&status, &upload_policy, &throughput))
}

pub(crate) async fn snapshot(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SnapshotQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let limit = match snapshot_limit(query.limit) {
        Ok(limit) => limit,
        Err(response) => return *response,
    };
    let status = status_response(&state).await;
    let kad = kad_response(
        &state.core.status().await.kad,
        &state.core.vpn_guard_status(),
    );
    let shared_files = bounded(
        state
            .core
            .shares()
            .await
            .iter()
            .map(shared_file_response)
            .collect::<Vec<_>>(),
        limit,
    );
    api_ok(json!({
        "app": app_info_response(state.core.app_info()),
        "status": status,
        "transfers": bounded(state.core.transfers().await, limit),
        "sharedFiles": shared_files,
        "uploads": bounded(without_score_breakdown(state.core.uploads().await), limit),
        "uploadQueue": bounded(without_score_breakdown(state.core.upload_queue().await), limit),
        "servers": bounded(server_responses(state.core.servers().await), limit),
        "kad": kad,
        "network": network_response(&state.core.vpn_guard_status()),
        "logs": Vec::<Value>::new()
    }))
    .into_response()
}
