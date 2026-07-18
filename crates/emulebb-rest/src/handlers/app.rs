//! App lifecycle, diagnostics, settings, and dashboard REST handlers
//! (`/app`, `/app/shutdown`, `/app/settings`, `/diagnostics/*`, `/status`,
//! `/stats`, `/snapshot`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::stream;
use serde_json::json;
use std::convert::Infallible;

use emulebb_core::AppSettingsUpdate;
use tokio::sync::broadcast;

use crate::handlers::{logs::recent_log_values, prelude::*};
use crate::without_score_breakdown;

pub(crate) async fn app(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(app_info_response(state.core.app_info()))
}

pub(crate) async fn capabilities(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(capabilities_response(state.core.app_info()))
}

pub(crate) async fn events(State(state): State<RestState>) -> impl IntoResponse {
    let receiver = state.core.subscribe_transfer_events();
    let core = state.core.clone();
    let stream = stream::unfold((receiver, core), |(mut receiver, core)| async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event)
                        .expect("transfer events contain only serializable REST DTOs");
                    return Some((
                        Ok::<_, Infallible>(
                            Event::default()
                                .id(event.id.to_string())
                                .event(event.event_type)
                                .data(data),
                        ),
                        (receiver, core),
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    let id = core.reserve_transfer_event_id();
                    let data = json!({
                        "id": id,
                        "type": "sync.reset",
                        "reason": "lagged",
                        "missed": missed
                    })
                    .to_string();
                    return Some((
                        Ok::<_, Infallible>(
                            Event::default()
                                .id(id.to_string())
                                .event("sync.reset")
                                .data(data),
                        ),
                        (receiver, core),
                    ));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
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

pub(crate) async fn capture_diagnostic_dump(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
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

pub(crate) async fn settings(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.app_settings().await {
        Ok(settings) => api_ok(settings).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn update_settings(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<AppSettingsUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_app_settings(request).await {
        Ok(settings) => api_ok(settings).into_response(),
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
    let shared_hashing_count = state.core.shared_directories().await.hashing_count;
    api_ok(stats_response(
        &status,
        &upload_policy,
        &throughput,
        shared_hashing_count,
    ))
}

pub(crate) async fn snapshot(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SnapshotQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let limit = snapshot_limit(query.limit);
    let status = status_response(&state).await;
    let network = state.core.network_binding_status();
    let kad = kad_response(
        &state.core.status().await.kad,
        network.as_ref(),
        &state.core.vpn_guard_status(),
    );
    let shared_files = state
        .core
        .shares_page(0, limit)
        .await
        .0
        .iter()
        .map(shared_file_response)
        .collect::<Vec<_>>();
    api_ok(json!({
        "app": app_info_response(state.core.app_info()),
        "status": status,
        "transfers": bounded(state.core.transfers().await, limit),
        "sharedFiles": shared_files,
        "uploads": bounded(without_score_breakdown(state.core.uploads().await), limit),
        "uploadQueue": bounded(without_score_breakdown(state.core.upload_queue().await), limit),
        "servers": server_responses(state.core.servers().await),
        "kad": kad,
        "network": network_response(network.as_ref(), &state.core.vpn_guard_status()),
        "logs": recent_log_values(limit)
    }))
    .into_response()
}
