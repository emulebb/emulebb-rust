//! App lifecycle, diagnostics, settings, and dashboard REST handlers
//! (`/app`, `/app/shutdown`, `/diagnostics/*`, `/status`,
//! `/stats`, `/snapshot`).

use axum::{
    body::{Body, Bytes},
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::stream;
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;

use emulebb_core::{DownloadEvent, DownloadEventResetReason};
use tokio::sync::broadcast;

use crate::diagnostic_bundle::{
    MAX_DIAGNOSTIC_BUNDLE_BYTES, MIN_DIAGNOSTIC_BUNDLE_BYTES, capture as capture_bundle,
};
use crate::handlers::{logs::recent_log_values, prelude::*};

pub(crate) async fn app(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(app_info_response(state.core.app_info()))
}

pub(crate) async fn capabilities(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(capabilities_response(state.core.app_info()))
}

pub(crate) async fn events(
    headers: HeaderMap,
    State(state): State<RestState>,
) -> impl IntoResponse {
    let reason = if headers.contains_key("Last-Event-ID") {
        DownloadEventResetReason::Reconnect
    } else {
        DownloadEventResetReason::Initial
    };
    let subscription = state.core.subscribe_download_events(reason, None);
    let receiver = subscription.receiver;
    let shutdown = state.shutdown.as_ref().map(|request| request.subscribe());
    let core = state.core.clone();
    let pending_reset = Some(subscription.reset);
    let stream = stream::unfold(
        (receiver, core, pending_reset, shutdown),
        |(mut receiver, core, pending_reset, mut shutdown)| async move {
            if shutdown
                .as_ref()
                .is_some_and(|request| *request.borrow() || request.has_changed().is_err())
            {
                return None;
            }
            if let Some(event) = pending_reset {
                return Some((
                    Ok::<_, Infallible>(sse_event(event)),
                    (receiver, core, None, shutdown),
                ));
            }
            // WHY: a live SSE response otherwise keeps HTTP graceful shutdown
            // waiting forever, delaying network teardown and embedded-host exit.
            let event = if let Some(request) = shutdown.as_mut() {
                tokio::select! {
                    biased;
                    _ = request.wait_for(|requested| *requested) => return None,
                    event = receiver.recv() => event,
                }
            } else {
                receiver.recv().await
            };
            match event {
                Ok(event) => Some((
                    Ok::<_, Infallible>(sse_event(event)),
                    (receiver, core, None, shutdown),
                )),
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    let subscription = core
                        .subscribe_download_events(DownloadEventResetReason::Lagged, Some(missed));
                    let event = subscription.reset;
                    Some((
                        Ok::<_, Infallible>(sse_event(event)),
                        (subscription.receiver, core, None, shutdown),
                    ))
                }
                Err(broadcast::error::RecvError::Closed) => None,
            }
        },
    );
    (
        [
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-transform"),
            ),
            (
                HeaderName::from_static("x-accel-buffering"),
                HeaderValue::from_static("no"),
            ),
        ],
        Sse::new(stream).keep_alive(KeepAlive::default()),
    )
}

pub(crate) async fn event_status(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.download_event_diagnostics())
}

fn sse_event(event: DownloadEvent) -> Event {
    let id = event.cursor();
    let event_type = event.sse_name();
    let data = serde_json::to_string(&event)
        .expect("download events contain only serializable scalar identities");
    Event::default().id(id).event(event_type).data(data)
}

pub(crate) async fn shutdown_app(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<ShutdownRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_shutdown {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "confirmShutdown must be true",
        )
        .into_response();
    }
    if let Some(shutdown) = state.shutdown.as_ref() {
        shutdown.send_replace(true);
    }
    api_ok(json!({"ok": true})).into_response()
}

/// The capture slot follows encoded backing through body/frame clones, including
/// a slow receiver; constructing the response does not release its ownership.
struct DiagnosticBundleBody {
    bytes: Box<[u8]>,
    _capture: tokio::sync::OwnedSemaphorePermit,
}

impl AsRef<[u8]> for DiagnosticBundleBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) async fn capture_diagnostic_bundle(
    State(state): State<RestState>,
    body: Bytes,
) -> Response {
    let request = match parse_required_json_body::<DiagnosticBundleCaptureRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_capture {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "confirmCapture must be true",
        )
        .into_response();
    }
    if !(MIN_DIAGNOSTIC_BUNDLE_BYTES..=MAX_DIAGNOSTIC_BUNDLE_BYTES).contains(&request.max_bytes) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!(
                "maxBytes must be in the range {MIN_DIAGNOSTIC_BUNDLE_BYTES}..={MAX_DIAGNOSTIC_BUNDLE_BYTES}"
            ),
        )
        .into_response();
    }
    // WHY: a caller can retain a completed body indefinitely. Bound aggregate
    // capture work and backing until that body is actually dropped, not queued.
    let Ok(capture) = state.diagnostic_capture.clone().try_acquire_owned() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_BUSY",
            "a diagnostic capture or its response is already active",
        )
        .into_response();
    };
    match capture_bundle(&state, request.max_bytes).await {
        Ok(bundle) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, bundle.len().to_string())
            .body(Body::from(Bytes::from_owner(DiagnosticBundleBody {
                bytes: bundle,
                _capture: capture,
            })))
            .expect("diagnostic bundle response must be valid"),
        Err(error) => super::persistence::persistence_error(error),
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
            "INVALID_ARGUMENT",
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

pub(crate) async fn status(State(state): State<RestState>) -> impl IntoResponse {
    match status_response(&state).await {
        Ok(value) => api_ok(value).into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn diagnostics(State(state): State<RestState>) -> impl IntoResponse {
    match runtime_diagnostics_response(&state).await {
        Ok(value) => api_ok(value).into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn vpn_guard(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(vpn_guard_response(&state.core.vpn_guard_status()))
}

pub(crate) async fn probe_vpn_guard(State(state): State<RestState>) -> impl IntoResponse {
    state.core.run_vpn_guard_egress_probe().await;
    api_ok(vpn_guard_response(&state.core.vpn_guard_status()))
}

pub(crate) async fn network(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(network_response(
        state.core.network_binding_status().as_ref(),
        &state.core.vpn_guard_status(),
    ))
}

pub(crate) async fn nat(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(nat_response(&state.core.nat_status().await))
}

pub(crate) async fn refresh_nat(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(nat_response(&state.core.refresh_nat_status().await))
}

pub(crate) async fn stats(State(state): State<RestState>) -> impl IntoResponse {
    let status = state.core.status().await;
    let transfers = match state.core.transfer_stats().await {
        Ok(value) => value,
        Err(error) => return super::persistence::persistence_error(error),
    };
    let upload_policy = state.core.upload_policy_metrics().await;
    let throughput = state.core.transfer_throughput_stats();
    let scan = state.core.library_scan();
    api_ok(stats_response(
        &status,
        &transfers,
        &upload_policy,
        &throughput,
        &scan,
    ))
    .into_response()
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
    let status = match status_response(&state).await {
        Ok(value) => value,
        Err(error) => return super::persistence::persistence_error(error),
    };
    let network = state.core.network_binding_status();
    let kad = kad_response(
        &state.core.status().await.kad,
        network.as_ref(),
        &state.core.vpn_guard_status(),
    );
    let downloads = match state.core.download_counts().await {
        Ok(downloads) => downloads,
        Err(error) => return super::persistence::persistence_error(error),
    };
    // WHY: unrelated persistence work must finish before retaining both upload
    // pages, so their response allowances do not compete with metadata workspaces.
    let upload_queue = match state
        .core
        .upload_queue_page(None, limit.min(200), false)
        .await
    {
        Ok(page) => page,
        Err(error) => return super::persistence::persistence_error(error),
    };
    let uploads = match state
        .core
        .active_upload_page(None, limit.min(200), false)
        .await
    {
        Ok(page) => page,
        Err(error) => return super::persistence::persistence_error(error),
    };
    // WHY: a JSON value tree would copy both admitted upload pages and release
    // their charges before a slow receiver drops the encoded body. Borrow the
    // rows and admit exact wire backing through the existing read registry.
    super::resource::retained_json(
        &downloads,
        &super::resource::item_document(SnapshotResponse {
            app: app_info_response(state.core.app_info()),
            status,
            downloads: &downloads,
            uploads: &uploads.uploads,
            upload_queue: &upload_queue.uploads,
            kad,
            network: network_response(network.as_ref(), &state.core.vpn_guard_status()),
            logs: recent_log_values(limit),
        }),
    )
}

/// Borrow admitted transfer rows while encoding the dashboard envelope.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotResponse<'a> {
    app: serde_json::Value,
    status: serde_json::Value,
    downloads: &'a emulebb_core::DownloadCounts,
    uploads: &'a [emulebb_core::Upload],
    upload_queue: &'a [emulebb_core::Upload],
    kad: serde_json::Value,
    network: serde_json::Value,
    logs: Vec<serde_json::Value>,
}
