//! Router construction, API-key middleware, and the fallback / 405-rewrite
//! response shaping.
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged. The route table wires the per-domain handlers from
//! `crate::handlers`.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, HttpBody, to_bytes},
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use emulebb_core::EmulebbCore;
use serde_json::json;
use tokio::sync::watch;

use crate::envelope::api_error;
use crate::handlers::*;
use crate::{RestConfig, RestState};

pub fn router(core: Arc<EmulebbCore>, config: RestConfig) -> Router {
    router_with_shutdown(core, config, None)
}

pub fn router_with_shutdown(
    core: Arc<EmulebbCore>,
    config: RestConfig,
    shutdown: Option<watch::Sender<bool>>,
) -> Router {
    let state = RestState {
        core,
        api_key: Arc::new(config.api_key),
        shutdown,
    };
    Router::new()
        .route("/api/v1/app", get(app))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/app/shutdown", post(shutdown_app))
        .route("/api/v1/diagnostics/dumps", post(capture_diagnostic_dump))
        .route(
            "/api/v1/diagnostics/crash-tests",
            post(trigger_diagnostic_crash_test),
        )
        .route(
            "/api/v1/app/preferences",
            get(preferences).patch(update_preferences),
        )
        .route("/api/v1/status", get(status))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/categories", get(categories).post(create_category))
        .route(
            "/api/v1/categories/{category_id}",
            get(category).patch(update_category).delete(delete_category),
        )
        .route("/api/v1/friends", get(friends).post(create_friend))
        .route("/api/v1/friends/{user_hash}", delete(delete_friend))
        .route("/api/v1/kad", get(kad))
        .route(
            "/api/v1/kad/operations/import-nodes-url",
            post(kad_import_nodes_url),
        )
        .route("/api/v1/kad/operations/start", post(kad_start))
        .route("/api/v1/kad/operations/stop", post(kad_stop))
        .route("/api/v1/kad/operations/bootstrap", post(kad_bootstrap))
        .route(
            "/api/v1/kad/operations/recheck-firewall",
            post(kad_recheck_firewall),
        )
        .route("/api/v1/servers", get(servers).post(create_server))
        .route("/api/v1/servers/operations/connect", post(servers_connect))
        .route(
            "/api/v1/servers/operations/disconnect",
            post(servers_disconnect),
        )
        .route(
            "/api/v1/servers/operations/import-met-url",
            post(servers_import_met_url),
        )
        .route(
            "/api/v1/servers/{server_id}",
            get(server).patch(update_server).delete(delete_server),
        )
        .route(
            "/api/v1/servers/{server_id}/operations/connect",
            post(connect_server),
        )
        .route(
            "/api/v1/searches",
            get(searches).post(create_search).delete(delete_searches),
        )
        .route(
            "/api/v1/searches/{search_id}",
            get(search).delete(delete_search),
        )
        .route(
            "/api/v1/shared-files",
            get(shared_files).post(create_shared_file),
        )
        .route(
            "/api/v1/shared-files/operations/reload",
            post(reload_shared_directories),
        )
        .route(
            "/api/v1/shared-files/{hash}",
            get(shared_file)
                .patch(update_shared_file)
                .delete(delete_shared_file),
        )
        .route(
            "/api/v1/shared-files/{hash}/file",
            delete(delete_shared_file_payload),
        )
        .route(
            "/api/v1/shared-files/{hash}/comments",
            get(shared_file_comments),
        )
        .route(
            "/api/v1/shared-files/{hash}/ed2k-link",
            get(shared_file_ed2k_link),
        )
        .route(
            "/api/v1/shared-directories",
            get(shared_directories).patch(update_shared_directories),
        )
        .route(
            "/api/v1/shared-directories/operations/reload",
            post(reload_shared_directories),
        )
        .route(
            "/api/v1/searches/{search_id}/results/{hash}/operations/download",
            post(download_search_result),
        )
        .route("/api/v1/transfers", get(transfers).post(create_transfer))
        .route(
            "/api/v1/transfers/operations/clear-completed",
            post(clear_completed_transfers),
        )
        .route(
            "/api/v1/transfers/{hash}",
            get(transfer).patch(update_transfer).delete(transfer_delete),
        )
        .route(
            "/api/v1/transfers/{hash}/files",
            delete(transfer_delete_files),
        )
        .route("/api/v1/transfers/{hash}/details", get(transfer_details))
        .route("/api/v1/transfers/{hash}/sources", get(transfer_sources))
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}",
            get(transfer_source),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}/operations/browse",
            post(transfer_source_browse),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}/operations/add-friend",
            post(transfer_source_add_friend),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}/operations/remove-friend",
            post(transfer_source_remove_friend),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}/operations/remove",
            post(transfer_source_remove),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}/operations/ban",
            post(transfer_source_ban),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}/operations/unban",
            post(transfer_source_unban),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{client_id}/operations/release-slot",
            post(transfer_source_release_slot),
        )
        .route("/api/v1/uploads", get(uploads))
        .route("/api/v1/uploads/{client_id}", get(upload))
        .route(
            "/api/v1/uploads/{client_id}/operations/remove",
            post(upload_remove),
        )
        .route(
            "/api/v1/uploads/{client_id}/operations/release-slot",
            post(upload_release_slot),
        )
        .route(
            "/api/v1/uploads/{client_id}/operations/add-friend",
            post(upload_add_friend),
        )
        .route(
            "/api/v1/uploads/{client_id}/operations/remove-friend",
            post(upload_remove_friend),
        )
        .route(
            "/api/v1/uploads/{client_id}/operations/ban",
            post(upload_ban),
        )
        .route(
            "/api/v1/uploads/{client_id}/operations/unban",
            post(upload_unban),
        )
        .route("/api/v1/upload-queue", get(upload_queue))
        .route("/api/v1/upload-queue/{client_id}", get(upload_queue_client))
        .route(
            "/api/v1/upload-queue/{client_id}/operations/remove",
            post(upload_remove),
        )
        .route(
            "/api/v1/upload-queue/{client_id}/operations/release-slot",
            post(upload_release_slot),
        )
        .route(
            "/api/v1/upload-queue/{client_id}/operations/add-friend",
            post(upload_add_friend),
        )
        .route(
            "/api/v1/upload-queue/{client_id}/operations/remove-friend",
            post(upload_remove_friend),
        )
        .route(
            "/api/v1/upload-queue/{client_id}/operations/ban",
            post(upload_ban),
        )
        .route(
            "/api/v1/upload-queue/{client_id}/operations/unban",
            post(upload_unban),
        )
        .route(
            "/api/v1/transfers/{hash}/operations/pause",
            post(transfer_pause),
        )
        .route(
            "/api/v1/transfers/{hash}/operations/resume",
            post(transfer_resume),
        )
        .route(
            "/api/v1/transfers/{hash}/operations/stop",
            post(transfer_stop),
        )
        .route(
            "/api/v1/transfers/{hash}/operations/recheck",
            post(transfer_recheck),
        )
        .route(
            "/api/v1/transfers/{hash}/operations/preview",
            post(transfer_preview),
        )
        .route("/api/v1/logs", get(logs))
        .route("/api/v1/logs/operations/clear", post(clear_logs))
        .fallback(fallback)
        .layer(middleware::map_response(rewrite_method_not_allowed))
        .layer(middleware::from_fn(validate_route_metadata))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .with_state(state)
}

async fn require_api_key(
    State(state): State<RestState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if state.api_key.is_empty() {
        return next.run(request).await;
    }
    let supplied = request
        .headers()
        .get("X-API-Key")
        .and_then(|value| value.to_str().ok());
    if supplied == Some(state.api_key.as_str()) {
        next.run(request).await
    } else {
        api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "missing or invalid API key",
        )
        .into_response()
    }
}

async fn fallback() -> impl IntoResponse {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "API route not found")
}

async fn validate_route_metadata(request: Request<Body>, next: Next) -> Response {
    let method = request.method().as_str();
    let path = request.uri().path();
    let Some(allowed_query_fields) = route_query_fields(method, path) else {
        return next.run(request).await;
    };
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            if !allowed_query_fields.contains(&name) {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    format!("unknown JSON field: {name}"),
                )
                .into_response();
            }
        }
    }
    if request.body().size_hint().upper() == Some(0) {
        return next.run(request).await;
    }

    let is_delete = method == "DELETE";
    let is_json_content = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_json_content_type);

    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, usize::MAX).await {
        Ok(body) => body,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                format!("invalid request body: {error}"),
            )
            .into_response();
        }
    };

    if !is_ascii_whitespace_only(&body) {
        if is_delete {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "DELETE request bodies are not supported",
            )
            .into_response();
        }
        if !is_json_content {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "Content-Type must be application/json for JSON request bodies",
            )
            .into_response();
        }
    }

    let request = Request::from_parts(parts, Body::from(body));
    next.run(request).await
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim()
        .eq_ignore_ascii_case("application/json")
}

fn is_ascii_whitespace_only(body: &[u8]) -> bool {
    body.iter().all(|byte| byte.is_ascii_whitespace())
}

fn route_query_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
    const NONE: &[&str] = &[];
    const SNAPSHOT: &[&str] = &["limit"];
    const PAGE: &[&str] = &["offset", "limit"];
    const TRANSFERS: &[&str] = &["state", "categoryId", "offset", "limit"];
    const CONFIRM: &[&str] = &["confirm"];
    const UPLOAD_QUEUE: &[&str] = &["offset", "limit", "includeScoreBreakdown"];

    match (method, path) {
        ("GET", "/api/v1/app")
        | ("GET", "/api/v1/capabilities")
        | ("GET", "/api/v1/app/preferences")
        | ("GET", "/api/v1/status")
        | ("GET", "/api/v1/stats")
        | ("GET", "/api/v1/categories")
        | ("POST", "/api/v1/categories")
        | ("GET", "/api/v1/friends")
        | ("POST", "/api/v1/friends")
        | ("GET", "/api/v1/kad")
        | ("POST", "/api/v1/kad/operations/import-nodes-url")
        | ("POST", "/api/v1/kad/operations/start")
        | ("POST", "/api/v1/kad/operations/stop")
        | ("POST", "/api/v1/kad/operations/bootstrap")
        | ("POST", "/api/v1/kad/operations/recheck-firewall")
        | ("GET", "/api/v1/servers")
        | ("POST", "/api/v1/servers")
        | ("POST", "/api/v1/servers/operations/connect")
        | ("POST", "/api/v1/servers/operations/disconnect")
        | ("POST", "/api/v1/servers/operations/import-met-url")
        | ("GET", "/api/v1/searches")
        | ("POST", "/api/v1/searches")
        | ("GET", "/api/v1/shared-directories")
        | ("PATCH", "/api/v1/shared-directories")
        | ("POST", "/api/v1/shared-directories/operations/reload")
        | ("POST", "/api/v1/shared-files")
        | ("POST", "/api/v1/shared-files/operations/reload")
        | ("GET", "/api/v1/uploads")
        | ("GET", "/api/v1/upload-queue")
        | ("POST", "/api/v1/transfers")
        | ("POST", "/api/v1/transfers/operations/clear-completed")
        | ("POST", "/api/v1/logs/operations/clear")
        | ("POST", "/api/v1/app/shutdown")
        | ("POST", "/api/v1/diagnostics/dumps")
        | ("POST", "/api/v1/diagnostics/crash-tests") => Some(match path {
            "/api/v1/upload-queue" if method == "GET" => UPLOAD_QUEUE,
            _ => NONE,
        }),
        ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
        ("GET", "/api/v1/shared-files") => Some(PAGE),
        ("GET", "/api/v1/transfers") => Some(TRANSFERS),
        ("GET", "/api/v1/logs") => Some(SNAPSHOT),
        ("DELETE", "/api/v1/searches") => Some(CONFIRM),
        _ => route_query_fields_for_parameterized(method, path),
    }
}

fn route_query_fields_for_parameterized(
    method: &str,
    path: &str,
) -> Option<&'static [&'static str]> {
    const NONE: &[&str] = &[];
    const CONFIRM: &[&str] = &["confirm"];
    const SEARCH: &[&str] = &["offset", "limit", "includeEvidence", "exactTotal"];

    let segments = path
        .strip_prefix("/api/v1/")?
        .split('/')
        .collect::<Vec<_>>();
    match (method, segments.as_slice()) {
        ("GET", ["categories", _])
        | ("PATCH", ["categories", _])
        | ("DELETE", ["categories", _])
        | ("DELETE", ["friends", _])
        | ("GET", ["servers", _])
        | ("PATCH", ["servers", _])
        | ("DELETE", ["servers", _])
        | ("DELETE", ["searches", _])
        | ("GET", ["shared-files", _])
        | ("PATCH", ["shared-files", _])
        | ("DELETE", ["shared-files", _])
        | ("GET", ["shared-files", _, "ed2k-link"])
        | ("GET", ["shared-files", _, "comments"])
        | ("GET", ["transfers", _])
        | ("PATCH", ["transfers", _])
        | ("DELETE", ["transfers", _])
        | ("GET", ["transfers", _, "details"])
        | ("GET", ["transfers", _, "sources"])
        | ("GET", ["transfers", _, "sources", _])
        | ("GET", ["uploads", _])
        | ("GET", ["upload-queue", _]) => Some(NONE),
        ("POST", ["servers", _, "operations", "connect"])
        | ("POST", ["searches", _, "results", _, "operations", "download"]) => Some(NONE),
        ("POST", ["transfers", _, "operations", operation])
            if matches!(
                *operation,
                "pause" | "resume" | "stop" | "recheck" | "preview"
            ) =>
        {
            Some(NONE)
        }
        ("POST", ["transfers", _, "sources", _, "operations", operation])
            if matches!(
                *operation,
                "browse"
                    | "add-friend"
                    | "remove-friend"
                    | "remove"
                    | "ban"
                    | "unban"
                    | "release-slot"
            ) =>
        {
            Some(NONE)
        }
        ("POST", ["uploads", _, "operations", operation])
        | ("POST", ["upload-queue", _, "operations", operation])
            if matches!(
                *operation,
                "remove" | "release-slot" | "add-friend" | "remove-friend" | "ban" | "unban"
            ) =>
        {
            Some(NONE)
        }
        ("GET", ["searches", _]) => Some(SEARCH),
        ("DELETE", ["shared-files", _, "file"]) | ("DELETE", ["transfers", _, "files"]) => {
            Some(CONFIRM)
        }
        _ => None,
    }
}

/// Replaces axum's default 405 body with the standard REST error envelope while
/// preserving the `Allow` header the method router already set, so the response
/// matches the emulebb master byte-for-byte (status 405 + `Allow` + envelope).
async fn rewrite_method_not_allowed(response: Response) -> Response {
    if response.status() != StatusCode::METHOD_NOT_ALLOWED {
        return response;
    }
    let (mut parts, _body) = response.into_parts();
    let body = serde_json::to_vec(&json!({
        "error": {
            "code": "METHOD_NOT_ALLOWED",
            "message": "HTTP method is not allowed for this API route",
            "details": {}
        }
    }))
    .unwrap_or_default();
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body))
}
