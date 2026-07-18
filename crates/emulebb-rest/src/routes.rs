//! Router construction, API-key middleware, and the fallback / 405-rewrite
//! response shaping.
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged. The route table wires the per-domain handlers from
//! `crate::handlers`.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderName, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
};
use emulebb_core::EmulebbCore;
use serde_json::json;
use tokio::sync::watch;

use crate::envelope::api_error;
use crate::handlers::*;
use crate::responses::CONTRACT_VERSION;
use crate::route_metadata::validate_route_metadata;
use crate::webui::mount_webui;
use crate::{RestServerSettings, RestState};

pub fn router(core: Arc<EmulebbCore>, config: RestServerSettings) -> Router {
    router_with_shutdown(core, config, None)
}

pub fn router_with_shutdown(
    core: Arc<EmulebbCore>,
    config: RestServerSettings,
    shutdown: Option<watch::Sender<bool>>,
) -> Router {
    let state = RestState {
        core,
        api_key: Arc::new(config.api_key),
        shutdown,
    };
    let api_router = Router::new()
        .route("/api/v1/app", get(app))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/events", get(events))
        .route("/api/v1/app/shutdown", post(shutdown_app))
        .route("/api/v1/diagnostics", get(diagnostics))
        .route("/api/v1/diagnostics/dumps", post(capture_diagnostic_dump))
        .route(
            "/api/v1/diagnostics/crash-tests",
            post(trigger_diagnostic_crash_test),
        )
        .route("/api/v1/app/settings/surface", get(settings_surface))
        .route("/api/v1/app/settings", get(settings).patch(update_settings))
        .route("/api/v1/status", get(status))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/categories", get(categories).post(create_category))
        .route(
            "/api/v1/categories/{categoryId}",
            get(category).patch(update_category).delete(delete_category),
        )
        .route("/api/v1/friends", get(friends).post(create_friend))
        .route("/api/v1/friends/{userHash}", delete(delete_friend))
        .route("/api/v1/ip-filter", get(ip_filter))
        .route(
            "/api/v1/ip-filter/operations/reload",
            post(reload_ip_filter),
        )
        .route("/api/v1/kad", get(kad))
        .route("/api/v1/kad/nodes", get(kad_nodes))
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
            "/api/v1/servers/{serverId}",
            get(server).patch(update_server).delete(delete_server),
        )
        .route(
            "/api/v1/servers/{serverId}/operations/connect",
            post(connect_server),
        )
        .route(
            "/api/v1/searches",
            get(searches).post(create_search).delete(delete_searches),
        )
        .route(
            "/api/v1/searches/{searchId}",
            get(search).delete(delete_search),
        )
        .route("/api/v1/shared-files", get(shared_files))
        .route(
            "/api/v1/shared-files/{hash}",
            get(shared_file).patch(update_shared_file),
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
            "/api/v1/searches/{searchId}/results/{hash}/operations/download",
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
            "/api/v1/transfers/{hash}/sources/{clientId}",
            get(transfer_source),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{clientId}/operations/browse",
            post(transfer_source_browse),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{clientId}/operations/add-friend",
            post(transfer_source_add_friend),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{clientId}/operations/remove-friend",
            post(transfer_source_remove_friend),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{clientId}/operations/remove",
            post(transfer_source_remove),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{clientId}/operations/ban",
            post(transfer_source_ban),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{clientId}/operations/unban",
            post(transfer_source_unban),
        )
        .route(
            "/api/v1/transfers/{hash}/sources/{clientId}/operations/release-slot",
            post(transfer_source_release_slot),
        )
        .route("/api/v1/uploads", get(uploads))
        .route("/api/v1/uploads/{clientId}", get(upload))
        .route(
            "/api/v1/uploads/{clientId}/operations/remove",
            post(upload_remove),
        )
        .route(
            "/api/v1/uploads/{clientId}/operations/release-slot",
            post(upload_release_slot),
        )
        .route(
            "/api/v1/uploads/{clientId}/operations/add-friend",
            post(upload_add_friend),
        )
        .route(
            "/api/v1/uploads/{clientId}/operations/remove-friend",
            post(upload_remove_friend),
        )
        .route(
            "/api/v1/uploads/{clientId}/operations/ban",
            post(upload_ban),
        )
        .route(
            "/api/v1/uploads/{clientId}/operations/unban",
            post(upload_unban),
        )
        .route("/api/v1/upload-queue", get(upload_queue))
        .route("/api/v1/upload-queue/{clientId}", get(upload_queue_client))
        .route(
            "/api/v1/upload-queue/{clientId}/operations/remove",
            post(upload_remove),
        )
        .route(
            "/api/v1/upload-queue/{clientId}/operations/release-slot",
            post(upload_release_slot),
        )
        .route(
            "/api/v1/upload-queue/{clientId}/operations/add-friend",
            post(upload_add_friend),
        )
        .route(
            "/api/v1/upload-queue/{clientId}/operations/remove-friend",
            post(upload_remove_friend),
        )
        .route(
            "/api/v1/upload-queue/{clientId}/operations/ban",
            post(upload_ban),
        )
        .route(
            "/api/v1/upload-queue/{clientId}/operations/unban",
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
        .route("/api/v1/logs", get(logs))
        .route("/api/v1/logs/operations/clear", post(clear_logs))
        .route("/api/v1", any(fallback))
        .route("/api/v1/{*path}", any(fallback))
        .layer(middleware::map_response(rewrite_method_not_allowed))
        .layer(middleware::from_fn(validate_route_metadata))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .layer(middleware::map_response(add_contract_version_header))
        .with_state(state);

    mount_webui(api_router, config.web_root_dir)
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

async fn add_contract_version_header(mut response: Response) -> Response {
    response.headers_mut().insert(
        HeaderName::from_static("x-contract-version"),
        HeaderValue::from_static(CONTRACT_VERSION),
    );
    response
}

async fn fallback() -> impl IntoResponse {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "API route not found")
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
