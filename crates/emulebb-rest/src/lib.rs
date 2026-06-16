use std::sync::Arc;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, RawQuery, State},
    http::{HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use emulebb_core::{
    EmulebbCore, LocalShareCreate, SearchCreate, SearchResultDownloadCreate, ServerCreate,
    ServerUpdate, SharedDirectoriesUpdate, SharedFileUpdate, TransferCreate, TransferUpdate,
};
use serde_json::{Value, json};
use tokio::sync::watch;

mod log_buffer;
pub use log_buffer::record_log;

mod dto;
use dto::*;

mod envelope;
use envelope::*;

mod handlers;
use handlers::*;

mod responses;
use responses::*;

#[derive(Debug, Clone)]
pub struct RestConfig {
    pub api_key: String,
}

#[derive(Debug, Clone)]
pub struct RestState {
    core: Arc<EmulebbCore>,
    api_key: Arc<String>,
    shutdown: Option<watch::Sender<bool>>,
}

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

async fn servers(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(server_responses(state.core.servers().await))
}

async fn create_server(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
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

async fn servers_connect(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.connect_ed2k().await {
        Ok(_status) => api_ok(server_status_response(&state).await).into_response(),
        Err(_error) => api_ok(server_status_response(&state).await).into_response(),
    }
}

async fn servers_disconnect(State(state): State<RestState>) -> impl IntoResponse {
    state.core.disconnect_ed2k().await;
    api_ok(server_status_response(&state).await)
}

async fn servers_import_met_url(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
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

async fn server(
    State(state): State<RestState>,
    Path(server_id): Path<String>,
) -> impl IntoResponse {
    match state.core.server(&server_id).await {
        Some(server) => api_ok(server_response(&server)).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response(),
    }
}

async fn update_server(
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

async fn delete_server(
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

async fn connect_server(
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

async fn searches(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(
        state
            .core
            .searches()
            .await
            .iter()
            .map(search_session_response)
            .collect::<Vec<_>>(),
    )
}

async fn create_search(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<SearchCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.create_search(request).await {
        Ok(search) => api_ok(search_response(&search)).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<SearchResultsQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    match state.core.search(&search_id).await {
        Some(search) => match search_results_page(search, query) {
            Ok(page) => api_ok(search_page_response(&page)).into_response(),
            Err(response) => *response,
        },
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response(),
    }
}

async fn delete_search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
) -> impl IntoResponse {
    match state.core.delete_search(&search_id).await {
        Ok(true) => api_ok(json!({ "deleted": true })).into_response(),
        Ok(false) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response()
        }
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &error.to_string(),
        )
        .into_response(),
    }
}

async fn delete_searches(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<ConfirmQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    if query.confirm != Some(true) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "confirm must be true",
        )
        .into_response();
    }
    match state.core.clear_searches().await {
        Ok(()) => api_ok(json!({ "ok": true })).into_response(),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &error.to_string(),
        )
        .into_response(),
    }
}

async fn shared_files(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<PageQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let items = state
        .core
        .shares()
        .await
        .iter()
        .map(shared_file_response)
        .collect::<Vec<_>>();
    api_collection_page(items, query).into_response()
}

async fn create_shared_file(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedFileCreateRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if request.path.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "path is required")
            .into_response();
    }
    let path = request.path;
    match state
        .core
        .share_local_file(LocalShareCreate {
            path: path.clone(),
            name: None,
        })
        .await
    {
        Ok(share) => api_ok(SharedFileCreateResult {
            ok: true,
            path,
            already_shared: false,
            queued: false,
            file: shared_file_response(&share),
        })
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn shared_directories(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.shared_directories().await)
}

async fn update_shared_directories(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedDirectoriesUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.set_shared_directories(request).await {
        Ok(directories) => api_ok(directories).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn reload_shared_directories(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.reload_shared_directories().await {
        Ok(_shares) => api_ok(json!({ "ok": true })).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn shared_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.share(&hash).await {
        Some(share) => api_ok(shared_file_response(&share)).into_response(),
        None => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
    }
}

async fn update_shared_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<SharedFileUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_shared_file(&hash, request).await {
        Ok(Some(share)) => api_ok(shared_file_response(&share)).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn delete_shared_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let Some(share) = state.core.share(&hash).await else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found")
            .into_response();
    };
    let path = managed_shared_file_path(&share);
    match state.core.unshare_file(&hash).await {
        Ok(Some(_share)) => api_ok(SharedFileRemoveResult {
            ok: true,
            deleted_files: false,
            path,
            hash: share.hash,
        })
        .into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn delete_shared_file_payload(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<ConfirmQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    if query.confirm != Some(true) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "shared file deletion requires confirm=true",
        )
        .into_response();
    }
    let Some(share) = state.core.share(&hash).await else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found")
            .into_response();
    };
    let path = managed_shared_file_path(&share);
    match state.core.delete_transfer_files(&hash).await {
        Ok(Some(_transfer)) => api_ok(SharedFileRemoveResult {
            ok: true,
            deleted_files: true,
            path,
            hash: share.hash,
        })
        .into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn shared_file_comments(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.share(&hash).await {
        Some(share) => {
            let items = if share.comment.is_empty() && share.rating == 0 {
                Vec::<Value>::new()
            } else {
                vec![json!({
                    "source": "local",
                    "userName": null,
                    "fileName": share.name,
                    "comment": share.comment,
                    "rating": share.rating
                })]
            };
            api_collection(items).into_response()
        }
        None => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
    }
}

async fn shared_file_ed2k_link(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.share(&hash).await {
        Some(share) => api_ok(Ed2kLinkResult {
            hash: share.hash,
            link: share.ed2k_link,
        })
        .into_response(),
        None => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "shared file not found").into_response()
        }
    }
}

async fn download_search_result(
    State(state): State<RestState>,
    Path((search_id, hash)): Path<(String, String)>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match optional_json_body::<SearchResultDownloadCreate>(&body) {
        Ok(request) => request,
        Err(error) => {
            return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string())
                .into_response();
        }
    };
    match state
        .core
        .download_search_result(&search_id, &hash, request)
        .await
    {
        Ok(Some(_transfer)) => api_ok(SearchResultDownloadResult {
            ok: true,
            search_id,
            hash,
        })
        .into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "search result not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfers(
    State(state): State<RestState>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<TransfersQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let items = state
        .core
        .transfers()
        .await
        .into_iter()
        .filter(|transfer| {
            query
                .state
                .as_deref()
                .is_none_or(|state| transfer.state == state)
        })
        .filter(|transfer| {
            query
                .category_id
                .is_none_or(|category_id| transfer.category_id == category_id)
        })
        .collect::<Vec<_>>();
    api_collection_page(items, query.page()).into_response()
}

async fn create_transfer(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<TransferCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.create_transfers(request).await {
        Ok(transfers) => api_bulk_operation(
            transfers
                .iter()
                .map(bulk_result_from_transfer)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn clear_completed_transfers(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<ClearCompletedTransfersRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !request.confirm_clear_completed {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "confirmClearCompleted must be true",
        )
        .into_response();
    }
    match state.core.clear_completed_transfer_rows().await {
        Ok(()) => api_ok(json!({ "ok": true })).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer(State(state): State<RestState>, Path(hash): Path<String>) -> impl IntoResponse {
    match state.core.transfer(&hash).await {
        Some(transfer) => api_ok(transfer).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response(),
    }
}

async fn transfer_details(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.transfer_details(&hash).await {
        Ok(Some(details)) => api_ok(details).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMULE_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

async fn update_transfer(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<TransferUpdate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.update_transfer(&hash, request).await {
        Ok(Some(transfer)) => api_ok(transfer).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_sources(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.transfer_sources(&hash).await {
        Ok(Some(sources)) => api_collection(sources).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.transfer_source(&hash, &client_id).await {
        Ok(Some(source)) => api_ok(source).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source_browse(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.browse_transfer_source(&hash, &client_id).await {
        Ok(true) => {
            api_ok(json!({"ok": true, "alreadyPending": false, "searchId": null})).into_response()
        }
        Ok(false) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source_add_friend(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state
        .core
        .add_transfer_source_friend(&hash, &client_id)
        .await
    {
        Ok(Some(friend)) => api_ok(friend).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source_remove_friend(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state
        .core
        .remove_transfer_source_friend(&hash, &client_id)
        .await
    {
        Ok(Some(_friend)) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "friend not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source_remove(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.remove_transfer_source(&hash, &client_id).await {
        Ok(Some(())) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source_ban(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.ban_transfer_source(&hash, &client_id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source_unban(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.unban_transfer_source(&hash, &client_id).await {
        Ok(Some(banned)) => api_ok(json!({"ok": true, "banned": banned})).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_source_release_slot(
    State(state): State<RestState>,
    Path((hash, client_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.transfer_source(&hash, &client_id).await {
        Ok(Some(_source)) => api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "client does not currently hold an upload slot",
        )
        .into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "transfer source not found",
        )
        .into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_pause(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.pause_transfer(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_resume(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.resume_transfer(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_stop(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.stop_transfer(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_recheck(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.recheck_transfer(&hash).await {
        Ok(Some(())) => api_ok(json!({"ok": true})).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_preview(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.preview_transfer(&hash).await {
        Ok(Some(transfer)) => api_ok(transfer).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_delete(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.core.delete_completed_transfer_row(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_delete_files(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let query = match parse_optional_query::<ConfirmQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    if query.confirm != Some(true) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "transfer file deletion requires confirm=true",
        )
        .into_response();
    }
    match state.core.delete_transfer_files(&hash).await {
        Ok(Some(transfer)) => {
            api_bulk_operation(vec![bulk_result_from_transfer(&transfer)]).into_response()
        }
        Ok(None) => api_bulk_operation(vec![bulk_result_from_hash(&hash)]).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
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

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use emulebb_index::{FileIndex, IndexedFile};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    fn test_router() -> Router {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        router(
            core,
            RestConfig {
                api_key: "secret".to_string(),
            },
        )
    }

    async fn assert_invalid_json_response(
        app: Router,
        method: &str,
        uri: &str,
        body: &'static str,
        expected_message: &str,
    ) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], expected_message);
    }

    async fn assert_invalid_query_response(app: Router, method: &str, uri: &str) {
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(
            value["error"]["message"],
            "unknown JSON field: unsupportedQuery"
        );
    }

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = rust_test_tmp_root().join(format!(
            "emulebb-rest-{name}-{}-{stamp}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test dir");
        path
    }

    fn rust_test_tmp_root() -> std::path::PathBuf {
        std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
            .map(std::path::PathBuf::from)
            .map(|root| root.join("tmp").join("emulebb-rust-tests"))
            .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
    }

    #[tokio::test]
    async fn write_routes_use_canonical_json_error_envelope() {
        let cases = [
            ("POST", "/api/v1/app/shutdown"),
            ("POST", "/api/v1/diagnostics/dumps"),
            ("POST", "/api/v1/diagnostics/crash-tests"),
            ("POST", "/api/v1/categories"),
            ("PATCH", "/api/v1/categories/1"),
            ("POST", "/api/v1/friends"),
            ("POST", "/api/v1/servers"),
            ("PATCH", "/api/v1/servers/local:4661"),
            ("POST", "/api/v1/searches"),
            ("PATCH", "/api/v1/shared-directories"),
            (
                "PATCH",
                "/api/v1/shared-files/00112233445566778899aabbccddeeff",
            ),
            ("POST", "/api/v1/transfers"),
            ("POST", "/api/v1/transfers/operations/clear-completed"),
            (
                "PATCH",
                "/api/v1/transfers/00112233445566778899aabbccddeeff",
            ),
            ("POST", "/api/v1/logs/operations/clear"),
        ];
        for (method, uri) in cases {
            assert_invalid_json_response(
                test_router(),
                method,
                uri,
                r#"{"unsupportedJsonField":true}"#,
                "unknown JSON field: unsupportedJsonField",
            )
            .await;
        }
    }

    #[tokio::test]
    async fn malformed_json_uses_canonical_error_envelope() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert!(value["error"]["message"].as_str().unwrap().contains("EOF"));
    }

    #[tokio::test]
    async fn query_routes_use_canonical_error_envelope() {
        let cases = [
            ("GET", "/api/v1/snapshot?unsupportedQuery=true"),
            ("GET", "/api/v1/searches/search-1?unsupportedQuery=true"),
            ("DELETE", "/api/v1/searches?unsupportedQuery=true"),
            ("GET", "/api/v1/shared-files?unsupportedQuery=true"),
            (
                "DELETE",
                "/api/v1/shared-files/00112233445566778899aabbccddeeff/file?unsupportedQuery=true",
            ),
            ("GET", "/api/v1/transfers?unsupportedQuery=true"),
            ("GET", "/api/v1/upload-queue?unsupportedQuery=true"),
            (
                "DELETE",
                "/api/v1/transfers/00112233445566778899aabbccddeeff/files?unsupportedQuery=true",
            ),
        ];
        for (method, uri) in cases {
            assert_invalid_query_response(test_router(), method, uri).await;
        }
    }

    #[tokio::test]
    async fn rejects_missing_api_key() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/app")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "UNAUTHORIZED");
        assert_eq!(value["error"]["details"], json!({}));
    }

    #[tokio::test]
    async fn method_not_allowed_sets_allow_header_and_error_envelope() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/app")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        // The Allow header must advertise the method registered for this path.
        let allow = response
            .headers()
            .get(header::ALLOW)
            .expect("405 must carry an Allow header")
            .to_str()
            .unwrap()
            .to_string();
        assert!(allow.contains("GET"), "Allow header was {allow}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "METHOD_NOT_ALLOWED");
        assert_eq!(
            value["error"]["message"],
            "HTTP method is not allowed for this API route"
        );
        assert_eq!(value["error"]["details"], json!({}));
    }

    #[tokio::test]
    async fn pagination_rejects_out_of_range_bounds_with_details() {
        async fn error_value(uri: &str) -> (StatusCode, Value) {
            let response = test_router()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("X-API-Key", "secret")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice(&body).unwrap())
        }

        // limit above the maximum.
        let (status, value) = error_value("/api/v1/transfers?limit=5000").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], "limit is out of range");
        assert_eq!(value["error"]["details"]["field"], "limit");
        assert_eq!(value["error"]["details"]["constraint"], "1..1000");

        // limit below the minimum is rejected, not clamped.
        let (status, value) = error_value("/api/v1/transfers?limit=0").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"]["details"]["constraint"], "1..1000");

        // offset above INT_MAX.
        let (status, value) = error_value("/api/v1/transfers?offset=2147483648").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"]["message"], "offset is out of range");
        assert_eq!(value["error"]["details"]["field"], "offset");
        assert_eq!(value["error"]["details"]["constraint"], "0..2147483647");

        // Valid pagination succeeds.
        let (status, _value) = error_value("/api/v1/transfers?limit=10&offset=5").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn app_returns_evelope_with_capabilities() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/app")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["meta"]["apiVersion"], "v1");
        assert_eq!(value["data"]["name"], "eMuleBB Rust");
        assert_eq!(value["data"]["capabilities"]["rest.emulebb.v1"], true);
    }

    #[tokio::test]
    async fn app_shutdown_requires_confirmation_and_signals_daemon() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let app = router_with_shutdown(
            core,
            RestConfig {
                api_key: "secret".to_string(),
            },
            Some(shutdown_tx),
        );

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/app/shutdown")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmShutdown":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
        assert!(!*shutdown_rx.borrow());

        let accepted = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/app/shutdown")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmShutdown":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let body = to_bytes(accepted.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);
        assert!(shutdown_rx.changed().await.is_ok());
        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn diagnostic_dump_uses_canonical_route_and_confirmation() {
        let runtime_dir = unique_test_dir("diagnostic-dump");
        let transfer_root = runtime_dir.join("transfers");
        let core = Arc::new(
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
        );
        let app = router(
            core,
            RestConfig {
                api_key: "secret".to_string(),
            },
        );

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/diagnostics/dumps")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmDump":false,"fullMemory":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

        let accepted = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/diagnostics/dumps")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmDump":true,"fullMemory":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let body = to_bytes(accepted.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);
        assert_eq!(value["data"]["fullMemory"], false);
        assert_eq!(value["data"]["kind"], "json");
        let path = value["data"]["path"].as_str().unwrap();
        assert!(std::path::Path::new(path).is_file());
        assert_eq!(
            value["data"]["sizeBytes"].as_u64().unwrap(),
            std::fs::metadata(path).unwrap().len()
        );
    }

    #[tokio::test]
    async fn diagnostic_crash_test_requires_confirmation() {
        let denied = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/diagnostics/crash-tests")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmCrash":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn preferences_use_canonical_get_and_patch_route() {
        let app = test_router();
        let read = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/app/preferences")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        let body = to_bytes(read.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["uploadLimitKiBps"], 1024);
        assert_eq!(value["data"]["downloadAutoBroadbandIo"], true);

        let update = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/app/preferences")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"uploadLimitKiBps":2048,"uploadClientDataRate":64,"maxUploadSlots":4,"queueSize":3000,"networkEd2k":false,"downloadAutoBroadbandIo":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        let body = to_bytes(update.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["uploadLimitKiBps"], 2048);
        assert_eq!(value["data"]["uploadClientDataRate"], 64);
        assert_eq!(value["data"]["maxUploadSlots"], 4);
        assert_eq!(value["data"]["queueSize"], 3000);
        assert_eq!(value["data"]["networkEd2k"], false);
        assert_eq!(value["data"]["downloadAutoBroadbandIo"], false);

        let empty_patch = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/app/preferences")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(empty_patch.status(), StatusCode::BAD_REQUEST);

        let unknown_key = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/app/preferences")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"unsupportedPreference":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown_key.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(unknown_key.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(
            value["error"]["message"],
            "unknown JSON field: unsupportedPreference"
        );

        let invalid_range = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/app/preferences")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"queueSize":1999}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_range.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn snapshot_returns_bounded_emulebb_polling_shape() {
        let runtime_dir = unique_test_dir("snapshot");
        let transfer_root = runtime_dir.join("transfers");
        let first_file = runtime_dir.join("First.Snapshot.bin");
        let second_file = runtime_dir.join("Second.Snapshot.bin");
        std::fs::write(&first_file, b"first snapshot payload").unwrap();
        std::fs::write(&second_file, b"second snapshot payload").unwrap();
        let core = Arc::new(
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
        );
        core.share_local_file(LocalShareCreate {
            path: first_file.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
        core.share_local_file(LocalShareCreate {
            path: second_file.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
        core.add_server(ServerCreate {
            address: "192.0.2.20".to_string(),
            port: 4661,
            name: Some("snapshot-server".to_string()),
            priority: None,
            static_server: Some(true),
            connect: None,
        })
        .await
        .unwrap();
        let app = router(
            core,
            RestConfig {
                api_key: "secret".to_string(),
            },
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/snapshot?limit=1")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        let data = &value["data"];
        assert_eq!(data["app"]["name"], "eMuleBB Rust");
        assert_eq!(data["status"]["lifecycle"]["state"], "running");
        assert_eq!(data["transfers"].as_array().unwrap().len(), 1);
        assert_eq!(data["sharedFiles"].as_array().unwrap().len(), 1);
        assert_eq!(data["servers"].as_array().unwrap().len(), 1);
        assert_eq!(data["uploads"].as_array().unwrap().len(), 0);
        assert_eq!(data["uploadQueue"].as_array().unwrap().len(), 0);
        assert!(data["kad"].is_object());
        assert!(data["network"]["ports"].is_object());
        assert!(data["network"]["binding"].is_object());
        assert!(data["network"]["vpnGuard"].is_object());
        assert_eq!(data["logs"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn logs_clear_requires_canonical_confirmation() {
        let app = test_router();

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/logs/operations/clear")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmClearLogs":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

        let cleared = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/logs/operations/clear")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmClearLogs":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cleared.status(), StatusCode::OK);
        let body = to_bytes(cleared.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);
    }

    #[tokio::test]
    async fn uploads_and_upload_queue_use_canonical_envelopes() {
        let app = test_router();
        for path in ["/api/v1/uploads", "/api/v1/upload-queue"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("X-API-Key", "secret")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);
        }

        let paged_queue = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/upload-queue?offset=1&limit=1&includeScoreBreakdown=true")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paged_queue.status(), StatusCode::OK);
        let body = to_bytes(paged_queue.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["total"], 0);
        assert_eq!(value["data"]["offset"], 1);
        assert_eq!(value["data"]["limit"], 1);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/upload-queue/unknown")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        for path in [
            "/api/v1/uploads/unknown/operations/remove",
            "/api/v1/uploads/unknown/operations/release-slot",
            "/api/v1/uploads/unknown/operations/add-friend",
            "/api/v1/uploads/unknown/operations/remove-friend",
            "/api/v1/uploads/unknown/operations/ban",
            "/api/v1/uploads/unknown/operations/unban",
            "/api/v1/upload-queue/unknown/operations/remove",
            "/api/v1/upload-queue/unknown/operations/release-slot",
            "/api/v1/upload-queue/unknown/operations/add-friend",
            "/api/v1/upload-queue/unknown/operations/remove-friend",
            "/api/v1/upload-queue/unknown/operations/ban",
            "/api/v1/upload-queue/unknown/operations/unban",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("X-API-Key", "secret")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn servers_use_canonical_crud_routes() {
        let app = test_router();
        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/servers")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"address":"192.0.2.20","port":4661,"name":"local","priority":"low","static":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(value["data"].get("endpoint").is_none());
        assert_eq!(value["data"]["address"], "192.0.2.20");
        assert_eq!(value["data"]["port"], 4661);
        assert_eq!(value["data"]["priority"], "low");
        assert_eq!(value["data"]["static"], true);

        let update = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/servers/192.0.2.20:4661")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"renamed","priority":"high"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        let body = to_bytes(update.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["name"], "renamed");
        assert_eq!(value["data"]["priority"], "high");

        let delete = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/servers/192.0.2.20:4661")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::OK);

        let missing = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/servers/192.0.2.20:4661")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn categories_use_canonical_crud_routes() {
        let runtime_dir = unique_test_dir("categories");
        let app = test_router();

        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/categories")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"][0]["id"], 0);

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/categories")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":" Media ","path":"{}","comment":"queue","color":65280,"priority":"high"}}"#,
                        runtime_dir.display().to_string().replace('\\', "\\\\")
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["id"], 1);
        assert_eq!(value["data"]["name"], "Media");
        assert_eq!(value["data"]["priority"], 2);
        assert_eq!(value["data"]["color"], 65280);

        let update = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/categories/1")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"name":"Archive","path":null,"color":null,"priority":"verylow"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        let body = to_bytes(update.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["name"], "Archive");
        assert_eq!(value["data"]["path"], Value::Null);
        assert_eq!(value["data"]["color"], Value::Null);
        assert_eq!(value["data"]["priority"], 4);

        let protected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/categories/0")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(protected.status(), StatusCode::BAD_REQUEST);

        let delete = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/categories/1")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::OK);

        let missing = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/categories/1")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn friends_use_canonical_crud_routes() {
        let app = test_router();
        let user_hash = "00112233445566778899aabbccddeeff";

        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/friends")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/friends")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"userHash":"{user_hash}","name":"Harness Peer"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["userHash"], user_hash);
        assert_eq!(value["data"]["name"], "Harness Peer");
        assert_eq!(value["data"]["lastSeen"], Value::Null);
        assert_eq!(value["data"]["address"], Value::Null);
        assert_eq!(value["data"]["port"], 0);

        let duplicate = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/friends")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"userHash":"{user_hash}","name":"Ignored Rename"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        let body = to_bytes(duplicate.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["name"], "Harness Peer");

        let invalid = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/friends")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"userHash":"00112233445566778899AABBCCDDEEFF"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        let delete = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/friends/{user_hash}"))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::OK);

        let missing = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/friends/{user_hash}"))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn search_clear_requires_canonical_query_confirmation() {
        let app = test_router();

        for query in ["first", "second"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/searches")
                        .header("X-API-Key", "secret")
                        .header("Content-Type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"query":"{query}","method":"automatic","type":""}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/searches")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

        let cleared = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/searches?confirm=true")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cleared.status(), StatusCode::OK);
        let body = to_bytes(cleared.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);

        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/searches")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn search_results_use_canonical_paging_query() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        core.index_file(IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Paged.Result.One.iso".to_string(),
            size_bytes: 42,
            content_type: "iso".to_string(),
            availability_score: 2,
        })
        .await
        .unwrap();
        core.index_file(IndexedFile {
            ed2k_hash: "ffeeddccbbaa99887766554433221100".to_string(),
            name: "Paged.Result.Two.iso".to_string(),
            size_bytes: 84,
            content_type: "iso".to_string(),
            availability_score: 3,
        })
        .await
        .unwrap();
        let app = router(
            core,
            RestConfig {
                api_key: "secret".to_string(),
            },
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/searches")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"query":"paged result","method":"automatic","type":""}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        let search_id = value["data"]["id"].as_str().unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/searches/{search_id}?offset=1&limit=1&includeEvidence=false&exactTotal=true"
                    ))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["id"], search_id);
        // The eMuleBB master returns paged search results under "items" with
        // total/offset/limit (search/results shares the common page shape).
        assert_eq!(value["data"]["total"], 2);
        assert_eq!(value["data"]["offset"], 1);
        assert_eq!(value["data"]["limit"], 1);
        assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);

        // An out-of-range limit is rejected (matching the emulebb master), not
        // silently clamped, and carries field/constraint details.
        let rejected = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/searches/{search_id}?limit=5000"))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(rejected.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], "limit is out of range");
        assert_eq!(value["error"]["details"]["field"], "limit");
        assert_eq!(value["error"]["details"]["constraint"], "1..1000");
    }

    #[tokio::test]
    async fn search_to_download_flow_uses_local_index() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        core.index_file(IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Indexed.Result.iso".to_string(),
            size_bytes: 42,
            content_type: "iso".to_string(),
            availability_score: 2,
        })
        .await
        .unwrap();
        let app = router(
            core,
            RestConfig {
                api_key: "secret".to_string(),
            },
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/searches")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"query":"indexed result","method":"automatic","type":""}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        let search_id = value["data"]["id"].as_str().unwrap();
        // search/start returns an empty first page; the seeded index result is
        // still recorded on the search and downloadable by hash.
        assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);

        let download_uri = format!(
            "/api/v1/searches/{search_id}/results/00112233445566778899aabbccddeeff/operations/download"
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(download_uri)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);
        assert_eq!(value["data"]["searchId"], search_id);
        assert_eq!(value["data"]["hash"], "00112233445566778899aabbccddeeff");
    }

    #[tokio::test]
    async fn search_result_download_accepts_paused_request_body() {
        let core =
            Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
        core.index_file(IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Paused.Indexed.Result.iso".to_string(),
            size_bytes: 42,
            content_type: "iso".to_string(),
            availability_score: 2,
        })
        .await
        .unwrap();
        let app = router(
            core,
            RestConfig {
                api_key: "secret".to_string(),
            },
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/searches")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"query":"paused indexed","method":"automatic","type":""}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        let search_id = value["data"]["id"].as_str().unwrap();

        let download_uri = format!(
            "/api/v1/searches/{search_id}/results/00112233445566778899aabbccddeeff/operations/download"
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(download_uri)
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"paused":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);
        assert_eq!(value["data"]["searchId"], search_id);
        assert_eq!(value["data"]["hash"], "00112233445566778899aabbccddeeff");
    }

    #[tokio::test]
    async fn stopped_transfer_resume_returns_bad_request() {
        let app = test_router();
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"link":"ed2k://|file|Stopped.bin|4096|00112233445566778899aabbccddeeff|/"}"#,
                    ))
                    .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);
        let body = to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"][0]["ok"], true);
        assert_eq!(
            value["data"]["items"][0]["hash"],
            "00112233445566778899aabbccddeeff"
        );

        let recheck_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/operations/recheck")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recheck_response.status(), StatusCode::OK);
        let body = to_bytes(recheck_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);

        let preview_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/operations/preview")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preview_response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(preview_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["error"]["message"],
            "transfer is not ready for preview"
        );

        let stop_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/operations/stop")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stop_response.status(), StatusCode::OK);

        let resume_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/operations/resume")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resume_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn transfer_patch_uses_canonical_update_families() {
        let app = test_router();
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"link":"ed2k://|file|Patch.Me.bin|4096|00112233445566778899aabbccddeeff|/"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);

        let created_category = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/categories")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":"Media"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created_category.status(), StatusCode::OK);

        let priority_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"priority":"veryhigh"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(priority_response.status(), StatusCode::OK);
        let body = to_bytes(priority_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["priority"], "veryhigh");

        let category_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"categoryName":"media"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(category_response.status(), StatusCode::OK);
        let body = to_bytes(category_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["categoryId"], 1);
        assert_eq!(value["data"]["categoryName"], "Media");

        let rename_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"name":" Renamed.bin "}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rename_response.status(), StatusCode::OK);
        let body = to_bytes(rename_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["name"], "Renamed.bin");
        assert_eq!(value["data"]["priority"], "veryhigh");
        assert_eq!(value["data"]["categoryId"], 1);

        let multi_family_response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"priority":"high","name":"Nope.bin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(multi_family_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_transfers_accepts_canonical_links_array() {
        let app = test_router();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"links":["ed2k://|file|One.bin|1|00112233445566778899aabbccddeeff|/","ed2k://|file|Two.bin|2|ffeeddccbbaa99887766554433221100|/"],"paused":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["total"], 2);
        assert_eq!(value["data"]["items"][0]["ok"], true);
        assert_eq!(value["data"]["items"][1]["ok"], true);
        assert_eq!(
            value["data"]["items"][0]["hash"],
            "00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            value["data"]["items"][1]["hash"],
            "ffeeddccbbaa99887766554433221100"
        );

        let paged = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/transfers?state=paused&offset=1&limit=1")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paged.status(), StatusCode::OK);
        let body = to_bytes(paged.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["total"], 2);
        assert_eq!(value["data"]["offset"], 1);
        assert_eq!(value["data"]["limit"], 1);
        assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);
        assert_eq!(value["data"]["items"][0]["state"], "paused");
    }

    #[tokio::test]
    async fn delete_transfer_files_requires_confirm_and_removes_transfer() {
        let app = test_router();
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"link":"ed2k://|file|Delete.Me.bin|4096|00112233445566778899aabbccddeeff|/"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);

        let missing_confirm = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/files")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_confirm.status(), StatusCode::BAD_REQUEST);

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/files?confirm=true")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_response.status(), StatusCode::OK);
        let body = to_bytes(delete_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"][0]["ok"], true);
        assert_eq!(
            value["data"]["items"][0]["hash"],
            "00112233445566778899aabbccddeeff"
        );

        let read_after_delete = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_after_delete.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_completed_transfer_row_preserves_files() {
        let runtime_dir = unique_test_dir("delete-completed-transfer-row");
        let transfer_root = runtime_dir.join("transfers");
        let payload_path = runtime_dir.join("Completed.Rest.Row.bin");
        std::fs::write(&payload_path, b"completed rest row payload").unwrap();
        let core = Arc::new(
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
        );
        let share = core
            .share_local_file(LocalShareCreate {
                path: payload_path.display().to_string(),
                name: Some("Completed.Rest.Row.bin".to_string()),
            })
            .await
            .unwrap();
        let app = router(
            Arc::clone(&core),
            RestConfig {
                api_key: "secret".to_string(),
            },
        );

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/transfers/{}", share.hash))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_response.status(), StatusCode::OK);
        let body = to_bytes(delete_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"][0]["ok"], true);
        assert_eq!(value["data"]["items"][0]["hash"], share.hash);
        assert!(std::path::Path::new(&share.transfer_dir).is_dir());

        let read_after_delete = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/transfers/{}", share.hash))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_after_delete.status(), StatusCode::NOT_FOUND);
        assert!(
            core.shares()
                .await
                .iter()
                .any(|entry| entry.hash == share.hash)
        );
    }

    #[tokio::test]
    async fn clear_completed_transfers_requires_confirmation_and_preserves_files() {
        let runtime_dir = unique_test_dir("clear-completed-transfers");
        let transfer_root = runtime_dir.join("transfers");
        let first_path = runtime_dir.join("Completed.Rest.Clear.One.bin");
        let second_path = runtime_dir.join("Completed.Rest.Clear.Two.bin");
        std::fs::write(&first_path, b"completed clear row one").unwrap();
        std::fs::write(&second_path, b"completed clear row two").unwrap();
        let core = Arc::new(
            EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
        );
        let first = core
            .share_local_file(LocalShareCreate {
                path: first_path.display().to_string(),
                name: None,
            })
            .await
            .unwrap();
        let second = core
            .share_local_file(LocalShareCreate {
                path: second_path.display().to_string(),
                name: None,
            })
            .await
            .unwrap();
        let app = router(
            Arc::clone(&core),
            RestConfig {
                api_key: "secret".to_string(),
            },
        );

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers/operations/clear-completed")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmClearCompleted":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

        let cleared = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transfers/operations/clear-completed")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"confirmClearCompleted":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cleared.status(), StatusCode::OK);
        let body = to_bytes(cleared.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["ok"], true);

        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/transfers")
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);
        assert!(std::path::Path::new(&first.transfer_dir).is_dir());
        assert!(std::path::Path::new(&second.transfer_dir).is_dir());
        assert_eq!(core.shares().await.len(), 2);

        let delete_shared_file = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v1/shared-files/{}/file?confirm=true",
                        first.hash
                    ))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_shared_file.status(), StatusCode::OK);
        assert!(!std::path::Path::new(&first.transfer_dir).exists());
    }
}
