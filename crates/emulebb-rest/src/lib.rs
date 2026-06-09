use std::{collections::BTreeMap, path::Path as FsPath, sync::Arc};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use emulebb_core::{
    EmulebbCore, LocalShare, LocalShareCreate, SearchCreate, SearchResultDownloadCreate,
    ServerCreate, ServerUpdate, SharedDirectoriesUpdate, Transfer, TransferCreate,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct RestConfig {
    pub api_key: String,
}

#[derive(Debug, Clone)]
pub struct RestState {
    core: Arc<EmulebbCore>,
    api_key: Arc<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkOperationResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchResultDownloadResult {
    ok: bool,
    search_id: String,
    hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SharedFileResponse {
    hash: String,
    name: String,
    path: String,
    directory: String,
    size_bytes: u64,
    priority: &'static str,
    auto_upload_priority: bool,
    requests: u64,
    accepted_requests: u64,
    transferred_bytes: u64,
    all_time_requests: u64,
    all_time_accepts: u64,
    all_time_transferred: u64,
    part_count: u32,
    part_file: bool,
    complete: bool,
    comment: String,
    rating: u8,
    has_comment: bool,
    user_rating: u8,
    published_ed2k: bool,
    shared_by_rule: bool,
    ed2k_link: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SharedFileCreateRequest {
    path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SharedFileCreateResult {
    ok: bool,
    path: String,
    already_shared: bool,
    queued: bool,
    file: SharedFileResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Ed2kLinkResult {
    hash: String,
    link: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfirmQuery {
    confirm: Option<bool>,
}

pub fn router(core: Arc<EmulebbCore>, config: RestConfig) -> Router {
    let state = RestState {
        core,
        api_key: Arc::new(config.api_key),
    };
    Router::new()
        .route("/api/v1/app", get(app))
        .route("/api/v1/status", get(status))
        .route("/api/v1/stats", get(status))
        .route("/api/v1/kad", get(kad))
        .route("/api/v1/kad/operations/start", post(kad_start))
        .route("/api/v1/kad/operations/stop", post(kad_stop))
        .route("/api/v1/kad/operations/bootstrap", post(kad_start))
        .route("/api/v1/servers", get(servers).post(create_server))
        .route("/api/v1/servers/operations/connect", post(servers_connect))
        .route(
            "/api/v1/servers/operations/disconnect",
            post(servers_disconnect),
        )
        .route(
            "/api/v1/servers/{server_id}",
            get(server).patch(update_server).delete(delete_server),
        )
        .route(
            "/api/v1/servers/{server_id}/operations/connect",
            post(connect_server),
        )
        .route("/api/v1/searches", get(searches).post(create_search))
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
        .route("/api/v1/shared-files/{hash}", get(shared_file))
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
            "/api/v1/transfers/{hash}",
            get(transfer).delete(transfer_delete),
        )
        .route(
            "/api/v1/transfers/{hash}/files",
            delete(transfer_delete_files),
        )
        .route("/api/v1/transfers/{hash}/details", get(transfer))
        .route("/api/v1/transfers/{hash}/sources", get(transfer_sources))
        .route("/api/v1/uploads", get(uploads))
        .route("/api/v1/uploads/{client_id}", get(upload))
        .route("/api/v1/upload-queue", get(upload_queue))
        .route("/api/v1/upload-queue/{client_id}", get(upload_queue_client))
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
        .route("/api/v1/logs", get(logs))
        .fallback(fallback)
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

async fn app(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.app_info())
}

async fn status(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.status().await)
}

async fn kad(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.status().await.kad)
}

async fn kad_start(State(state): State<RestState>) -> impl IntoResponse {
    state.core.set_kad_running(true).await;
    api_ok(state.core.status().await.kad)
}

async fn kad_stop(State(state): State<RestState>) -> impl IntoResponse {
    state.core.set_kad_running(false).await;
    api_ok(state.core.status().await.kad)
}

async fn servers(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(state.core.servers().await)
}

async fn create_server(
    State(state): State<RestState>,
    Json(request): Json<ServerCreate>,
) -> impl IntoResponse {
    match state.core.add_server(request).await {
        Ok(server) => api_ok(server).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn servers_connect(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.connect_ed2k().await {
        Ok(status) => api_ok(status).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn servers_disconnect(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.disconnect_ed2k().await)
}

async fn server(
    State(state): State<RestState>,
    Path(server_id): Path<String>,
) -> impl IntoResponse {
    match state.core.server(&server_id).await {
        Some(server) => api_ok(server).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response(),
    }
}

async fn update_server(
    State(state): State<RestState>,
    Path(server_id): Path<String>,
    Json(request): Json<ServerUpdate>,
) -> impl IntoResponse {
    match state.core.update_server(&server_id, request).await {
        Ok(Some(server)) => api_ok(server).into_response(),
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
        Ok(Some(server)) => api_ok(server).into_response(),
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
        Ok(Some(status)) => api_ok(status).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn searches(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(state.core.searches().await)
}

async fn create_search(
    State(state): State<RestState>,
    Json(request): Json<SearchCreate>,
) -> impl IntoResponse {
    match state.core.create_search(request).await {
        Ok(search) => api_ok(search).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
) -> impl IntoResponse {
    match state.core.search(&search_id).await {
        Some(search) => api_ok(search).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response(),
    }
}

async fn delete_search(
    State(state): State<RestState>,
    Path(search_id): Path<String>,
) -> impl IntoResponse {
    if state.core.delete_search(&search_id).await {
        api_ok(json!({ "deleted": true })).into_response()
    } else {
        api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "search not found").into_response()
    }
}

async fn shared_files(State(state): State<RestState>) -> impl IntoResponse {
    let items = state
        .core
        .shares()
        .await
        .iter()
        .map(shared_file_response)
        .collect::<Vec<_>>();
    api_collection_page(items)
}

async fn create_shared_file(
    State(state): State<RestState>,
    Json(request): Json<SharedFileCreateRequest>,
) -> impl IntoResponse {
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
    Json(request): Json<SharedDirectoriesUpdate>,
) -> impl IntoResponse {
    match state.core.set_shared_directories(request).await {
        Ok(directories) => api_ok(directories).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn reload_shared_directories(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.reload_shared_directories().await {
        Ok(shares) => api_ok(json!({
            "ok": true,
            "sharedFiles": shares.iter().map(shared_file_response).collect::<Vec<_>>(),
            "count": shares.len()
        }))
        .into_response(),
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

async fn transfers(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(state.core.transfers().await)
}

async fn create_transfer(
    State(state): State<RestState>,
    Json(request): Json<TransferCreate>,
) -> impl IntoResponse {
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

async fn transfer(State(state): State<RestState>, Path(hash): Path<String>) -> impl IntoResponse {
    match state.core.transfer(&hash).await {
        Some(transfer) => api_ok(transfer).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response(),
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

async fn uploads(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(state.core.uploads().await)
}

async fn upload(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    upload_by_client_id(state, client_id, false).await
}

async fn upload_queue(State(state): State<RestState>) -> impl IntoResponse {
    api_collection_page(state.core.upload_queue().await)
}

async fn upload_queue_client(
    State(state): State<RestState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    upload_by_client_id(state, client_id, true).await
}

async fn upload_by_client_id(state: RestState, client_id: String, waiting_queue: bool) -> Response {
    match state.core.upload(&client_id, waiting_queue).await {
        Some(upload) => api_ok(upload).into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "upload queue client not found",
        )
        .into_response(),
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
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
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
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
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
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn transfer_delete_files(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    Query(query): Query<ConfirmQuery>,
) -> impl IntoResponse {
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
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

async fn logs() -> impl IntoResponse {
    api_collection(Vec::<Value>::new())
}

async fn fallback() -> impl IntoResponse {
    api_error(
        StatusCode::NOT_IMPLEMENTED,
        "NOT_IMPLEMENTED",
        "route is outside the current emulebb-rust REST subset",
    )
}

fn api_ok<T: Serialize>(data: T) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "data": data,
            "meta": BTreeMap::<String, Value>::new()
        })),
    )
}

fn api_collection<T: Serialize>(items: Vec<T>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "data": { "items": items },
            "meta": BTreeMap::<String, Value>::new()
        })),
    )
}

fn api_collection_page<T: Serialize>(items: Vec<T>) -> (StatusCode, Json<Value>) {
    let total = items.len();
    (
        StatusCode::OK,
        Json(json!({
            "data": {
                "items": items,
                "total": total,
                "offset": 0,
                "limit": total
            },
            "meta": BTreeMap::<String, Value>::new()
        })),
    )
}

fn api_bulk_operation(items: Vec<BulkOperationResult>) -> (StatusCode, Json<Value>) {
    let total = items.len();
    (
        StatusCode::OK,
        Json(json!({
            "data": {
                "items": items,
                "total": total,
                "offset": 0,
                "limit": total
            },
            "meta": BTreeMap::<String, Value>::new()
        })),
    )
}

fn shared_file_response(share: &LocalShare) -> SharedFileResponse {
    let path = managed_shared_file_path(share);
    SharedFileResponse {
        hash: share.hash.clone(),
        name: share.name.clone(),
        directory: shared_file_directory(&path),
        path,
        size_bytes: share.size_bytes,
        priority: "normal",
        auto_upload_priority: false,
        requests: 0,
        accepted_requests: 0,
        transferred_bytes: 0,
        all_time_requests: 0,
        all_time_accepts: 0,
        all_time_transferred: 0,
        part_count: share.part_count,
        part_file: false,
        complete: true,
        comment: String::new(),
        rating: 0,
        has_comment: false,
        user_rating: 0,
        published_ed2k: true,
        shared_by_rule: false,
        ed2k_link: share.ed2k_link.clone(),
    }
}

fn managed_shared_file_path(share: &LocalShare) -> String {
    let path = FsPath::new(&share.transfer_dir);
    if path.is_dir() {
        path.join("pieces.bin").display().to_string()
    } else {
        share.transfer_dir.clone()
    }
}

fn shared_file_directory(path: &str) -> String {
    FsPath::new(path)
        .parent()
        .map(|directory| directory.display().to_string())
        .unwrap_or_default()
}

fn bulk_result_from_transfer(transfer: &Transfer) -> BulkOperationResult {
    BulkOperationResult {
        ok: true,
        id: None,
        hash: Some(transfer.hash.clone()),
        name: Some(transfer.name.clone()),
        error: None,
    }
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message.into()
            },
            "meta": BTreeMap::<String, Value>::new()
        })),
    )
}

fn optional_json_body<T>(body: &[u8]) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned + Default,
{
    if body.is_empty() {
        Ok(T::default())
    } else {
        serde_json::from_slice(body)
    }
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

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emulebb-rest-{name}-{}-{stamp}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test dir");
        path
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
        assert_eq!(value["data"]["name"], "eMuleBB Rust");
        assert!(
            value["data"]["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry == "rest.emulebb.v1")
        );
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

        let response = app
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
        assert_eq!(value["data"]["endpoint"], "192.0.2.20:4661");
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
        assert_eq!(value["data"]["results"].as_array().unwrap().len(), 1);

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
    async fn create_transfers_accepts_canonical_links_array() {
        let app = test_router();
        let response = app
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
}
