use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use emulebb_core::{
    EmulebbCore, LocalShareCreate, SearchCreate, SearchResultDownloadCreate, Transfer,
    TransferCreate,
};
use serde::{Serialize, de::DeserializeOwned};
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
        .route("/api/v1/servers", get(servers))
        .route("/api/v1/servers/operations/connect", post(servers_connect))
        .route(
            "/api/v1/servers/operations/disconnect",
            post(servers_disconnect),
        )
        .route("/api/v1/searches", get(searches).post(create_search))
        .route(
            "/api/v1/searches/{search_id}",
            get(search).delete(delete_search),
        )
        .route("/api/v1/shares", get(shares).post(create_share))
        .route(
            "/api/v1/searches/{search_id}/results/{hash}/operations/download",
            post(download_search_result),
        )
        .route("/api/v1/transfers", get(transfers).post(create_transfer))
        .route("/api/v1/transfers/{hash}", get(transfer))
        .route("/api/v1/transfers/{hash}/details", get(transfer))
        .route("/api/v1/transfers/{hash}/sources", get(transfer_sources))
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

async fn shares(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(state.core.shares().await)
}

async fn create_share(
    State(state): State<RestState>,
    Json(request): Json<LocalShareCreate>,
) -> impl IntoResponse {
    match state.core.share_local_file(request).await {
        Ok(share) => api_ok(share).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
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

async fn logs() -> impl IntoResponse {
    api_collection(Vec::<Value>::new())
}

async fn fallback() -> impl IntoResponse {
    api_error(
        StatusCode::NOT_IMPLEMENTED,
        "NOT_IMPLEMENTED",
        "route is outside the emulebb-rust MVP REST subset",
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
}
