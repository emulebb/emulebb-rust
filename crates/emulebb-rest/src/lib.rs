use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use emulebb_core::{EmulebbCore, SearchCreate, TransferCreate};
use serde::Serialize;
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

async fn servers() -> impl IntoResponse {
    api_collection(Vec::<Value>::new())
}

async fn servers_connect(State(state): State<RestState>) -> impl IntoResponse {
    state.core.set_ed2k_connected(true).await;
    api_ok(json!({ "connected": true }))
}

async fn servers_disconnect(State(state): State<RestState>) -> impl IntoResponse {
    state.core.set_ed2k_connected(false).await;
    api_ok(json!({ "connected": false }))
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

async fn download_search_result(
    State(state): State<RestState>,
    Path((search_id, hash)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.core.download_search_result(&search_id, &hash).await {
        Ok(Some(transfer)) => api_ok(transfer).into_response(),
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
    match state.core.create_transfer(request).await {
        Ok(transfer) => api_ok(transfer).into_response(),
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

async fn transfer_sources() -> impl IntoResponse {
    api_collection(Vec::<Value>::new())
}

async fn transfer_pause(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    transfer_state(state, hash, "paused").await
}

async fn transfer_resume(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    transfer_state(state, hash, "downloading").await
}

async fn transfer_stop(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    transfer_state(state, hash, "stopped").await
}

async fn transfer_state(state: RestState, hash: String, next_state: &str) -> Response {
    match state.core.set_transfer_state(&hash, next_state).await {
        Some(transfer) => api_ok(transfer).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "transfer not found").into_response(),
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
    }
}
