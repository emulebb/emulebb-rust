use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, StatusCode, header},
    middleware,
    response::IntoResponse,
    routing::post,
};
use futures_util::{StreamExt, stream};
use serde_json::Value;
use tower::ServiceExt;

use crate::{
    request_body_policy::{MAX_API_REQUEST_BODY_BYTES, enforce_api_request_body_limit},
    rest_test_support::test_router,
};

fn counting_router(handler_calls: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route(
            "/api/v1/test",
            post(move |body: Bytes| {
                let handler_calls = handler_calls.clone();
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, body.len().to_string()).into_response()
                }
            }),
        )
        .layer(middleware::from_fn(enforce_api_request_body_limit))
}

async fn response_error_code(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    value["error"]["code"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn fixed_length_bodies_stop_at_the_single_api_limit() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let app = counting_router(handler_calls.clone());

    let accepted = app
        .clone()
        .oneshot(
            Request::post("/api/v1/test")
                .header(header::CONTENT_LENGTH, MAX_API_REQUEST_BODY_BYTES - 1)
                .body(Body::from(vec![b'a'; MAX_API_REQUEST_BODY_BYTES - 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);

    let body_polls = Arc::new(AtomicUsize::new(0));
    let rejected = app
        .oneshot(
            Request::post("/api/v1/test")
                .header(header::CONTENT_LENGTH, MAX_API_REQUEST_BODY_BYTES + 1)
                .body(counting_stream_body(
                    body_polls.clone(),
                    MAX_API_REQUEST_BODY_BYTES + 1,
                    1,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response_error_code(rejected).await, "PAYLOAD_TOO_LARGE");
    assert_eq!(body_polls.load(Ordering::SeqCst), 0);
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn streamed_body_at_the_limit_reaches_the_handler() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let body_polls = Arc::new(AtomicUsize::new(0));
    let response = counting_router(handler_calls.clone())
        .oneshot(
            Request::post("/api/v1/test")
                .body(counting_stream_body(body_polls.clone(), 64 * 1024, 16))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
    assert_eq!(body_polls.load(Ordering::SeqCst), 16);
}

#[tokio::test]
async fn missing_or_misleading_content_length_cannot_bypass_stream_limit() {
    for declared_length in [None, Some("1")] {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let body_polls = Arc::new(AtomicUsize::new(0));
        let mut request = Request::post("/api/v1/test");
        if let Some(declared_length) = declared_length {
            request = request.header(header::CONTENT_LENGTH, declared_length);
        }

        let response = counting_router(handler_calls.clone())
            .oneshot(
                request
                    .body(counting_stream_body(body_polls.clone(), 64 * 1024, 64))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response_error_code(response).await, "PAYLOAD_TOO_LARGE");
        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
        assert!(body_polls.load(Ordering::SeqCst) < 64);
        assert!(body_polls.load(Ordering::SeqCst) <= MAX_API_REQUEST_BODY_BYTES / (64 * 1024) + 1);
    }
}

#[tokio::test]
async fn unauthorized_api_requests_do_not_consume_the_body() {
    let body_polls = Arc::new(AtomicUsize::new(0));
    let response = test_router()
        .oneshot(
            Request::post("/api/v1/searches")
                .header(header::CONTENT_TYPE, "application/json")
                .body(counting_stream_body(body_polls.clone(), 64 * 1024, 64))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bounded_malformed_json_keeps_the_existing_validation_error() {
    let response = test_router()
        .oneshot(
            Request::post("/api/v1/searches")
                .header("X-API-Key", "secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"unsupported":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_error_code(response).await, "INVALID_ARGUMENT");
}

fn counting_stream_body(
    body_polls: Arc<AtomicUsize>,
    chunk_size: usize,
    chunk_count: usize,
) -> Body {
    let chunk = Bytes::from(vec![b'a'; chunk_size]);
    let body = stream::iter(0..chunk_count).map(move |_| {
        body_polls.fetch_add(1, Ordering::SeqCst);
        Ok::<_, Infallible>(chunk.clone())
    });
    Body::from_stream(body)
}
