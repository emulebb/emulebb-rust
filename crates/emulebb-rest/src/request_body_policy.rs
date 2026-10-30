//! Single buffering and size policy for authenticated `/api/v1` requests.
//!
//! This middleware owns the REST request-body ceiling. It runs after API-key
//! authentication and before route metadata validation, buffers at most the
//! configured maximum once, and shares those bytes with metadata validation.

use std::error::Error as _;

use axum::{
    body::{Body, Bytes, to_bytes},
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body_util::LengthLimitError;

use crate::envelope::api_error;

pub(crate) const MAX_API_REQUEST_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct BufferedApiRequestBody(Bytes);

impl BufferedApiRequestBody {
    pub(crate) fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}

pub(crate) async fn enforce_api_request_body_limit(request: Request<Body>, next: Next) -> Response {
    if declared_body_is_oversized(&request) {
        return payload_too_large_response();
    }

    let (mut parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_API_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(error)
            if error
                .source()
                .is_some_and(|source| source.is::<LengthLimitError>()) =>
        {
            return payload_too_large_response();
        }
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                format!("invalid request body: {error}"),
            )
            .into_response();
        }
    };

    parts
        .extensions
        .insert(BufferedApiRequestBody(body.clone()));
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn declared_body_is_oversized(request: &Request<Body>) -> bool {
    request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > MAX_API_REQUEST_BODY_BYTES as u64)
}

fn payload_too_large_response() -> Response {
    api_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        "PAYLOAD_TOO_LARGE",
        format!("request body exceeds the {MAX_API_REQUEST_BODY_BYTES}-byte limit"),
    )
    .into_response()
}
