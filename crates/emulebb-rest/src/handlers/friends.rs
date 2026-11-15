//! Friend-list REST handlers (`/friends`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use emulebb_core::{FriendCreate, PersistenceError};

use crate::handlers::prelude::*;

pub(crate) async fn friends(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.friends().await {
        Ok(friends) => api_collection(friends).into_response(),
        Err(error) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PERSISTENCE_UNAVAILABLE",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn create_friend(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<FriendCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.add_friend(request).await {
        Ok(friend) => api_ok(friend).into_response(),
        Err(error) => friend_error(error),
    }
}

pub(crate) async fn delete_friend(
    State(state): State<RestState>,
    Path(user_hash): Path<String>,
) -> impl IntoResponse {
    match state.core.delete_friend(&user_hash).await {
        Ok(Some(_friend)) => api_ok(json!({ "ok": true })).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "friend not found").into_response()
        }
        Err(error) => friend_error(error),
    }
}

pub(crate) fn friend_error(error: anyhow::Error) -> axum::response::Response {
    match error.downcast_ref::<PersistenceError>() {
        Some(PersistenceError::CommittedAfterWorkerFailure) => api_error_with_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "PERSISTENCE_COMMITTED",
            error.to_string(),
            json!({"committed": true}),
        )
        .into_response(),
        Some(PersistenceError::Busy) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PERSISTENCE_BUSY",
            error.to_string(),
        )
        .into_response(),
        Some(PersistenceError::Closing) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PERSISTENCE_CLOSING",
            error.to_string(),
        )
        .into_response(),
        Some(PersistenceError::TooLarge) => api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PERSISTENCE_TOO_LARGE",
            error.to_string(),
        )
        .into_response(),
        Some(PersistenceError::Storage(_)) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSISTENCE_FAILED",
            error.to_string(),
        )
        .into_response(),
        Some(PersistenceError::CommitUnknown | PersistenceError::Worker) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PERSISTENCE_UNAVAILABLE",
            error.to_string(),
        )
        .into_response(),
        _ => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            error.to_string(),
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persistence_outcomes_have_explicit_status_codes_and_details() {
        for (error, status, code, committed) in [
            (
                PersistenceError::Busy,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_BUSY",
                false,
            ),
            (
                PersistenceError::Closing,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_CLOSING",
                false,
            ),
            (
                PersistenceError::TooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "PERSISTENCE_TOO_LARGE",
                false,
            ),
            (
                PersistenceError::Storage("failure".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSISTENCE_FAILED",
                false,
            ),
            (
                PersistenceError::Worker,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_UNAVAILABLE",
                false,
            ),
            (
                PersistenceError::CommitUnknown,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_UNAVAILABLE",
                false,
            ),
            (
                PersistenceError::CommittedAfterWorkerFailure,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_COMMITTED",
                true,
            ),
        ] {
            let response = friend_error(error.into());
            assert_eq!(response.status(), status);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], code);
            assert_eq!(
                body["error"]["details"]
                    .get("committed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                committed
            );
        }
    }
}
