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

use super::persistence::persistence_error;
use emulebb_core::FriendCreate;
#[cfg(test)]
use emulebb_core::PersistenceError;

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
        Err(error) => persistence_error(error),
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
        Err(error) => persistence_error(error),
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
            (
                PersistenceError::CommittedPublicationFailed,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_COMMITTED",
                true,
            ),
        ] {
            let response = persistence_error(error.into());
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

    #[tokio::test]
    async fn local_mutation_outcomes_use_the_shared_persistence_contract() {
        use emulebb_ed2k::ed2k_transfer::LocalMutationError;
        for (error, status, code, committed) in [
            (
                LocalMutationError::Busy,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_BUSY",
                false,
            ),
            (
                LocalMutationError::Closing,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_CLOSING",
                false,
            ),
            (
                LocalMutationError::TooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "PERSISTENCE_TOO_LARGE",
                false,
            ),
            (
                LocalMutationError::Storage,
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSISTENCE_FAILED",
                false,
            ),
            (
                LocalMutationError::Committed,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_COMMITTED",
                true,
            ),
            (
                LocalMutationError::Unknown,
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_UNAVAILABLE",
                false,
            ),
        ] {
            let response = persistence_error(error.into());
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
