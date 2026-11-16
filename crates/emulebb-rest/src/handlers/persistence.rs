//! Shared mapping of persistence outcomes to REST responses.

use crate::handlers::prelude::*;
use axum::{http::StatusCode, response::IntoResponse};
use emulebb_core::{LocalMutationError, PersistenceError};
use serde_json::json;

pub(crate) fn persistence_error(error: anyhow::Error) -> axum::response::Response {
    if let Some(local) = error.downcast_ref::<LocalMutationError>() {
        let mapped = match local {
            LocalMutationError::Busy => PersistenceError::Busy,
            LocalMutationError::Closing => PersistenceError::Closing,
            LocalMutationError::TooLarge => PersistenceError::TooLarge,
            LocalMutationError::Storage => {
                PersistenceError::Storage("database operation failed".into())
            }
            LocalMutationError::Committed => PersistenceError::CommittedPublicationFailed,
            LocalMutationError::Unknown => PersistenceError::CommitUnknown,
        };
        return persistence_error(mapped.into());
    }
    match error.downcast_ref::<PersistenceError>() {
        Some(
            PersistenceError::CommittedAfterWorkerFailure
            | PersistenceError::CommittedPublicationFailed,
        ) => api_error_with_details(
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
