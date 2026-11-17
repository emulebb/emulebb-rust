//! Shared mapping of persistence outcomes to REST responses and bulk errors.
use crate::handlers::prelude::*;
use axum::{http::StatusCode, response::IntoResponse};
use emulebb_core::{LocalMutationError, PersistenceError};
use serde_json::{Value, json};

pub(super) fn persistence_fields(error: &PersistenceError) -> (StatusCode, &'static str, Value) {
    let (status, code) = match error {
        PersistenceError::CommittedAfterWorkerFailure
        | PersistenceError::CommittedPublicationFailed => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "PERSISTENCE_COMMITTED",
                json!({"committed": true}),
            );
        }
        PersistenceError::Busy => (StatusCode::SERVICE_UNAVAILABLE, "PERSISTENCE_BUSY"),
        PersistenceError::Closing => (StatusCode::SERVICE_UNAVAILABLE, "PERSISTENCE_CLOSING"),
        PersistenceError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "PERSISTENCE_TOO_LARGE"),
        PersistenceError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "PERSISTENCE_FAILED"),
        PersistenceError::CommitUnknown | PersistenceError::Worker => {
            (StatusCode::SERVICE_UNAVAILABLE, "PERSISTENCE_UNAVAILABLE")
        }
    };
    (status, code, json!({}))
}

pub(crate) fn persistence_error(error: anyhow::Error) -> axum::response::Response {
    if let Some(local) = error.downcast_ref::<LocalMutationError>() {
        return persistence_error(PersistenceError::from(local).into());
    }
    if let Some(persistence) = error.downcast_ref::<PersistenceError>() {
        let (status, code, details) = persistence_fields(persistence);
        return api_error_with_details(status, code, error.to_string(), details).into_response();
    }
    api_error(
        StatusCode::BAD_REQUEST,
        "INVALID_ARGUMENT",
        error.to_string(),
    )
    .into_response()
}
