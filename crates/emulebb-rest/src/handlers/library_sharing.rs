//! Explicit bounded sharing writes use the qualified profile owner.
use super::persistence::{persistence_error, persistence_fields};
use super::prelude::*;
use super::resource::{HashOutcome, item};
use axum::{body::Bytes, extract::State, http::StatusCode, response::Response};
use emulebb_core::{LibraryFileChange, LibrarySharingOutcome, LibrarySharingRequest};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sharing {
    enabled: bool,
    hashes: Vec<String>,
}

fn outcome(value: LibrarySharingOutcome) -> HashOutcome {
    match value.outcome {
        Ok(LibraryFileChange::Changed) => HashOutcome::success(value.hash, true),
        Ok(LibraryFileChange::Unchanged) => HashOutcome::success(value.hash, false),
        Ok(LibraryFileChange::NotFound) => HashOutcome::failed(
            value.hash,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "library file not found",
            serde_json::json!({}),
        ),
        Err(error) => {
            let (status, code, details) = persistence_fields(&error);
            HashOutcome::failed(value.hash, status, code, error.to_string(), details)
        }
    }
}

pub(crate) async fn set_library_sharing(State(state): State<RestState>, body: Bytes) -> Response {
    let request = match parse_required_json_body::<Sharing>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state
        .core
        .set_library_sharing(&LibrarySharingRequest {
            enabled: request.enabled,
            hashes: request.hashes,
        })
        .await
    {
        Ok(reply) => item(
            StatusCode::MULTI_STATUS,
            reply.map(|values| values.into_iter().map(outcome).collect::<Vec<_>>()),
        ),
        Err(error) => persistence_error(error),
    }
}

#[cfg(test)]
mod tests;
