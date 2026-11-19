//! Canonical settings use one CAS document and the shared profile owner.
use crate::handlers::prelude::*;
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use emulebb_core::{LibraryReply, SettingsMutationError, SettingsSnapshot};
use emulebb_settings::product::{SettingsError, SettingsPatch};
use serde_json::json;

fn response(reply: LibraryReply<SettingsSnapshot>) -> Response {
    let revision = reply.value().revision();
    super::resource::settings_item(reply.map(SettingsSnapshot::into_data), revision)
}
fn invalid(error: &SettingsError) -> Response {
    let (status, code) = if *error == SettingsError::DocumentTooLarge {
        (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE")
    } else {
        (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT")
    };
    let details = match error {
        SettingsError::Validation(issues) => json!({"issues": issues}),
        _ => json!({}),
    };
    api_error_with_details(status, code, error.to_string(), details).into_response()
}
fn failure(error: anyhow::Error) -> Response {
    match error.downcast_ref::<SettingsMutationError>() {
        Some(SettingsMutationError::Invalid(error)) => invalid(error),
        Some(SettingsMutationError::Conflict { actual }) => api_error_with_details(
            StatusCode::CONFLICT,
            "SETTINGS_CONFLICT",
            "Saved settings changed; read the latest revision.",
            json!({"actualRevision": actual}),
        )
        .into_response(),
        Some(SettingsMutationError::RevisionExhausted) => api_error(
            StatusCode::CONFLICT,
            "SETTINGS_REVISION_EXHAUSTED",
            "Saved settings revision is exhausted.",
        )
        .into_response(),
        None => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn settings(State(state): State<RestState>) -> Response {
    match state.core.settings().await {
        Ok(reply) => response(reply),
        Err(error) => failure(error),
    }
}
pub(crate) async fn settings_surface() -> Response {
    super::resource::item(StatusCode::OK, emulebb_settings::settings_surface())
}
pub(crate) async fn update_settings(State(state): State<RestState>, body: Bytes) -> Response {
    let patch = match SettingsPatch::from_json(&body) {
        Ok(patch) => patch,
        Err(error) => return invalid(&error),
    };
    match state.core.update_settings(&patch).await {
        Ok(reply) => response(reply),
        Err(error) => failure(error),
    }
}
