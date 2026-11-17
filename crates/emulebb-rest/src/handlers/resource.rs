//! Shared typed resource envelopes and bounded, collection-scoped cursors.
use crate::envelope::api_error;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Serialize)]
struct Success<T> {
    data: T,
    meta: PageMeta,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PageMeta {
    api_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_more: Option<bool>,
}
pub(super) fn item<T: Serialize>(status: StatusCode, data: T) -> Response {
    (
        status,
        Json(Success {
            data,
            meta: PageMeta {
                api_version: "v1",
                next_cursor: None,
                has_more: None,
            },
        }),
    )
        .into_response()
}
pub(super) fn page<T: Serialize>(data: T, next_cursor: Option<String>, has_more: bool) -> Response {
    (
        StatusCode::OK,
        Json(Success {
            data,
            meta: PageMeta {
                api_version: "v1",
                next_cursor: Some(next_cursor),
                has_more: Some(has_more),
            },
        }),
    )
        .into_response()
}
pub(super) fn invalid(message: impl Into<String>) -> Response {
    api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message).into_response()
}
pub(super) fn encode_cursor(scope: &str, position: &str) -> String {
    hex::encode(format!("{scope}|{position}"))
}

pub(super) fn decode_cursor(value: &str, scope: &str) -> Result<String, Box<Response>> {
    let invalid_cursor = || Box::new(invalid("cursor is invalid for this collection"));
    if value.len() > 512 {
        return Err(invalid_cursor());
    }
    let decoded = hex::decode(value).map_err(|_| invalid_cursor())?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| invalid_cursor())?;
    let prefix = format!("{scope}|");
    let position = decoded
        .strip_prefix(&prefix)
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid_cursor)?;
    Ok(position.to_owned())
}

/// One ordered outcome for an explicitly selected library hash.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HashOutcome {
    hash: String,
    status: &'static str,
    http_status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
}
impl HashOutcome {
    pub(super) fn success(hash: String, changed: bool) -> Self {
        Self {
            hash,
            status: if changed { "accepted" } else { "unchanged" },
            http_status: 200,
            error: None,
        }
    }
    pub(super) fn failed(
        hash: String,
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            hash,
            status: "failed",
            http_status: status.as_u16(),
            error: Some(
                serde_json::json!({"code": code, "message": message.into(), "details": details}),
            ),
        }
    }
}
