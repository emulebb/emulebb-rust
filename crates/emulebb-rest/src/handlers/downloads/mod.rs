//! Durable download resources; execution geometry and evidence are separate pages.
mod actions;
mod browse;
mod sources;
pub(crate) use actions::{download_remove, download_start, download_stop, download_verify};
pub(crate) use browse::{
    download_comments, download_parts, download_source, download_sources, downloads,
};
pub(crate) use sources::*;

use crate::handlers::prelude::*;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use emulebb_core::{DownloadCreate, DownloadPatchError, DownloadUpdate, JobId};
use serde::{Deserialize, Serialize};

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
fn page<T: Serialize>(data: T, next_cursor: Option<String>, has_more: bool) -> Response {
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
fn invalid(message: impl Into<String>) -> Response {
    api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message).into_response()
}
fn missing() -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "download not found").into_response()
}
fn job_id(value: &str) -> Result<JobId, Box<Response>> {
    value
        .parse()
        .map_err(|_| Box::new(invalid("id must be a positive decimal i64 string")))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}
impl PageQuery {
    fn limit(&self) -> Result<usize, Box<Response>> {
        let limit = self.limit.unwrap_or(100);
        if !(1..=200).contains(&limit) {
            return Err(Box::new(out_of_range_response("limit", 1, 200)));
        }
        Ok(limit)
    }
    fn boundary(&self, scope: &str) -> Result<Option<u64>, Box<Response>> {
        self.cursor
            .as_deref()
            .map(|value| decode_cursor(value, scope))
            .transpose()
    }
}
fn encode_cursor(scope: &str, position: u64) -> String {
    hex::encode(format!("{scope}|{position}"))
}
fn decode_cursor(value: &str, scope: &str) -> Result<u64, Box<Response>> {
    if value.len() > 512 {
        return Err(Box::new(invalid("cursor is invalid for this collection")));
    }
    let decoded = hex::decode(value)
        .map_err(|_| Box::new(invalid("cursor is invalid for this collection")))?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|_| Box::new(invalid("cursor is invalid for this collection")))?;
    let prefix = format!("{scope}|");
    let position = decoded
        .strip_prefix(&prefix)
        .ok_or_else(|| Box::new(invalid("cursor is invalid for this collection")))?;
    if position.is_empty()
        || !position.bytes().all(|byte| byte.is_ascii_digit())
        || (position.len() > 1 && position.starts_with('0'))
    {
        return Err(Box::new(invalid("cursor is invalid for this collection")));
    }
    position
        .parse()
        .map_err(|_| Box::new(invalid("cursor is invalid for this collection")))
}

pub(crate) async fn create_download(State(state): State<RestState>, body: Bytes) -> Response {
    let request = match parse_required_json_body::<DownloadCreate>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state.core.create_download(request).await {
        Ok((created, value)) => item(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            &*value,
        ),
        Err(error) => download_creation_error(error),
    }
}
pub(crate) async fn download(State(state): State<RestState>, Path(id): Path<String>) -> Response {
    let id = match job_id(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    match state.core.download_detail(id).await {
        Ok(Some(value)) => item(StatusCode::OK, &*value),
        Ok(None) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}
pub(crate) async fn update_download(
    State(state): State<RestState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let id = match job_id(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    let update = match parse_required_json_body::<DownloadUpdate>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state.core.patch_download(id, update).await {
        Ok(emulebb_core::DownloadChange::NotFound) => missing(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => match error.downcast_ref::<DownloadPatchError>() {
            Some(
                DownloadPatchError::NameFixed
                | DownloadPatchError::SizeConflict
                | DownloadPatchError::Stale,
            ) => api_error(StatusCode::CONFLICT, "DOWNLOAD_CONFLICT", error.to_string())
                .into_response(),
            Some(DownloadPatchError::CategoryNotFound) => {
                api_error(StatusCode::NOT_FOUND, "NOT_FOUND", error.to_string()).into_response()
            }
            _ => super::persistence::persistence_error(error),
        },
    }
}
