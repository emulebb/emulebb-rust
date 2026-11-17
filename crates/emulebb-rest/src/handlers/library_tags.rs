//! Immutable tag resources and explicit, bounded hash assignment actions.
use super::prelude::*;
use super::resource::{decode_cursor, encode_cursor, invalid, item, page};
use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use emulebb_core::LibraryTagError;
use emulebb_core::{LibraryTagChange, LibraryTagRequest, LibraryTagValue};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assign {
    tag: String,
    hashes: Vec<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Paging {
    limit: Option<usize>,
    cursor: Option<String>,
}

fn error(error: anyhow::Error) -> Response {
    match error.downcast_ref::<LibraryTagError>() {
        Some(LibraryTagError::InvalidName) => invalid("invalid tag name"),
        Some(LibraryTagError::AlreadyExists) => api_error(
            StatusCode::CONFLICT,
            "TAG_NAME_CONFLICT",
            "tag name already exists",
        )
        .into_response(),
        Some(LibraryTagError::NotFound) => missing("library tag not found"),
        Some(LibraryTagError::UnknownFile) => missing("library file not found"),
        None => super::persistence::persistence_error(error),
    }
}
fn missing(message: &'static str) -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", message).into_response()
}
fn unexpected() -> Response {
    super::persistence::persistence_error(emulebb_core::PersistenceError::Worker.into())
}

pub(crate) async fn create_library_tag(State(state): State<RestState>, body: Bytes) -> Response {
    let request = match parse_required_json_body::<Create>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state
        .core
        .library_tags(&LibraryTagRequest::Create(request.name))
        .await
    {
        Err(value) => error(value),
        Ok(reply) => {
            let LibraryTagValue::Tag(Some(tag)) = reply.value() else {
                return unexpected();
            };
            let location = format!("/api/v1/library/tags/{}", tag.name);
            let mut response = item(
                StatusCode::CREATED,
                reply.map(|value| match value {
                    LibraryTagValue::Tag(Some(tag)) => tag,
                    _ => unreachable!(),
                }),
            );
            response.headers_mut().insert(
                header::LOCATION,
                location.parse().expect("ASCII tag identity"),
            );
            response
        }
    }
}
pub(crate) async fn library_tag(
    State(state): State<RestState>,
    Path(name): Path<String>,
) -> Response {
    match state.core.library_tags(&LibraryTagRequest::Get(name)).await {
        Err(value) => error(value),
        Ok(reply) => match reply.value() {
            LibraryTagValue::Tag(None) => missing("library tag not found"),
            LibraryTagValue::Tag(Some(_)) => item(
                StatusCode::OK,
                reply.map(|value| match value {
                    LibraryTagValue::Tag(Some(tag)) => tag,
                    _ => unreachable!(),
                }),
            ),
            _ => unexpected(),
        },
    }
}
pub(crate) async fn delete_library_tag(
    State(state): State<RestState>,
    Path(name): Path<String>,
) -> Response {
    match state
        .core
        .library_tags(&LibraryTagRequest::Delete(name))
        .await
    {
        Err(value) => error(value),
        Ok(reply) => match reply.value() {
            LibraryTagValue::Deleted(true) => StatusCode::NO_CONTENT.into_response(),
            LibraryTagValue::Deleted(false) => missing("library tag not found"),
            _ => unexpected(),
        },
    }
}
async fn list(state: RestState, hash: Option<String>, raw: Option<String>) -> Response {
    let query = match parse_optional_query::<Paging>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let limit = query.limit.unwrap_or(100);
    if !(1..=200).contains(&limit) {
        return out_of_range_response("limit", 1, 200).into_response();
    }
    let scope = hash.as_ref().map_or_else(
        || "library-tags".into(),
        |hash| format!("library-file-tags:{hash}"),
    );
    let after = match query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor(cursor, &scope))
        .transpose()
    {
        Ok(value) => value,
        Err(error) => return *error,
    };
    if after
        .as_deref()
        .is_some_and(|name| !emulebb_core::valid_category_name(name))
    {
        return invalid("cursor is invalid for this collection");
    }
    match state
        .core
        .library_tags(&LibraryTagRequest::Page { hash, after, limit })
        .await
    {
        Err(value) => error(value),
        Ok(reply) => {
            let (next, more) = match reply.value() {
                LibraryTagValue::Page(Some(value)) => (
                    value
                        .next_after
                        .as_deref()
                        .map(|name| encode_cursor(&scope, name)),
                    value.has_more,
                ),
                LibraryTagValue::Page(None) => return missing("library file not found"),
                _ => return unexpected(),
            };
            page(
                reply.map(|value| match value {
                    LibraryTagValue::Page(Some(value)) => value.tags,
                    _ => unreachable!(),
                }),
                next,
                more,
            )
        }
    }
}
pub(crate) async fn library_tags(
    State(state): State<RestState>,
    RawQuery(raw): RawQuery,
) -> Response {
    list(state, None, raw).await
}
pub(crate) async fn library_file_tags(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    list(state, Some(hash), raw).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Outcome {
    hash: String,
    status: &'static str,
    http_status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Failure>,
}
#[derive(Serialize)]
struct Failure {
    code: &'static str,
    message: &'static str,
    details: serde_json::Value,
}

async fn change(state: RestState, body: Bytes, assigned: bool) -> Response {
    let request = match parse_required_json_body::<Assign>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state
        .core
        .library_tags(&LibraryTagRequest::Change {
            tag: request.tag,
            hashes: request.hashes,
            assigned,
        })
        .await
    {
        Err(value) => error(value),
        Ok(reply) => {
            if !matches!(reply.value(), LibraryTagValue::Assignments(_)) {
                return unexpected();
            }
            item(
                StatusCode::MULTI_STATUS,
                reply.map(|value| {
                    let LibraryTagValue::Assignments(values) = value else {
                        unreachable!()
                    };
                    values
                        .into_iter()
                        .map(|value| {
                            let (status, http_status, error) = match value.change {
                                LibraryTagChange::Changed => ("accepted", 200, None),
                                LibraryTagChange::Unchanged => ("unchanged", 200, None),
                                LibraryTagChange::NotFound => (
                                    "failed",
                                    404,
                                    Some(Failure {
                                        code: "NOT_FOUND",
                                        message: "library file not found",
                                        details: serde_json::json!({}),
                                    }),
                                ),
                                LibraryTagChange::StorageFailed => (
                                    "failed",
                                    500,
                                    Some(Failure {
                                        code: "PERSISTENCE_FAILED",
                                        message: "database operation failed",
                                        details: serde_json::json!({}),
                                    }),
                                ),
                            };
                            Outcome {
                                hash: value.hash,
                                status,
                                http_status,
                                error,
                            }
                        })
                        .collect::<Vec<_>>()
                }),
            )
        }
    }
}
pub(crate) async fn add_library_file_tags(State(state): State<RestState>, body: Bytes) -> Response {
    change(state, body, true).await
}
pub(crate) async fn remove_library_file_tags(
    State(state): State<RestState>,
    body: Bytes,
) -> Response {
    change(state, body, false).await
}
