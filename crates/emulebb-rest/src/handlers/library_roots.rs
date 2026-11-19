//! Immutable root resources and the single retained library scan operation.
use super::prelude::*;
use super::resource::{decode_cursor, encode_cursor, identity, item, page};
use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use emulebb_core::LibraryRoot;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    path: String,
    #[serde(default)]
    watch_enabled: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Patch {
    watch_enabled: bool,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Paging {
    limit: Option<usize>,
    cursor: Option<String>,
}

fn missing() -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "library root not found").into_response()
}

pub(crate) async fn library_roots(
    State(state): State<RestState>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match parse_optional_query::<Paging>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let limit = query.limit.unwrap_or(100);
    if !(1..=100).contains(&limit) {
        return out_of_range_response("limit", 1, 100);
    }
    let after = match query
        .cursor
        .as_deref()
        .map(|value| decode_cursor(value, "library-roots"))
        .transpose()
    {
        Ok(Some(value)) => match identity(&value) {
            Ok(id) => id,
            Err(error) => return *error,
        },
        Ok(None) => 0,
        Err(error) => return *error,
    };
    match state.core.library_root_page(after, limit).await {
        Ok(reply) => {
            let next = reply
                .value()
                .next_id
                .map(|id| encode_cursor("library-roots", &id.to_string()));
            let more = next.is_some();
            page(reply.map(|value| value.roots), next, more)
        }
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn library_root(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Response {
    let id = match identity(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    match state.core.library_root(id).await {
        Ok(reply) if reply.value().is_some() => item(
            StatusCode::OK,
            reply.map(|root| root.expect("checked root")),
        ),
        Ok(_) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn create_library_root(State(state): State<RestState>, body: Bytes) -> Response {
    let request = match parse_required_json_body::<Create>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state
        .core
        .create_library_root(&request.path, request.watch_enabled)
        .await
    {
        Ok(Some(root)) => {
            let location = format!("/api/v1/library/roots/{}", root.id);
            let mut response = item(StatusCode::CREATED, LibraryRoot::from(root));
            response.headers_mut().insert(
                header::LOCATION,
                location.parse().expect("decimal root identity"),
            );
            response
        }
        Ok(None) => api_error(
            StatusCode::CONFLICT,
            "ROOT_CONFLICT",
            "an existing library root overlaps this path",
        )
        .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn update_library_root(
    State(state): State<RestState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let id = match identity(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    let request = match parse_required_json_body::<Patch>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state
        .core
        .patch_library_root_watch(id, request.watch_enabled)
        .await
    {
        Ok(Some(root)) => item(StatusCode::OK, LibraryRoot::from(root)),
        Ok(None) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn delete_library_root(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Response {
    let id = match identity(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    match state.core.delete_library_root(id).await {
        Ok(emulebb_metadata::MetadataLibraryRootDelete::Deleted(_)) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(emulebb_metadata::MetadataLibraryRootDelete::Missing) => missing(),
        Ok(emulebb_metadata::MetadataLibraryRootDelete::Managed) => api_error(
            StatusCode::CONFLICT,
            "ROOT_MANAGED",
            "library root is required by settings or a category",
        )
        .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn library_scan(State(state): State<RestState>) -> Response {
    item(StatusCode::OK, state.core.library_scan())
}
pub(crate) async fn scan_library(State(state): State<RestState>) -> Response {
    match state.core.reload_shared_directories_detached().await {
        Ok(_) => {
            let mut response = item(StatusCode::ACCEPTED, state.core.library_scan());
            response.headers_mut().insert(
                header::LOCATION,
                header::HeaderValue::from_static("/api/v1/library/scan"),
            );
            response
        }
        Err(error) => super::persistence::persistence_error(error),
    }
}
