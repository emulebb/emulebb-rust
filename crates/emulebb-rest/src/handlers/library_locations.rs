//! Bounded cached locations for one client-owned content hash.

use super::prelude::*;
use super::resource::{decode_cursor, encode_cursor, identity, invalid, page_document};
use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Paging {
    limit: Option<usize>,
    cursor: Option<String>,
}

pub(crate) async fn library_file_locations(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match parse_optional_query::<Paging>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let limit = query.limit.unwrap_or(100);
    if !(1..=200).contains(&limit) {
        return out_of_range_response("limit", 1, 200);
    }
    let scope = format!("library-locations:{hash}");
    let after = match query
        .cursor
        .as_deref()
        .map(|cursor| {
            let position = decode_cursor(cursor, &scope)?;
            identity(&position)
                .map_err(|_| Box::new(invalid("cursor is invalid for this collection")))
        })
        .transpose()
    {
        Ok(value) => value.unwrap_or(0),
        Err(error) => return *error,
    };
    let page = match state.core.library_locations(&hash, after, limit).await {
        Ok(Some(page)) => page,
        Ok(None) => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "library file not found")
                .into_response();
        }
        Err(error) => return super::persistence::persistence_error(error),
    };
    let encoded = page
        .try_project(emulebb_core::LIBRARY_LOCATION_PAGE_BYTES + 4096, |page| {
            let next = page
                .next_after
                .map(|after| encode_cursor(&scope, &after.to_string()));
            Ok(page_document(
                page.locations,
                next,
                page.next_after.is_some(),
                None,
            ))
        })
        .and_then(|page| page.serialize_json());
    match encoded {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            axum::body::Body::from(axum::body::Bytes::from_owner(bytes)),
        )
            .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

#[cfg(test)]
mod tests;
