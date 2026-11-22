//! Thin keyset library pages and admitted hash details.
use super::prelude::*;
use super::resource::{decode_cursor, encode_cursor, item_document, page_document, retained_json};
use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use emulebb_core::{LibraryFileQuery, LibraryFileSort, LibraryFileUpdate, LibraryFileView};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Query {
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(default)]
    count_total: bool,
    #[serde(default)]
    view: View,
    #[serde(default)]
    sort: Sort,
    #[serde(default)]
    order: Order,
    q: Option<String>,
    root_id: Option<String>,
    tag: Option<String>,
    sharing_enabled: Option<bool>,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum View {
    #[default]
    Present,
    Shared,
    Unavailable,
    AllKnown,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum Sort {
    #[default]
    DisplayName,
    SizeBytes,
    SessionUploadedBytes,
    SessionUploadRequests,
    SessionAcceptedUploads,
    LifetimeUploadedBytes,
    LifetimeUploadRequests,
    LifetimeAcceptedUploads,
    LastUploadRequestedAt,
    LastUploadedAt,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Order {
    #[default]
    Asc,
    Desc,
}

struct FilterDigest(Sha256);
impl std::io::Write for FilterDigest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn missing() -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "library file not found").into_response()
}

pub(crate) async fn library_files(
    State(state): State<RestState>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match parse_optional_query::<Query>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let limit = query.limit.unwrap_or(100);
    if !(1..=200).contains(&limit) {
        return out_of_range_response("limit", 1, 200);
    }
    let root_id = match query
        .root_id
        .as_deref()
        .map(super::resource::identity)
        .transpose()
    {
        Ok(value) => value,
        Err(error) => return *error,
    };
    if query.q.as_ref().is_some_and(|value| value.len() > 65_536)
        || query
            .tag
            .as_ref()
            .is_some_and(|value| !emulebb_metadata::valid_category_name(value))
    {
        return super::resource::invalid("invalid library filter");
    }
    if let Err(error) = emulebb_metadata::normalize_library_search(query.q.as_deref()) {
        return super::resource::invalid(error.to_string());
    }
    // Scope excludes paging controls. Hashing bounds the cursor even for a long
    // search; explicit enum serialization makes the scope stable across builds.
    let mut digest = FilterDigest(Sha256::new());
    serde_json::to_writer(
        &mut digest,
        &(
            &query.view,
            &query.sort,
            &query.order,
            &query.q,
            &query.root_id,
            &query.tag,
            query.sharing_enabled,
        ),
    )
    .expect("library filter hashing is infallible");
    let scope = format!("library-files:{}", hex::encode(digest.0.finalize()));
    let after = match query
        .cursor
        .as_deref()
        .map(|value| {
            let position = decode_cursor(value, &scope)?;
            let mut hash = [0; 16];
            if position.len() != 32
                || position.bytes().any(|b| b.is_ascii_uppercase())
                || hex::decode_to_slice(position, &mut hash).is_err()
            {
                return Err(Box::new(super::resource::invalid("invalid library cursor")));
            }
            Ok(hash)
        })
        .transpose()
    {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let page = match state
        .core
        .library_file_page(LibraryFileQuery {
            view: match query.view {
                View::Present => LibraryFileView::Present,
                View::Shared => LibraryFileView::Shared,
                View::Unavailable => LibraryFileView::Unavailable,
                View::AllKnown => LibraryFileView::AllKnown,
            },
            sort: match query.sort {
                Sort::DisplayName => LibraryFileSort::DisplayName,
                Sort::SizeBytes => LibraryFileSort::SizeBytes,
                Sort::SessionUploadedBytes => LibraryFileSort::SessionUploadedBytes,
                Sort::SessionUploadRequests => LibraryFileSort::SessionUploadRequests,
                Sort::SessionAcceptedUploads => LibraryFileSort::SessionAcceptedUploads,
                Sort::LifetimeUploadedBytes => LibraryFileSort::LifetimeUploadedBytes,
                Sort::LifetimeUploadRequests => LibraryFileSort::LifetimeUploadRequests,
                Sort::LifetimeAcceptedUploads => LibraryFileSort::LifetimeAcceptedUploads,
                Sort::LastUploadRequestedAt => LibraryFileSort::LastRequestedAt,
                Sort::LastUploadedAt => LibraryFileSort::LastUploadedAt,
            },
            descending: matches!(query.order, Order::Desc),
            search: query.q,
            root_id,
            tag: query.tag,
            sharing_enabled: query.sharing_enabled,
            after,
            limit,
            count_total: query.count_total,
        })
        .await
    {
        Ok(value) => value,
        Err(error)
            if error
                .downcast_ref::<emulebb_core::MetadataLibraryCursorExpired>()
                .is_some() =>
        {
            return api_error(
                StatusCode::CONFLICT,
                "CURSOR_EXPIRED",
                "library cursor anchor no longer exists",
            )
            .into_response();
        }
        Err(error) => return super::persistence::persistence_error(error),
    };
    let next = page
        .next_after
        .map(|hash| encode_cursor(&scope, &hex::encode(hash)));
    retained_json(
        &page,
        &page_document(&page.files, next, page.next_after.is_some(), page.total),
    )
}

pub(crate) async fn library_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
) -> Response {
    match state.core.library_file_detail(&hash).await {
        Ok(Some(detail)) => retained_json(&detail, &item_document(&*detail)),
        Ok(None) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn update_library_file(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    body: Bytes,
) -> Response {
    let request = match parse_required_json_body::<LibraryFileUpdate>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state.core.edit_library_file_metadata(&hash, &request).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

#[cfg(test)]
mod tests;
