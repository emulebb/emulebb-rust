//! Shared REST envelope, pagination, and request-parsing helpers.
//!
//! These free functions build the canonical `{data,meta}` / `{error}` response
//! envelopes, validate pagination bounds, and parse JSON bodies / query strings
//! into typed values. Extracted verbatim from `lib.rs` during the
//! maintainability restructuring; behavior is unchanged.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{BulkOperationResult, PageQuery, SearchResultsPage, SearchResultsQuery};
use emulebb_core::Search;

pub(crate) fn api_ok<T: Serialize>(data: T) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "data": data,
            "meta": api_meta()
        })),
    )
}

pub(crate) fn api_collection<T: Serialize>(items: Vec<T>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "data": { "items": items },
            "meta": api_meta()
        })),
    )
}

pub(crate) fn api_collection_page<T: Serialize>(items: Vec<T>, query: PageQuery) -> Response {
    let (offset, limit) = match resolve_page_bounds(query.offset, query.limit) {
        Ok(bounds) => bounds,
        Err(response) => return *response,
    };
    let total = items.len();
    let items = items
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    api_ok(json!({
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit
    }))
    .into_response()
}

pub(crate) fn search_results_page(
    search: Search,
    query: SearchResultsQuery,
) -> Result<SearchResultsPage, Box<Response>> {
    let (offset, limit) = resolve_page_bounds(query.offset, query.limit)?;
    let _include_evidence = query.include_evidence.unwrap_or(true);
    let _exact_total = query.exact_total.unwrap_or(true);
    let total = search.results.len();
    let results = search
        .results
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    Ok(SearchResultsPage {
        id: search.id,
        query: search.query,
        method: search.method,
        file_type: search.r#type,
        status: search.status,
        status_reason: search.status_reason,
        total,
        offset,
        limit,
        results,
    })
}

pub(crate) fn api_bulk_operation(items: Vec<BulkOperationResult>) -> (StatusCode, Json<Value>) {
    let total = items.len();
    (
        StatusCode::OK,
        Json(json!({
            "data": {
                "items": items,
                "total": total,
                "offset": 0,
                "limit": total
            },
            "meta": api_meta()
        })),
    )
}

pub(crate) fn api_meta() -> Value {
    json!({ "apiVersion": "v1" })
}

pub(crate) fn snapshot_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(100)
}

pub(crate) fn bounded<T>(items: Vec<T>, limit: usize) -> Vec<T> {
    items.into_iter().take(limit).collect()
}

pub(crate) fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    api_error_with_details(status, code, message, json!({}))
}

pub(crate) fn api_error_with_details(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    details: Value,
) -> (StatusCode, Json<Value>) {
    let code = if status == StatusCode::BAD_REQUEST && code == "BAD_REQUEST" {
        "INVALID_ARGUMENT"
    } else {
        code
    };
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message.into(),
                "details": details
            }
        })),
    )
}

/// Builds the canonical out-of-range error for a bounded scalar query field.
/// Kept identical to the emulebb master (`SetBoundedConstraintDetails`) so both
/// stacks emit the same message and `{field, constraint}` details.
pub(crate) fn out_of_range_response(field: &str, min: u64, max: u64) -> Response {
    api_error_with_details(
        StatusCode::BAD_REQUEST,
        "INVALID_ARGUMENT",
        format!("{field} is out of range"),
        json!({ "field": field, "constraint": format!("{min}..{max}") }),
    )
    .into_response()
}

/// REST pagination bounds, matching the emulebb master: `limit` in 1..=1000,
/// `offset` in 0..=2147483647. Out-of-range values are rejected (not clamped).
pub(crate) const PAGE_LIMIT_MIN: usize = 1;
pub(crate) const PAGE_LIMIT_MAX: usize = 1000;
pub(crate) const PAGE_OFFSET_MAX: usize = 2_147_483_647;

/// Validates an optional `limit` query value against the published bounds,
/// returning the effective limit (default 100) or a rejection response.
pub(crate) fn resolve_limit(limit: Option<usize>) -> Result<usize, Box<Response>> {
    match limit {
        Some(limit) if !(PAGE_LIMIT_MIN..=PAGE_LIMIT_MAX).contains(&limit) => {
            Err(out_of_range_response("limit", PAGE_LIMIT_MIN as u64, PAGE_LIMIT_MAX as u64).into())
        }
        Some(limit) => Ok(limit),
        None => Ok(100),
    }
}

/// Validates optional `offset`/`limit` query values, returning the effective
/// (offset, limit) pair or a rejection response.
pub(crate) fn resolve_page_bounds(
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<(usize, usize), Box<Response>> {
    let limit = resolve_limit(limit)?;
    let offset = match offset {
        Some(offset) if offset > PAGE_OFFSET_MAX => {
            return Err(out_of_range_response("offset", 0, PAGE_OFFSET_MAX as u64).into());
        }
        Some(offset) => offset,
        None => 0,
    };
    Ok((offset, limit))
}

pub(crate) fn parse_required_json_body<T>(body: &[u8]) -> Result<T, Box<Response>>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(body).map_err(|error| {
        api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            json_error_message(&error),
        )
        .into_response()
        .into()
    })
}

pub(crate) fn parse_optional_query<T>(query: Option<&str>) -> Result<T, Box<Response>>
where
    T: DeserializeOwned + Default,
{
    match query {
        Some(query) if !query.is_empty() => serde_urlencoded::from_str(query).map_err(|error| {
            api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                structured_error_message(error.to_string()),
            )
            .into_response()
            .into()
        }),
        _ => Ok(T::default()),
    }
}

pub(crate) fn json_error_message(error: &serde_json::Error) -> String {
    structured_error_message(error.to_string())
}

pub(crate) fn structured_error_message(message: String) -> String {
    if let Some(field) = unknown_json_field(&message) {
        return format!("unknown JSON field: {field}");
    }
    trim_json_location(message)
}

pub(crate) fn unknown_json_field(message: &str) -> Option<&str> {
    let (_, rest) = message.split_once("unknown field `")?;
    let (field, _) = rest.split_once('`')?;
    Some(field)
}

pub(crate) fn trim_json_location(message: String) -> String {
    if let Some((prefix, _)) = message.rsplit_once(" at line ") {
        prefix.to_string()
    } else {
        message
    }
}

pub(crate) fn optional_json_body<T>(body: &[u8]) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned + Default,
{
    if body.is_empty() {
        Ok(T::default())
    } else {
        serde_json::from_slice(body)
    }
}
