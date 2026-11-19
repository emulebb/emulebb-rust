//! Independent bounded session metadata and materialized result resources.
use super::super::resource;
use super::super::resource::identity;
use super::*;
use axum::response::Response;
use emulebb_metadata::{
    MetadataSearchResultSort as Sort, MetadataSearchResultsQuery, MetadataSearchSortOrder as Order,
};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Paging {
    pub(super) limit: Option<usize>,
    pub(super) cursor: Option<String>,
}
impl Paging {
    pub(super) fn resolve(&self, scope: &str) -> Result<(usize, Option<i64>), Box<Response>> {
        let limit = self.limit.unwrap_or(100);
        if !(1..=200).contains(&limit) {
            return Err(Box::new(out_of_range_response("limit", 1, 200)));
        }
        let anchor = self
            .cursor
            .as_deref()
            .map(|value| resource::decode_cursor(value, scope))
            .transpose()?;
        let anchor = anchor.map(|value| identity(&value)).transpose()?;
        Ok((limit, anchor))
    }
}
fn missing() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "search resource not found",
    )
    .into_response()
}

pub(crate) async fn searches(State(state): State<RestState>, RawQuery(raw): RawQuery) -> Response {
    let query = match parse_optional_query::<Paging>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let (limit, before) = match query.resolve("searches") {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state.core.search_headers_page(before, limit).await {
        Ok(reply) => {
            let page = reply.value();
            let cursor = if page.has_more {
                page.items
                    .last()
                    .map(|row| resource::encode_cursor("searches", &row.id.to_string()))
            } else {
                None
            };
            let values = page
                .items
                .iter()
                .map(|row| search_header_response(row, None))
                .collect::<Vec<_>>();
            resource::page(values, cursor, page.has_more)
        }
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
pub(crate) async fn search(State(state): State<RestState>, Path(id): Path<String>) -> Response {
    let key = match identity(&id) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state.core.search_header(key).await {
        Ok(reply) => match reply.value() {
            Some(header) => resource::item(
                StatusCode::OK,
                search_header_response(header, state.core.search_progress(&id).await.as_ref()),
            ),
            None => missing(),
        },
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultsQuery {
    limit: Option<usize>,
    cursor: Option<String>,
    sort: Option<Sort>,
    order: Option<Order>,
}
pub(crate) async fn search_results(
    State(state): State<RestState>,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let session = match identity(&id) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let query = match parse_optional_query::<ResultsQuery>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let sort = query.sort.unwrap_or(Sort::Sources);
    let order = query.order.unwrap_or(Order::Desc);
    let scope = format!(
        "search-results:{session}:{}:{}",
        sort.as_str(),
        order.as_str()
    );
    let (limit, after_claim_id) = match (Paging {
        limit: query.limit,
        cursor: query.cursor,
    })
    .resolve(&scope)
    {
        Ok(value) => value,
        Err(error) => return *error,
    };
    match state
        .core
        .search_results_page(MetadataSearchResultsQuery {
            session_id: session,
            after_claim_id,
            sort,
            order,
            limit,
        })
        .await
    {
        Ok(reply) => {
            let Some(page) = reply.value() else {
                return missing();
            };
            let cursor = if page.has_more {
                page.items
                    .last()
                    .map(|row| resource::encode_cursor(&scope, &row.claim_id.to_string()))
            } else {
                None
            };
            let values = page
                .items
                .iter()
                .map(|row| search_summary_response(session, row))
                .collect::<Vec<_>>();
            resource::page(values, cursor, page.has_more)
        }
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
pub(crate) async fn search_result(
    State(state): State<RestState>,
    Path((session, claim)): Path<(String, String)>,
) -> Response {
    let (session, claim) =
        match identity(&session).and_then(|session| Ok((session, identity(&claim)?))) {
            Ok(value) => value,
            Err(error) => return *error,
        };
    match state.core.search_result_header(session, claim).await {
        Ok(reply) => match reply.value() {
            Some(row) => resource::item(StatusCode::OK, search_summary_response(session, row)),
            None => missing(),
        },
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
