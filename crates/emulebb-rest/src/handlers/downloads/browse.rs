use super::*;
use axum::extract::RawQuery;
use emulebb_core::{DownloadJobQuery, DownloadJobView};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadsQuery {
    limit: Option<usize>,
    cursor: Option<String>,
    view: Option<String>,
    category: Option<String>,
}
pub(crate) async fn downloads(State(state): State<RestState>, RawQuery(raw): RawQuery) -> Response {
    let query = match parse_optional_query::<DownloadsQuery>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let paging = PageQuery {
        limit: query.limit,
        cursor: query.cursor,
    };
    let limit = match paging.limit() {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let view_name = query.view.as_deref().unwrap_or("unfinished");
    let view = match view_name {
        "unfinished" => DownloadJobView::Unfinished,
        "completed" => DownloadJobView::Completed,
        "all" => DownloadJobView::All,
        _ => return invalid("view must be unfinished, completed or all"),
    };
    if query
        .category
        .as_deref()
        .is_some_and(|name| !emulebb_core::valid_category_name(name))
    {
        return invalid("category must be a valid category name");
    }
    let scope = format!(
        "downloads:{view_name}:{}",
        query.category.as_deref().unwrap_or("").to_ascii_lowercase()
    );
    let before = match paging.boundary(&scope) {
        Ok(None) => None,
        Ok(Some(value)) => match i64::try_from(value)
            .ok()
            .and_then(|value| JobId::new(value).ok())
        {
            Some(id) => Some(id),
            None => return invalid("cursor is invalid for this collection"),
        },
        Err(error) => return *error,
    };
    let category_id = match query.category {
        None => None,
        Some(name) => match state.core.category_by_name(&name).await {
            Ok(Some(category)) => Some(category.id),
            Ok(None) => return page(Vec::<emulebb_core::DownloadSummary>::new(), None, false),
            Err(error) => return super::super::persistence::persistence_error(error),
        },
    };
    match state
        .core
        .download_page(DownloadJobQuery {
            view,
            category_id,
            before,
            limit,
        })
        .await
    {
        Ok(value) => page(
            &value.downloads,
            value
                .next_before
                .map(|id| encode_cursor(&scope, id.get() as u64)),
            value.has_more,
        ),
        Err(error) => super::super::persistence::persistence_error(error),
    }
}

async fn evidence(
    State(state): State<RestState>,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
    kind: &str,
) -> Response {
    let id = match job_id(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    let paging = match parse_optional_query::<PageQuery>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let limit = match paging.limit() {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let scope = format!("downloads:{id}:{kind}");
    let after = match paging.boundary(&scope) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    if kind == "parts" {
        let after = match after.map(u32::try_from).transpose() {
            Ok(value) => value,
            Err(_) => return invalid("cursor is invalid for this collection"),
        };
        return match state.core.download_parts_page(id, after, limit).await {
            Ok(Some(value)) => page(
                &value.parts,
                value
                    .next_after
                    .map(|position| encode_cursor(&scope, u64::from(position))),
                value.has_more,
            ),
            Ok(None) => missing(),
            Err(error) => super::super::persistence::persistence_error(error),
        };
    }
    let after = match i64::try_from(after.unwrap_or(0)) {
        Ok(value) => value,
        Err(_) => return invalid("cursor is invalid for this collection"),
    };
    if kind == "sources" {
        return match state.core.download_sources_page(id, after, limit).await {
            Ok(Some(value)) => page(
                &value.sources,
                value
                    .next_after
                    .map(|position| encode_cursor(&scope, position as u64)),
                value.has_more,
            ),
            Ok(None) => missing(),
            Err(error) => super::super::persistence::persistence_error(error),
        };
    }
    match state.core.download_comments_page(id, after, limit).await {
        Ok(Some(value)) => page(
            &value.comments,
            value
                .next_after
                .map(|position| encode_cursor(&scope, position as u64)),
            value.has_more,
        ),
        Ok(None) => missing(),
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
pub(crate) async fn download_sources(
    state: State<RestState>,
    id: Path<String>,
    query: RawQuery,
) -> Response {
    evidence(state, id, query, "sources").await
}
pub(crate) async fn download_comments(
    state: State<RestState>,
    id: Path<String>,
    query: RawQuery,
) -> Response {
    evidence(state, id, query, "comments").await
}
pub(crate) async fn download_parts(
    state: State<RestState>,
    id: Path<String>,
    query: RawQuery,
) -> Response {
    evidence(state, id, query, "parts").await
}
pub(crate) async fn download_source(
    State(state): State<RestState>,
    Path((id, client)): Path<(String, String)>,
) -> Response {
    let id = match job_id(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    match state.core.download_source(id, &client).await {
        Ok(Some(value)) => item(StatusCode::OK, &*value),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "download source not found",
        )
        .into_response(),
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
