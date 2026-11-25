use super::*;
use axum::extract::RawQuery;
use emulebb_core::PeerBrowseStatus;
use serde_json::json;

enum Action {
    AddFriend,
    RemoveFriend,
    Remove,
    Ban,
    Unban,
}
async fn apply(
    State(state): State<RestState>,
    Path((id, client)): Path<(String, String)>,
    action: Action,
) -> Response {
    let id = match job_id(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    let result = match action {
        Action::AddFriend => state
            .core
            .add_download_source_friend(id, &client)
            .await
            .map(|value| value.map(|friend| json!(friend))),
        Action::RemoveFriend => state
            .core
            .remove_download_source_friend(id, &client)
            .await
            .map(|value| value.map(|_| json!({"ok":true}))),
        Action::Remove => state
            .core
            .remove_download_source(id, &client)
            .await
            .map(|value| value.map(|_| json!({"ok":true}))),
        Action::Ban => state
            .core
            .ban_download_source(id, &client)
            .await
            .map(|value| value.map(|banned| json!({"ok":true,"banned":banned}))),
        Action::Unban => state
            .core
            .unban_download_source(id, &client)
            .await
            .map(|value| value.map(|banned| json!({"ok":true,"banned":banned}))),
    };
    match result {
        Ok(Some(value)) => api_ok(value).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "download source or friend not found",
        )
        .into_response(),
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
pub(crate) async fn download_source_browse(
    State(state): State<RestState>,
    Path((id, client)): Path<(String, String)>,
) -> Response {
    let id = match job_id(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    match state.core.browse_download_source(id, &client).await {
        Ok(Some(start)) => api_ok(json!({
            "ok": true,
            "alreadyPending": start.already_pending,
            "searchId": start.search_id.to_string(),
        }))
        .into_response(),
        Ok(None) => missing_browse(),
        Err(error) => super::super::persistence::persistence_error(error),
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowsePaging {
    offset: Option<usize>,
    limit: Option<usize>,
}

pub(crate) async fn download_source_browse_page(
    State(state): State<RestState>,
    Path((id, client, search_id)): Path<(String, String, String)>,
    RawQuery(raw): RawQuery,
) -> Response {
    let id = match job_id(&id) {
        Ok(id) => id,
        Err(error) => return *error,
    };
    let Some(search_id) = search_id
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0 && value.to_string() == search_id)
    else {
        return invalid("searchId must be a positive decimal u64 string");
    };
    let query = match parse_optional_query::<BrowsePaging>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let limit = match (PageQuery {
        limit: query.limit,
        cursor: None,
    })
    .limit()
    {
        Ok(limit) => limit,
        Err(error) => return *error,
    };
    match state
        .core
        .download_source_browse_page(id, &client, search_id, query.offset.unwrap_or(0), limit)
        .await
    {
        Ok(Some(page)) => {
            let status = match page.status {
                PeerBrowseStatus::Pending => "pending",
                PeerBrowseStatus::Complete => "complete",
                PeerBrowseStatus::Denied => "denied",
                PeerBrowseStatus::Timeout => "timeout",
                PeerBrowseStatus::Disconnected => "disconnected",
                PeerBrowseStatus::Malformed => "malformed",
                PeerBrowseStatus::Limit => "limit",
            };
            let files: Vec<_> = page
                .files
                .into_iter()
                .map(|result| {
                    json!({
                        "directory": result.directory.as_deref(),
                        "fileHash": result.file.file_hash.to_string(),
                        "displayName": result.file.display_name,
                        "sizeBytes": result.file.file_size,
                    })
                })
                .collect();
            api_ok(json!({
                "searchId": page.search_id.to_string(),
                "status": status,
                "total": page.total,
                "offset": page.offset,
                "files": files,
            }))
            .into_response()
        }
        Ok(None) => missing_browse(),
        Err(error) => super::super::persistence::persistence_error(error),
    }
}

fn missing_browse() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "download source or browse request not found",
    )
    .into_response()
}
pub(crate) async fn download_source_add_friend(
    state: State<RestState>,
    path: Path<(String, String)>,
) -> Response {
    apply(state, path, Action::AddFriend).await
}
pub(crate) async fn download_source_remove_friend(
    state: State<RestState>,
    path: Path<(String, String)>,
) -> Response {
    apply(state, path, Action::RemoveFriend).await
}
pub(crate) async fn download_source_remove(
    state: State<RestState>,
    path: Path<(String, String)>,
) -> Response {
    apply(state, path, Action::Remove).await
}
pub(crate) async fn download_source_ban(
    state: State<RestState>,
    path: Path<(String, String)>,
) -> Response {
    apply(state, path, Action::Ban).await
}
pub(crate) async fn download_source_unban(
    state: State<RestState>,
    path: Path<(String, String)>,
) -> Response {
    apply(state, path, Action::Unban).await
}
