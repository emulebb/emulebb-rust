use super::*;
use serde_json::json;

enum Action {
    Browse,
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
        Action::Browse => state
            .core
            .browse_download_source(id, &client)
            .await
            .map(|found| found.then(|| json!({"ok":true,"alreadyPending":false,"searchId":null}))),
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
    state: State<RestState>,
    path: Path<(String, String)>,
) -> Response {
    apply(state, path, Action::Browse).await
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
