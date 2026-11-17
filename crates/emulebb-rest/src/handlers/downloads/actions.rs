use super::*;
use emulebb_core::{DownloadAction, DownloadChange, DownloadControlError};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ids {
    ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Remove {
    ids: Vec<String>,
    delete_data: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Outcome {
    id: String,
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
fn failure(id: String, status: StatusCode, code: &'static str, message: &'static str) -> Outcome {
    Outcome {
        id,
        status: "failed",
        http_status: status.as_u16(),
        error: Some(Failure {
            code,
            message,
            details: serde_json::json!({}),
        }),
    }
}
async fn apply(state: RestState, action: DownloadAction, ids: Vec<String>) -> Response {
    if !(1..=100).contains(&ids.len()) {
        return invalid("expected 1 to 100 download IDs");
    }
    let ids = match ids
        .iter()
        .map(|id| job_id(id))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(error) => return *error,
    };
    if ids
        .iter()
        .enumerate()
        .any(|(index, id)| ids[..index].contains(id))
    {
        return invalid("download IDs must be distinct");
    }
    let accepted_status = if matches!(action, DownloadAction::Verify) {
        200
    } else {
        202
    };
    match state.core.control_downloads(action, &ids).await {
        Err(error) => super::super::persistence::persistence_error(error),
        Ok(batch) => {
            let data = batch
                .results()
                .iter()
                .map(|value| {
                    let id = value.id.to_string();
                    match value.outcome {
                        Ok(DownloadChange::Changed) => Outcome {
                            id,
                            status: "accepted",
                            http_status: accepted_status,
                            error: None,
                        },
                        Ok(DownloadChange::Unchanged) => Outcome {
                            id,
                            status: "unchanged",
                            http_status: 200,
                            error: None,
                        },
                        Ok(DownloadChange::NotFound) => {
                            failure(id, StatusCode::NOT_FOUND, "NOT_FOUND", "download not found")
                        }
                        Err(DownloadControlError::Completed) => failure(
                            id,
                            StatusCode::CONFLICT,
                            "DOWNLOAD_COMPLETED",
                            "completed download cannot be started again",
                        ),
                        Err(DownloadControlError::Unavailable) => failure(
                            id,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "DOWNLOAD_UNAVAILABLE",
                            "download control is temporarily unavailable",
                        ),
                        Err(DownloadControlError::Failed) => failure(
                            id,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "DOWNLOAD_FAILED",
                            "download control failed",
                        ),
                        Err(DownloadControlError::OutputMissing) => failure(
                            id,
                            StatusCode::CONFLICT,
                            "OUTPUT_MISSING",
                            "completed output is missing",
                        ),
                        Err(DownloadControlError::OutputDamaged) => failure(
                            id,
                            StatusCode::CONFLICT,
                            "OUTPUT_DAMAGED",
                            "completed output failed verification",
                        ),
                    }
                })
                .collect::<Vec<_>>();
            item(StatusCode::MULTI_STATUS, data)
        }
    }
}
pub(crate) async fn download_start(State(state): State<RestState>, body: Bytes) -> Response {
    let ids = match parse_required_json_body::<Ids>(&body) {
        Ok(value) => value.ids,
        Err(error) => return *error,
    };
    apply(state, DownloadAction::Start, ids).await
}
pub(crate) async fn download_stop(State(state): State<RestState>, body: Bytes) -> Response {
    let ids = match parse_required_json_body::<Ids>(&body) {
        Ok(value) => value.ids,
        Err(error) => return *error,
    };
    apply(state, DownloadAction::Stop, ids).await
}
pub(crate) async fn download_verify(State(state): State<RestState>, body: Bytes) -> Response {
    let ids = match parse_required_json_body::<Ids>(&body) {
        Ok(value) => value.ids,
        Err(error) => return *error,
    };
    apply(state, DownloadAction::Verify, ids).await
}
pub(crate) async fn download_remove(State(state): State<RestState>, body: Bytes) -> Response {
    let request = match parse_required_json_body::<Remove>(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    apply(
        state,
        DownloadAction::Remove {
            delete_data: request.delete_data,
        },
        request.ids,
    )
    .await
}
