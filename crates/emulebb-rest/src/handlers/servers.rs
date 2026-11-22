//! Bounded ID-addressed eD2K server resources and explicit network actions.

use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::resource::{self, item_document, page_document, retained_json};
use emulebb_metadata::{
    MetadataServerCreate, MetadataServerQuery, MetadataServerUpdate, ServerEndpointConflict,
};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Query {
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(default)]
    count_total: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    address: String,
    port: u16,
    #[serde(default = "normal_priority")]
    priority: String,
    #[serde(default, rename = "static")]
    static_server: bool,
    #[serde(default = "enabled")]
    enabled: bool,
}
fn normal_priority() -> String {
    "normal".into()
}
fn enabled() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Update {
    priority: Option<String>,
    #[serde(rename = "static")]
    static_server: Option<bool>,
    enabled: Option<bool>,
}
fn missing() -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "server not found").into_response()
}

use crate::handlers::prelude::*;

pub(crate) async fn servers(State(state): State<RestState>, RawQuery(raw): RawQuery) -> Response {
    let query = match parse_optional_query::<Query>(raw.as_deref()) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let limit = query.limit.unwrap_or(100);
    if !(1..=200).contains(&limit) {
        return out_of_range_response("limit", 1, 200);
    }
    let after_id = match query
        .cursor
        .as_deref()
        .map(|cursor| {
            resource::decode_cursor(cursor, "servers")
                .and_then(|position| resource::identity(&position))
        })
        .transpose()
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    match state
        .core
        .server_resource_page(MetadataServerQuery {
            after_id,
            limit,
            count_total: query.count_total,
        })
        .await
    {
        Ok(page) => {
            let cursor = page
                .next_after_id
                .map(|id| resource::encode_cursor("servers", &id.to_string()));
            retained_json(
                &page,
                &page_document(&page.servers, cursor, page.has_more, page.total),
            )
        }
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn create_server(State(state): State<RestState>, body: Bytes) -> Response {
    let request = match parse_required_json_body::<Create>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let address = request.address.trim();
    if address.is_empty() {
        return resource::invalid("address is required");
    }
    if request.port == 0 {
        return resource::invalid("port must be in the range 1..65535");
    }
    let input = MetadataServerCreate {
        address: address.to_owned(),
        port: request.port,
        priority: request.priority,
        static_server: request.static_server,
        enabled: request.enabled,
    };
    match state.core.create_server_resource(&input).await {
        Ok(id) => (
            StatusCode::CREATED,
            [(
                axum::http::header::LOCATION,
                format!("/api/v1/servers/{id}"),
            )],
            axum::Json(item_document(json!({"id": id.to_string()}))),
        )
            .into_response(),
        Err(error) if error.is::<ServerEndpointConflict>() => api_error(
            StatusCode::CONFLICT,
            "SERVER_EXISTS",
            "server endpoint already exists",
        )
        .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn servers_connect(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.connect_ed2k().await {
        Ok(_status) => connection_response(server_connect_acknowledgement(&state).await),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn servers_disconnect(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.disconnect_ed2k_server().await {
        Ok(_status) => connection_response(server_status_response(&state).await),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMULE_ERROR",
            error.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn servers_import_met_url(
    State(state): State<RestState>,
    body: Bytes,
) -> impl IntoResponse {
    let request = match parse_required_json_body::<UrlImportRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let url = request.url.trim();
    match state.core.import_server_met_url(url).await {
        Ok(true) => api_ok(json!({ "ok": true, "imported": true })).into_response(),
        Ok(false) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMULE_ERROR",
            "failed to update server.met from URL",
        )
        .into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn server(State(state): State<RestState>, Path(id): Path<String>) -> Response {
    let id = match resource::identity(&id) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    match state.core.server_resource(id).await {
        Ok(Some(server)) => retained_json(&server, &item_document(&*server)),
        Ok(None) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn update_server(
    State(state): State<RestState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let id = match resource::identity(&id) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    let request = match parse_required_json_body::<Update>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if request.priority.is_none() && request.static_server.is_none() && request.enabled.is_none() {
        return resource::invalid("server update requires at least one field");
    }
    match state
        .core
        .update_server_resource(
            id,
            &MetadataServerUpdate {
                priority: request.priority,
                static_server: request.static_server,
                enabled: request.enabled,
            },
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn delete_server(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Response {
    let id = match resource::identity(&id) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    match state.core.delete_server_resource(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

pub(crate) async fn connect_server(
    State(state): State<RestState>,
    Path(id): Path<String>,
) -> Response {
    let id = match resource::identity(&id) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    let endpoint = match state.core.server_by_id(id).await {
        Ok(Some(server)) => match server
            .try_project(emulebb_metadata::SERVER_READ_MAX_BYTES, |record| {
                Ok(record.server.endpoint())
            }) {
            Ok(endpoint) => endpoint,
            Err(error) => return super::persistence::persistence_error(error),
        },
        Ok(None) => return missing(),
        Err(error) => return super::persistence::persistence_error(error),
    };
    match state.core.connect_ed2k_server(&endpoint).await {
        Ok(Some(_status)) => connection_response(server_connect_acknowledgement(&state).await),
        Ok(None) => missing(),
        Err(error) => super::persistence::persistence_error(error),
    }
}

fn connection_response(result: anyhow::Result<serde_json::Value>) -> Response {
    match result {
        Ok(value) => api_ok(value).into_response(),
        Err(error) => super::persistence::persistence_error(error),
    }
}
