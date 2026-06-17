//! REST route metadata validation shared by the router middleware.
//!
//! This module mirrors the MFC route-spec validation order: registered route,
//! decoded unique query fields, query value checks, DELETE-body rejection, then
//! JSON content-type validation.

use std::collections::HashSet;

use axum::{
    body::{Body, HttpBody, to_bytes},
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::envelope::api_error;

pub(crate) async fn validate_route_metadata(request: Request<Body>, next: Next) -> Response {
    let method = request.method().as_str();
    let path = request.uri().path();
    let Some(allowed_query_fields) = route_query_fields(method, path) else {
        return next.run(request).await;
    };
    if let Some(query) = request.uri().query() {
        for (name, value) in match parse_query_fields(query) {
            Ok(fields) => fields,
            Err(response) => return *response,
        } {
            if !allowed_query_fields.contains(&name.as_str()) {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    format!("unknown query parameter: {name}"),
                )
                .into_response();
            }
            if name == "state" && !is_transfer_state_name(&value) {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    "state must be one of downloading, paused, queued, checking, completing, completed, error, missingfiles",
                )
                .into_response();
            }
            if is_boolean_query_field(&name) && !is_boolean_query_value(&value) {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    format!("{name} must be true or false"),
                )
                .into_response();
            }
            if name == "categoryId" {
                match parse_u32_query_value(&value) {
                    Ok(()) => {}
                    Err(message) => {
                        return api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message)
                            .into_response();
                    }
                }
            }
        }
    }
    if request.body().size_hint().upper() == Some(0) {
        return next.run(request).await;
    }

    let is_delete = method == "DELETE";
    let is_json_content = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_json_content_type);

    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, usize::MAX).await {
        Ok(body) => body,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                format!("invalid request body: {error}"),
            )
            .into_response();
        }
    };

    if !is_ascii_whitespace_only(&body) {
        if is_delete {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "DELETE request bodies are not supported",
            )
            .into_response();
        }
        if !is_json_content {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "Content-Type must be application/json for JSON request bodies",
            )
            .into_response();
        }
    }

    let request = Request::from_parts(parts, Body::from(body));
    next.run(request).await
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim()
        .eq_ignore_ascii_case("application/json")
}

fn is_ascii_whitespace_only(body: &[u8]) -> bool {
    body.iter().all(|byte| byte.is_ascii_whitespace())
}

fn parse_query_fields(query: &str) -> Result<Vec<(String, String)>, Box<Response>> {
    let fields = serde_urlencoded::from_str::<Vec<(String, String)>>(query).map_err(|error| {
        Box::new(
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                error.to_string(),
            )
            .into_response(),
        )
    })?;
    let mut seen = HashSet::new();
    for (name, _) in &fields {
        if !seen.insert(name.clone()) {
            return Err(Box::new(
                api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    format!("duplicate query parameter: {name}"),
                )
                .into_response(),
            ));
        }
    }
    Ok(fields)
}

fn is_transfer_state_name(value: &str) -> bool {
    matches!(
        value,
        "downloading"
            | "paused"
            | "queued"
            | "checking"
            | "completing"
            | "completed"
            | "error"
            | "missingfiles"
    )
}

fn is_boolean_query_field(name: &str) -> bool {
    matches!(
        name,
        "confirm" | "includeScoreBreakdown" | "includeEvidence" | "exactTotal"
    )
}

fn is_boolean_query_value(value: &str) -> bool {
    matches!(value, "true" | "false")
}

fn parse_u32_query_value(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("categoryId must be an unsigned number");
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| "categoryId must be an unsigned number")?;
    if value > u32::MAX as u64 {
        return Err("categoryId is out of range");
    }
    Ok(())
}

fn route_query_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
    const NONE: &[&str] = &[];
    const SNAPSHOT: &[&str] = &["limit"];
    const PAGE: &[&str] = &["offset", "limit"];
    const TRANSFERS: &[&str] = &["state", "categoryId", "offset", "limit"];
    const CONFIRM: &[&str] = &["confirm"];
    const UPLOAD_QUEUE: &[&str] = &["offset", "limit", "includeScoreBreakdown"];

    match (method, path) {
        ("GET", "/api/v1/app")
        | ("GET", "/api/v1/capabilities")
        | ("GET", "/api/v1/app/preferences")
        | ("GET", "/api/v1/status")
        | ("GET", "/api/v1/stats")
        | ("GET", "/api/v1/categories")
        | ("POST", "/api/v1/categories")
        | ("GET", "/api/v1/friends")
        | ("POST", "/api/v1/friends")
        | ("GET", "/api/v1/kad")
        | ("POST", "/api/v1/kad/operations/import-nodes-url")
        | ("POST", "/api/v1/kad/operations/start")
        | ("POST", "/api/v1/kad/operations/stop")
        | ("POST", "/api/v1/kad/operations/bootstrap")
        | ("POST", "/api/v1/kad/operations/recheck-firewall")
        | ("GET", "/api/v1/servers")
        | ("POST", "/api/v1/servers")
        | ("POST", "/api/v1/servers/operations/connect")
        | ("POST", "/api/v1/servers/operations/disconnect")
        | ("POST", "/api/v1/servers/operations/import-met-url")
        | ("GET", "/api/v1/searches")
        | ("POST", "/api/v1/searches")
        | ("GET", "/api/v1/shared-directories")
        | ("PATCH", "/api/v1/shared-directories")
        | ("POST", "/api/v1/shared-directories/operations/reload")
        | ("POST", "/api/v1/shared-files")
        | ("POST", "/api/v1/shared-files/operations/reload")
        | ("GET", "/api/v1/uploads")
        | ("GET", "/api/v1/upload-queue")
        | ("POST", "/api/v1/transfers")
        | ("POST", "/api/v1/transfers/operations/clear-completed")
        | ("POST", "/api/v1/logs/operations/clear")
        | ("POST", "/api/v1/app/shutdown")
        | ("POST", "/api/v1/diagnostics/dumps")
        | ("POST", "/api/v1/diagnostics/crash-tests") => Some(match path {
            "/api/v1/upload-queue" if method == "GET" => UPLOAD_QUEUE,
            _ => NONE,
        }),
        ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
        ("GET", "/api/v1/shared-files") => Some(PAGE),
        ("GET", "/api/v1/transfers") => Some(TRANSFERS),
        ("GET", "/api/v1/logs") => Some(SNAPSHOT),
        ("DELETE", "/api/v1/searches") => Some(CONFIRM),
        _ => route_query_fields_for_parameterized(method, path),
    }
}

fn route_query_fields_for_parameterized(
    method: &str,
    path: &str,
) -> Option<&'static [&'static str]> {
    const NONE: &[&str] = &[];
    const CONFIRM: &[&str] = &["confirm"];
    const SEARCH: &[&str] = &["offset", "limit", "includeEvidence", "exactTotal"];

    let segments = path
        .strip_prefix("/api/v1/")?
        .split('/')
        .collect::<Vec<_>>();
    match (method, segments.as_slice()) {
        ("GET", ["categories", _])
        | ("PATCH", ["categories", _])
        | ("DELETE", ["categories", _])
        | ("DELETE", ["friends", _])
        | ("GET", ["servers", _])
        | ("PATCH", ["servers", _])
        | ("DELETE", ["servers", _])
        | ("DELETE", ["searches", _])
        | ("GET", ["shared-files", _])
        | ("PATCH", ["shared-files", _])
        | ("DELETE", ["shared-files", _])
        | ("GET", ["shared-files", _, "ed2k-link"])
        | ("GET", ["shared-files", _, "comments"])
        | ("GET", ["transfers", _])
        | ("PATCH", ["transfers", _])
        | ("DELETE", ["transfers", _])
        | ("GET", ["transfers", _, "details"])
        | ("GET", ["transfers", _, "sources"])
        | ("GET", ["transfers", _, "sources", _])
        | ("GET", ["uploads", _])
        | ("GET", ["upload-queue", _]) => Some(NONE),
        ("POST", ["servers", _, "operations", "connect"])
        | ("POST", ["searches", _, "results", _, "operations", "download"]) => Some(NONE),
        ("POST", ["transfers", _, "operations", operation])
            if matches!(
                *operation,
                "pause" | "resume" | "stop" | "recheck" | "preview"
            ) =>
        {
            Some(NONE)
        }
        ("POST", ["transfers", _, "sources", _, "operations", operation])
            if matches!(
                *operation,
                "browse"
                    | "add-friend"
                    | "remove-friend"
                    | "remove"
                    | "ban"
                    | "unban"
                    | "release-slot"
            ) =>
        {
            Some(NONE)
        }
        ("POST", ["uploads", _, "operations", operation])
        | ("POST", ["upload-queue", _, "operations", operation])
            if matches!(
                *operation,
                "remove" | "release-slot" | "add-friend" | "remove-friend" | "ban" | "unban"
            ) =>
        {
            Some(NONE)
        }
        ("GET", ["searches", _]) => Some(SEARCH),
        ("DELETE", ["shared-files", _, "file"]) | ("DELETE", ["transfers", _, "files"]) => {
            Some(CONFIRM)
        }
        _ => None,
    }
}
