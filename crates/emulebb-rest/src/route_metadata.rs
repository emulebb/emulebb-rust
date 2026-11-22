//! REST route metadata validation shared by the router middleware.
//!
//! This module validates the Rust REST contract in a stable order: registered
//! route, decoded unique query fields, query value checks, DELETE-body
//! rejection, then JSON content-type validation.

use std::collections::HashSet;

use axum::{
    body::{Body, HttpBody},
    extract::MatchedPath,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use percent_encoding::percent_decode_str;

use crate::{
    envelope::{api_error, out_of_range_response},
    request_body_policy::BufferedApiRequestBody,
    route_body_metadata::validate_json_body_fields,
};

pub(crate) async fn validate_route_metadata(request: Request<Body>, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let parameterized = request
        .extensions()
        .get::<MatchedPath>()
        .is_none_or(|matched| matched.as_str().contains('{'));
    let Some(allowed_query_fields) = route_query_fields(&method, &path, parameterized) else {
        return next.run(request).await;
    };
    if let Err(response) = validate_path_parameters(&method, &path) {
        return *response;
    }
    let query_fields = if let Some(query) = request.uri().query() {
        match parse_query_fields(query) {
            Ok(fields) => fields,
            Err(response) => return *response,
        }
    } else {
        Vec::new()
    };
    for (name, value) in &query_fields {
        if !allowed_query_fields.contains(&name.as_str()) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                format!("unknown query parameter: {name}"),
            )
            .into_response();
        }
        if name == "limit"
            && let Err(error) = parse_bounded_query_value(
                value,
                1,
                if path == "/api/v1/downloads"
                    || path.starts_with("/api/v1/downloads/")
                    || path.starts_with("/api/v1/library/")
                    || path.starts_with("/api/v1/searches")
                {
                    200
                } else {
                    1000
                },
                "limit",
            )
        {
            return query_scalar_error_response(error).into_response();
        }
        if name == "offset"
            && let Err(error) = parse_bounded_query_value(value, 0, i32::MAX as u64, "offset")
        {
            return query_scalar_error_response(error).into_response();
        }
        if name == "category" && !emulebb_core::valid_category_name(value) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "category must be a valid category name",
            )
            .into_response();
        }
        if name == "sort" && path.starts_with("/api/v1/searches/") && !is_search_result_sort(value)
        {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "sort must be one of displayName, sizeBytes, sources, completeSources, rating, fileType, artist, album, title, lengthSeconds, bitrateKbps, codec",
            )
            .into_response();
        }
        if name == "order" && !matches!(value.as_str(), "asc" | "desc") {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "order must be one of asc, desc",
            )
            .into_response();
        }
        if is_boolean_query_field(name) && !is_boolean_query_value(value) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                format!("{name} must be true or false"),
            )
            .into_response();
        }
    }
    if let Err(response) = validate_destructive_query_confirmation(&method, &path, &query_fields) {
        return *response;
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

    let body = request
        .extensions()
        .get::<BufferedApiRequestBody>()
        .expect("API request body policy must run before route metadata validation")
        .as_bytes();

    if !is_ascii_whitespace_only(body) {
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
        if let Err(response) = validate_json_body_fields(&method, &path, body) {
            return *response;
        }
    }

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

fn is_search_result_sort(value: &str) -> bool {
    matches!(
        value,
        "displayName"
            | "sizeBytes"
            | "sources"
            | "completeSources"
            | "rating"
            | "fileType"
            | "artist"
            | "album"
            | "title"
            | "lengthSeconds"
            | "bitrateKbps"
            | "codec"
    )
}

fn is_boolean_query_field(name: &str) -> bool {
    matches!(name, "confirm" | "countTotal")
}

fn is_boolean_query_value(value: &str) -> bool {
    matches!(value, "true" | "false")
}

fn validate_destructive_query_confirmation(
    method: &str,
    path: &str,
    fields: &[(String, String)],
) -> Result<(), Box<Response>> {
    if !uses_destructive_query_confirmation(method, path) {
        return Ok(());
    }
    if fields
        .iter()
        .find(|(name, _)| name == "confirm")
        .map(|(_, value)| value.as_str())
        != Some("true")
    {
        return Err(Box::new(
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "confirm must be true",
            )
            .into_response(),
        ));
    }
    Ok(())
}

fn uses_destructive_query_confirmation(method: &str, path: &str) -> bool {
    method == "DELETE" && path == "/api/v1/searches"
}

#[derive(Clone, Copy)]
enum QueryScalarError {
    NotUnsigned {
        field: &'static str,
    },
    OutOfRange {
        field: &'static str,
        min: u64,
        max: u64,
    },
}

fn parse_bounded_query_value(
    value: &str,
    min: u64,
    max: u64,
    field: &'static str,
) -> Result<(), QueryScalarError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(QueryScalarError::NotUnsigned { field });
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| QueryScalarError::NotUnsigned { field })?;
    if value < min || value > max {
        return Err(QueryScalarError::OutOfRange { field, min, max });
    }
    Ok(())
}

fn query_scalar_error_response(error: QueryScalarError) -> Response {
    match error {
        QueryScalarError::NotUnsigned { field } => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!("{field} must be an unsigned number"),
        )
        .into_response(),
        QueryScalarError::OutOfRange { field, min, max } if matches!(field, "limit" | "offset") => {
            out_of_range_response(field, min, max)
        }
        QueryScalarError::OutOfRange { field, .. } => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!("{field} is out of range"),
        )
        .into_response(),
    }
}

fn validate_path_parameters(method: &str, path: &str) -> Result<(), Box<Response>> {
    let segments = path
        .strip_prefix("/api/v1/")
        .map(|path| path.split('/').collect::<Vec<_>>())
        .unwrap_or_default();
    match (method, segments.as_slice()) {
        ("GET" | "DELETE", ["library", "tags", name]) => {
            let name = decode_path_parameter(name, "tagName")?;
            if !emulebb_core::valid_category_name(&name) {
                return Err(Box::new(
                    api_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ARGUMENT",
                        "tagName must be a valid tag name",
                    )
                    .into_response(),
                ));
            }
        }
        ("GET", ["library", "files", hash, "tags" | "locations"]) => {
            validate_lowercase_md4_hex(hash, "hash")?
        }
        ("GET" | "PATCH" | "DELETE", ["categories", category]) => {
            let category = decode_path_parameter(category, "categoryName")?;
            if !emulebb_core::valid_category_name(&category) {
                return Err(Box::new(
                    api_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ARGUMENT",
                        "categoryName must be a valid category name",
                    )
                    .into_response(),
                ));
            }
        }
        ("DELETE", ["friends", user_hash]) => validate_lowercase_md4_hex(user_hash, "userHash")?,
        ("GET" | "DELETE", ["searches", search_id]) | ("POST", ["searches", search_id, "stop"]) => {
            validate_search_id(search_id)?
        }
        ("GET", ["searches", search_id, "results"]) => validate_search_id(search_id)?,
        ("GET", ["searches", search_id, "results", result_id]) => {
            validate_search_id(search_id)?;
            validate_positive_decimal_id(result_id, "resultId")?;
        }
        ("GET" | "PATCH" | "DELETE", ["servers", server_id])
        | ("POST", ["servers", server_id, "operations", "connect"]) => {
            let server_id = decode_path_parameter(server_id, "serverId")?;
            validate_endpoint_path_token(&server_id, "serverId")?
        }
        ("GET" | "PATCH", ["library", "files", hash]) => validate_lowercase_md4_hex(hash, "hash")?,
        ("GET" | "PATCH", ["downloads", id])
        | ("GET", ["downloads", id, "parts" | "sources" | "comments"]) => {
            let id = decode_path_parameter(id, "id")?;
            id.parse::<emulebb_core::JobId>().map_err(|_| {
                Box::new(
                    api_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ARGUMENT",
                        "id must be a positive decimal i64 string",
                    )
                    .into_response(),
                )
            })?;
        }
        ("GET", ["downloads", id, "sources", client_id])
        | ("POST", ["downloads", id, "sources", client_id, "operations", _]) => {
            let id = decode_path_parameter(id, "id")?;
            id.parse::<emulebb_core::JobId>().map_err(|_| {
                Box::new(
                    api_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ARGUMENT",
                        "id must be a positive decimal i64 string",
                    )
                    .into_response(),
                )
            })?;
            let client_id = decode_path_parameter(client_id, "clientId")?;
            validate_client_id_path_token(&client_id)?;
        }
        ("GET", ["uploads", client_id])
        | ("POST", ["uploads", client_id, "operations", _])
        | ("GET", ["upload-queue", client_id])
        | ("POST", ["upload-queue", client_id, "operations", _]) => {
            let id = decode_path_parameter(client_id, "id")?;
            if !uuid::Uuid::try_parse(&id).is_ok_and(|parsed| parsed.hyphenated().to_string() == id)
            {
                return Err(Box::new(
                    api_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ARGUMENT",
                        "id must be a lowercase hyphenated UUID",
                    )
                    .into_response(),
                ));
            }
        }
        ("GET", ["searches", search_id, "results", result_id, "observations"])
        | ("POST", ["searches", search_id, "results", result_id, "download"]) => {
            validate_search_id(search_id)?;
            validate_positive_decimal_id(result_id, "resultId")?;
        }
        _ => {}
    }
    Ok(())
}

fn decode_path_parameter(value: &str, field: &'static str) -> Result<String, Box<Response>> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| {
            Box::new(
                api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    format!("{field} must be valid UTF-8 after URL decoding"),
                )
                .into_response(),
            )
        })
}

fn validate_search_id(value: &str) -> Result<(), Box<Response>> {
    validate_positive_decimal_id(value, "searchId")
}

fn validate_positive_decimal_id(value: &str, field: &'static str) -> Result<(), Box<Response>> {
    let value = decode_path_parameter(value, field)?;
    if value
        .parse::<i64>()
        .is_ok_and(|id| id > 0 && id.to_string() == value)
    {
        return Ok(());
    }
    Err(Box::new(
        api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!("{field} must be a positive decimal i64 string"),
        )
        .into_response(),
    ))
}

fn validate_lowercase_md4_hex(value: &str, field: &'static str) -> Result<(), Box<Response>> {
    if is_lowercase_md4_hex(value) {
        return Ok(());
    }
    Err(Box::new(
        api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!("{field} must be a 32-character lowercase hex string"),
        )
        .into_response(),
    ))
}

fn is_lowercase_md4_hex(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_endpoint_path_token(value: &str, field: &'static str) -> Result<(), Box<Response>> {
    let Some((address, port)) = value.rsplit_once(':') else {
        return Err(endpoint_path_token_error(field));
    };
    if address.is_empty() || port.is_empty() {
        return Err(endpoint_path_token_error(field));
    }
    let Ok(port) = port.parse::<u64>() else {
        return Err(endpoint_path_token_error(field));
    };
    if !(1..=u16::MAX as u64).contains(&port) {
        return Err(endpoint_path_token_error(field));
    }
    Ok(())
}

fn endpoint_path_token_error(field: &'static str) -> Box<Response> {
    Box::new(
        api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!("{field} must use address:port with a port in the range 1..65535"),
        )
        .into_response(),
    )
}

fn validate_client_id_path_token(value: &str) -> Result<(), Box<Response>> {
    if is_lowercase_md4_hex(value) || is_endpoint_path_token(value) {
        return Ok(());
    }
    Err(Box::new(
        api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "clientId must be a 32-character lowercase hex string or address:port",
        )
        .into_response(),
    ))
}

fn is_endpoint_path_token(value: &str) -> bool {
    let Some((address, port)) = value.rsplit_once(':') else {
        return false;
    };
    if address.is_empty() || port.is_empty() {
        return false;
    }
    let Ok(port) = port.parse::<u64>() else {
        return false;
    };
    (1..=u16::MAX as u64).contains(&port)
}

fn route_query_fields(
    method: &str,
    path: &str,
    parameterized: bool,
) -> Option<&'static [&'static str]> {
    const SEARCH_PAGE: &[&str] = &["limit", "cursor"];
    const NONE: &[&str] = &[];
    const SNAPSHOT: &[&str] = &["limit"];
    const PAGE: &[&str] = &["offset", "limit"];
    const LIBRARY_FILES: &[&str] = &[
        "limit",
        "cursor",
        "q",
        "view",
        "sort",
        "order",
        "rootId",
        "tag",
        "sharingEnabled",
        "countTotal",
    ];
    const LIBRARY_TAGS: &[&str] = &["limit", "cursor"];
    const DOWNLOADS: &[&str] = &["view", "category", "cursor", "limit"];
    const CONFIRM: &[&str] = &["confirm"];
    const SHARED_FILE_IGNORE_PATTERN: &[&str] = &["pattern"];
    const UPLOAD_QUEUE: &[&str] = &["cursor", "limit", "countTotal"];

    if matches!(
        path,
        "/api/v1/library/files/tags/add" | "/api/v1/library/files/tags/remove"
    ) {
        return (method == "POST").then_some(NONE);
    }
    if matches!(
        path,
        "/api/v1/downloads/start"
            | "/api/v1/downloads/stop"
            | "/api/v1/downloads/verify"
            | "/api/v1/downloads/remove"
    ) {
        return (method == "POST").then_some(NONE);
    }

    #[cfg(feature = "packet-diagnostics")]
    if method == "POST"
        && matches!(
            path,
            "/api/v1/diagnostics/protocol-fixtures/queued-lowid-sources"
                | "/api/v1/diagnostics/protocol-fixtures/buddy-relay-eligibility"
                | "/api/v1/diagnostics/protocol-fixtures/client-udp-queue-pressure"
                | "/api/v1/diagnostics/protocol-controls/queued-source-reasks"
        )
    {
        return Some(NONE);
    }

    match (method, path) {
        ("GET", "/api/v1/app")
        | ("GET", "/api/v1/capabilities")
        | ("GET", "/api/v1/events")
        | ("GET", "/api/v1/events/status")
        | ("GET", "/api/v1/settings")
        | ("GET", "/api/v1/settings/surface")
        | ("PATCH", "/api/v1/settings")
        | ("GET", "/api/v1/status")
        | ("GET", "/api/v1/stats")
        | ("GET", "/api/v1/diagnostics")
        | ("GET", "/api/v1/network")
        | ("GET", "/api/v1/nat")
        | ("POST", "/api/v1/nat/operations/refresh")
        | ("GET", "/api/v1/vpn-guard")
        | ("POST", "/api/v1/vpn-guard/operations/probe")
        | ("GET", "/api/v1/categories")
        | ("POST", "/api/v1/categories")
        | ("GET", "/api/v1/friends")
        | ("POST", "/api/v1/friends")
        | ("GET", "/api/v1/ip-filter")
        | ("POST", "/api/v1/ip-filter/operations/reload")
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
        | ("POST", "/api/v1/searches")
        | ("POST", "/api/v1/library/roots")
        | ("GET", "/api/v1/library/ignores")
        | ("POST", "/api/v1/library/ignores")
        | ("GET", "/api/v1/library/scan")
        | ("POST", "/api/v1/library/scan")
        | ("GET", "/api/v1/upload-queue")
        | ("POST", "/api/v1/downloads")
        | ("POST", "/api/v1/logs/operations/clear")
        | ("POST", "/api/v1/app/shutdown")
        | ("POST", "/api/v1/diagnostics/bundles")
        | ("POST", "/api/v1/diagnostics/crash-tests") => Some(match path {
            "/api/v1/upload-queue" if method == "GET" => UPLOAD_QUEUE,
            _ => NONE,
        }),
        ("GET", "/api/v1/searches") => Some(SEARCH_PAGE),
        ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
        ("GET", "/api/v1/library/files") => Some(LIBRARY_FILES),
        ("GET", "/api/v1/uploads") => Some(UPLOAD_QUEUE),
        ("GET", "/api/v1/kad/nodes") => Some(PAGE),
        ("POST", "/api/v1/library/files/sharing") => Some(NONE),
        ("GET", "/api/v1/library/tags") => Some(LIBRARY_TAGS),
        ("GET", "/api/v1/library/roots") => Some(LIBRARY_TAGS),
        ("POST", "/api/v1/library/tags") => Some(NONE),
        ("GET", "/api/v1/downloads") => Some(DOWNLOADS),
        ("GET", "/api/v1/logs") => Some(SNAPSHOT),
        ("DELETE", "/api/v1/searches") => Some(CONFIRM),
        ("DELETE", "/api/v1/library/ignores") => Some(SHARED_FILE_IGNORE_PATTERN),
        _ if parameterized => route_query_fields_for_parameterized(method, path),
        _ => None,
    }
}

fn route_query_fields_for_parameterized(
    method: &str,
    path: &str,
) -> Option<&'static [&'static str]> {
    const NONE: &[&str] = &[];
    const SEARCH_OBSERVATIONS: &[&str] = &["limit", "cursor"];
    const LIBRARY_TAGS: &[&str] = &["limit", "cursor"];
    const SEARCH_RESULTS: &[&str] = &["limit", "cursor", "sort", "order"];

    let segments = path
        .strip_prefix("/api/v1/")?
        .split('/')
        .collect::<Vec<_>>();
    match (method, segments.as_slice()) {
        ("GET" | "PATCH" | "DELETE", ["library", "roots", _]) => Some(NONE),
        ("GET" | "DELETE", ["library", "tags", _]) => Some(NONE),
        ("GET", ["library", "files", _, "tags"]) => Some(LIBRARY_TAGS),
        ("GET", ["library", "files", _, "locations"]) => Some(LIBRARY_TAGS),
        ("GET", ["categories", _])
        | ("PATCH", ["categories", _])
        | ("DELETE", ["categories", _])
        | ("DELETE", ["friends", _])
        | ("GET", ["servers", _])
        | ("PATCH", ["servers", _])
        | ("DELETE", ["servers", _])
        | ("DELETE", ["searches", _])
        | ("GET", ["library", "files", _])
        | ("PATCH", ["library", "files", _])
        | ("PATCH", ["library", "ignores", "defaults", _])
        | ("GET", ["downloads", _])
        | ("PATCH", ["downloads", _])
        | ("GET", ["downloads", _, "sources", _])
        | ("GET", ["uploads", _])
        | ("GET", ["upload-queue", _]) => Some(NONE),
        ("POST", ["nat", "operations", "refresh"])
        | ("POST", ["servers", _, "operations", "connect"])
        | ("POST", ["vpn-guard", "operations", "probe"])
        | ("POST", ["searches", _, "results", _, "download"]) => Some(NONE),
        ("GET", ["downloads", _, "parts" | "comments" | "sources"]) => Some(&["cursor", "limit"]),
        ("POST", ["downloads", _, "sources", _, "operations", operation])
            if matches!(
                *operation,
                "browse" | "add-friend" | "remove-friend" | "remove" | "ban" | "unban"
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
        ("GET", ["searches", _]) | ("GET", ["searches", _, "results", _]) => Some(NONE),
        ("POST", ["searches", _, "stop"]) => Some(NONE),
        ("GET", ["searches", _, "results"]) => Some(SEARCH_RESULTS),
        ("GET", ["searches", _, "results", _, "observations"]) => Some(SEARCH_OBSERVATIONS),
        _ => None,
    }
}
