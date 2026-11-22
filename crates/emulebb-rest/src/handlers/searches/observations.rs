//! Session-scoped raw provenance, independent of summary browsing.
use super::super::resource;
use super::*;
use axum::response::Response;
use emulebb_metadata::MetadataSearchResultObservation;

pub(crate) async fn search_result_observations(
    State(state): State<RestState>,
    Path((session, claim)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match parse_optional_query::<super::browse::Paging>(raw.as_deref()) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let identity = |value: &str| {
        value
            .parse::<i64>()
            .ok()
            .filter(|id| *id > 0 && id.to_string() == value)
    };
    let (Some(session), Some(claim)) = (identity(&session), identity(&claim)) else {
        return resource::invalid("search and result IDs must be positive decimal i64 strings");
    };
    let scope = format!("search-observations:{session}:{claim}");
    let (limit, after) = match query.resolve(&scope) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let after = after.unwrap_or(0);
    match state
        .core
        .search_result_observations_page(session, claim, after, limit)
        .await
    {
        Ok(reply) => {
            let Some(page) = reply.value() else {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "NOT_FOUND",
                    "search result not found",
                )
                .into_response();
            };
            let cursor = if page.has_more {
                page.items.last().map(|row| {
                    resource::encode_cursor(
                        &scope,
                        &row.observation.receipt.observation_id.to_string(),
                    )
                })
            } else {
                None
            };
            let values = page
                .items
                .iter()
                .map(observation_response)
                .collect::<Vec<_>>();
            // Keep the SQL reply lease through bounded projection and serialization.
            resource::page(values, cursor, page.has_more)
        }
        Err(error) => super::super::persistence::persistence_error(error),
    }
}
fn observation_response(member: &MetadataSearchResultObservation) -> serde_json::Value {
    let event = &member.observation.event;
    let m = &event.metadata;
    json!({
        "id":member.observation.receipt.observation_id.to_string(),
        "origin":event.origin.as_str(),"reporterEndpoint":event.reporter_endpoint,
        "rawName":m.name,"normalizedName":m.name.as_deref().map(emulebb_core::normalize_ed2k_file_name),
        "sizeBytes":event.claim.size_bytes,"sources":m.source_count,"completeSources":m.complete_source_count,
        "sourceClientId":m.source_client_id,"sourceClientPort":m.source_client_port,"fileType":m.file_type,
        "media":{"artist":m.media_artist,"album":m.media_album,"title":m.media_title,
            "lengthSeconds":m.media_length_seconds,"bitrateKbps":m.media_bitrate_kbps,"codec":m.media_codec},
        "rating":m.rating,"aichHash":m.aich_root.as_ref().map(|value|data_encoding::BASE32_NOPAD.encode(value)),
        "complete":m.complete,"directory":m.directory,
        "comment":m.comment,"publisherId":m.publisher_id.as_ref().map(hex::encode),
        "firstSeenAt":member.first_seen_at_s,"lastSeenAt":member.last_seen_at_s,"observationCount":member.observation_count
    })
}
#[cfg(test)]
mod tests;
