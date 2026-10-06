use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use emulebb_metadata::{
    MetadataSearch, MetadataSearchResult, MetadataSearchResultObservation, MetadataSearchSpec,
    MetadataStore, normalized_search_query,
};

use crate::{Search, SearchResult, SearchResultMedia, SearchResultObservation, SearchSpec};

pub(crate) fn next_numeric_search_id(searches: &HashMap<String, Search>) -> u32 {
    searches
        .keys()
        .filter_map(|id| id.parse::<u32>().ok())
        .max()
        .unwrap_or_default()
        .saturating_add(1)
        .max(1)
}

pub(crate) fn allocate_search_id(
    searches: &HashMap<String, Search>,
    next_search_id: u32,
) -> Result<(String, u32)> {
    let mut candidate = next_search_id.max(1);
    loop {
        let search_id = candidate.to_string();
        if !searches.contains_key(&search_id) {
            let next_search_id = candidate.checked_add(1).unwrap_or(1).max(1);
            return Ok((search_id, next_search_id));
        }
        candidate = candidate
            .checked_add(1)
            .context("search id space exhausted")?;
    }
}

pub(crate) fn load_searches(metadata: &MetadataStore) -> Result<HashMap<String, Search>> {
    metadata
        .load_searches()?
        .into_iter()
        .map(|search| {
            let search = search_from_metadata(search)?;
            Ok((search.id.clone(), search))
        })
        .collect()
}

pub(crate) fn persist_search(metadata: &MetadataStore, search: &Search) -> Result<()> {
    metadata.upsert_search(&search_to_metadata(search))
}

fn search_to_metadata(search: &Search) -> MetadataSearch {
    let updated_at_ms = search.updated_at.timestamp_millis();
    MetadataSearch {
        public_id: search.id.clone(),
        normalized_query: normalized_search_query(&search.spec.query),
        spec: MetadataSearchSpec {
            query: search.spec.query.clone(),
            method: search.spec.method.clone(),
            file_type: search.spec.r#type.clone(),
            extension: search.spec.extension.clone(),
            min_size_bytes: search.spec.min_size_bytes,
            max_size_bytes: search.spec.max_size_bytes,
            min_availability: search.spec.min_availability,
            min_complete_sources: search.spec.min_complete_sources,
            min_bitrate_kbps: search.spec.min_bitrate_kbps,
            min_length_seconds: search.spec.min_length_seconds,
            codec: search.spec.codec.clone(),
            title: search.spec.title.clone(),
            album: search.spec.album.clone(),
            artist: search.spec.artist.clone(),
        },
        resolved_method: search.resolved_method.clone(),
        status: search.status.clone(),
        status_reason: search.status_reason.clone(),
        created_at_ms: search.created_at.timestamp_millis(),
        updated_at_ms,
        completed_at_ms: (search.status == "completed").then_some(updated_at_ms),
        results: search
            .results
            .iter()
            .map(|result| search_result_to_metadata(result, updated_at_ms))
            .collect(),
    }
}

fn search_result_to_metadata(result: &SearchResult, observed_at_ms: i64) -> MetadataSearchResult {
    let observations = if result.observations.is_empty() {
        vec![MetadataSearchResultObservation {
            origin: "unknown".to_string(),
            name: result.name.clone(),
            size_bytes: result.size_bytes,
            source_count: result.sources,
            complete_source_count: result.complete_sources,
            source_client_id: result.source_client_id,
            source_client_port: result.source_client_port,
            file_type: result.file_type.clone(),
            media_artist: result.media.artist.clone(),
            media_album: result.media.album.clone(),
            media_title: result.media.title.clone(),
            media_length_seconds: result.media.length_seconds,
            media_bitrate_kbps: result.media.bitrate_kbps,
            media_codec: result.media.codec.clone(),
            rating: result.rating,
            aich_hash: result.aich_hash.clone(),
            complete: result.complete,
            directory: result.directory.clone(),
            observed_at_ms,
        }]
    } else {
        result
            .observations
            .iter()
            .map(|observation| MetadataSearchResultObservation {
                origin: observation.origin.clone(),
                name: observation.name.clone(),
                size_bytes: observation.size_bytes,
                source_count: observation.sources,
                complete_source_count: observation.complete_sources,
                source_client_id: observation.source_client_id,
                source_client_port: observation.source_client_port,
                file_type: observation.file_type.clone(),
                media_artist: observation.media.artist.clone(),
                media_album: observation.media.album.clone(),
                media_title: observation.media.title.clone(),
                media_length_seconds: observation.media.length_seconds,
                media_bitrate_kbps: observation.media.bitrate_kbps,
                media_codec: observation.media.codec.clone(),
                rating: observation.rating,
                aich_hash: observation.aich_hash.clone(),
                complete: observation.complete,
                directory: observation.directory.clone(),
                observed_at_ms: observation.observed_at.timestamp_millis(),
            })
            .collect()
    };
    MetadataSearchResult {
        file_hash: result.hash.clone(),
        name: result.name.clone(),
        size_bytes: result.size_bytes,
        source_count: result.sources,
        complete_source_count: result.complete_sources,
        file_type: result.file_type.clone(),
        media_artist: result.media.artist.clone(),
        media_album: result.media.album.clone(),
        media_title: result.media.title.clone(),
        media_length_seconds: result.media.length_seconds,
        media_bitrate_kbps: result.media.bitrate_kbps,
        media_codec: result.media.codec.clone(),
        rating: result.rating,
        aich_hash: result.aich_hash.clone(),
        complete: result.complete,
        directory: result.directory.clone(),
        observations,
    }
}

fn search_from_metadata(search: MetadataSearch) -> Result<Search> {
    let created_at = timestamp_ms(search.created_at_ms, "search created_at_ms")?;
    let updated_at = timestamp_ms(search.updated_at_ms, "search updated_at_ms")?;
    // WHY: a persisted "queued"/"running" search has no queue entry or
    // background task after a restart — leaving the status as-is would show
    // an immortal in-progress search that can never complete (the dishonest
    // sibling of the silent completed-empty bug). Surface the truth instead.
    let (status, status_reason) = match search.status.as_str() {
        "queued" | "running" => (
            "error".to_string(),
            Some("interrupted-by-restart".to_string()),
        ),
        _ => (search.status, search.status_reason),
    };
    let spec = SearchSpec {
        query: search.spec.query,
        method: search.spec.method,
        r#type: search.spec.file_type,
        extension: search.spec.extension,
        min_size_bytes: search.spec.min_size_bytes,
        max_size_bytes: search.spec.max_size_bytes,
        min_availability: search.spec.min_availability,
        min_complete_sources: search.spec.min_complete_sources,
        min_bitrate_kbps: search.spec.min_bitrate_kbps,
        min_length_seconds: search.spec.min_length_seconds,
        codec: search.spec.codec,
        title: search.spec.title,
        album: search.spec.album,
        artist: search.spec.artist,
    };
    let file_type_filter = spec.r#type.clone();
    Ok(Search {
        id: search.public_id.clone(),
        spec,
        resolved_method: search.resolved_method,
        status,
        status_reason,
        created_at,
        updated_at,
        results: search
            .results
            .into_iter()
            .map(|result| search_result_from_metadata(&search.public_id, &file_type_filter, result))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn search_result_from_metadata(
    search_id: &str,
    file_type_filter: &str,
    result: MetadataSearchResult,
) -> Result<SearchResult> {
    let observations = result
        .observations
        .into_iter()
        .map(|observation| {
            Ok(SearchResultObservation {
                origin: observation.origin,
                name: observation.name,
                size_bytes: observation.size_bytes,
                sources: observation.source_count,
                complete_sources: observation.complete_source_count,
                source_client_id: observation.source_client_id,
                source_client_port: observation.source_client_port,
                file_type: observation.file_type,
                media: SearchResultMedia {
                    artist: observation.media_artist,
                    album: observation.media_album,
                    title: observation.media_title,
                    length_seconds: observation.media_length_seconds,
                    bitrate_kbps: observation.media_bitrate_kbps,
                    codec: observation.media_codec,
                },
                rating: observation.rating,
                aich_hash: observation.aich_hash,
                complete: observation.complete,
                directory: observation.directory,
                observed_at: timestamp_ms(
                    observation.observed_at_ms,
                    "search result observation observed_at_ms",
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let source = observations.iter().find_map(|observation| {
        observation
            .source_client_id
            .zip(observation.source_client_port)
    });
    Ok(SearchResult {
        search_id: search_id.to_string(),
        r#type: file_type_filter.to_string(),
        hash: result.file_hash,
        name: result.name,
        size_bytes: result.size_bytes,
        sources: result.source_count,
        complete_sources: result.complete_source_count,
        source_client_id: source.map(|(client_id, _)| client_id),
        source_client_port: source.map(|(_, client_port)| client_port),
        file_type: result.file_type,
        media: SearchResultMedia {
            artist: result.media_artist,
            album: result.media_album,
            title: result.media_title,
            length_seconds: result.media_length_seconds,
            bitrate_kbps: result.media_bitrate_kbps,
            codec: result.media_codec,
        },
        rating: result.rating,
        aich_hash: result.aich_hash,
        complete: result.complete,
        directory: result.directory,
        observations,
    })
}

fn timestamp_ms(value: i64, label: &str) -> Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp_millis(value).with_context(|| format!("invalid {label}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_spec_and_terminal_reason_survive_persistence() {
        let metadata = MetadataStore::in_memory().unwrap();
        let spec = SearchSpec {
            query: "exact session".to_string(),
            method: "global".to_string(),
            r#type: "audio".to_string(),
            extension: "flac".to_string(),
            min_size_bytes: Some(u64::MAX - 1),
            max_size_bytes: Some(u64::MAX),
            min_availability: Some(23),
            min_complete_sources: Some(7),
            min_bitrate_kbps: Some(1_411),
            min_length_seconds: Some(240),
            codec: "flac".to_string(),
            title: "Example Title".to_string(),
            album: "Example Album".to_string(),
            artist: "Example Artist".to_string(),
        };
        let now = Utc::now();
        let result = SearchResult::from_observation(
            "91".to_string(),
            "audio".to_string(),
            "00112233445566778899aabbccddeeff".to_string(),
            SearchResultObservation {
                origin: "kad".to_string(),
                name: "Example Track.flac".to_string(),
                size_bytes: 8_192,
                sources: 12,
                complete_sources: 4,
                source_client_id: None,
                source_client_port: None,
                file_type: "Audio".to_string(),
                media: SearchResultMedia {
                    artist: "Example Artist".to_string(),
                    album: "Example Album".to_string(),
                    title: "Example Title".to_string(),
                    length_seconds: 240,
                    bitrate_kbps: 1_411,
                    codec: "flac".to_string(),
                },
                rating: 0,
                aich_hash: String::new(),
                complete: false,
                directory: String::new(),
                observed_at: now,
            },
        );
        let search = Search {
            id: "91".to_string(),
            spec: spec.clone(),
            resolved_method: Some("global".to_string()),
            status: "error".to_string(),
            status_reason: Some("network-search-failed".to_string()),
            created_at: now,
            updated_at: now,
            results: vec![result],
        };

        persist_search(&metadata, &search).unwrap();
        let searches = load_searches(&metadata).unwrap();

        assert_eq!(searches.len(), 1);
        let reloaded = searches.get("91").unwrap();
        assert_eq!(reloaded.spec, spec);
        assert_eq!(reloaded.resolved_method.as_deref(), Some("global"));
        assert_eq!(reloaded.results.len(), 1);
        assert_eq!(reloaded.results[0].media.artist, "Example Artist");
        assert_eq!(reloaded.results[0].media.album, "Example Album");
        assert_eq!(reloaded.results[0].media.title, "Example Title");
        assert_eq!(reloaded.results[0].media.length_seconds, 240);
        assert_eq!(reloaded.results[0].media.bitrate_kbps, 1_411);
        assert_eq!(reloaded.results[0].media.codec, "flac");
        assert_eq!(reloaded.results[0].observations[0].origin, "kad");
        assert_eq!(
            reloaded.status_reason.as_deref(),
            Some("network-search-failed")
        );
    }
}
