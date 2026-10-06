use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use emulebb_metadata::{
    MetadataSearch, MetadataSearchResult, MetadataSearchResultObservation, MetadataStore,
    normalized_search_query,
};

use crate::{Search, SearchResult, SearchResultObservation};

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
        query: search.query.clone(),
        normalized_query: normalized_search_query(&search.query),
        method: search.method.clone(),
        file_type_filter: search.r#type.clone(),
        status: search.status.clone(),
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
            origin: result.method.clone(),
            name: result.name.clone(),
            size_bytes: result.size_bytes,
            source_count: result.sources,
            complete_source_count: result.complete_sources,
            source_client_id: result.source_client_id,
            source_client_port: result.source_client_port,
            file_type: result.file_type.clone(),
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
                rating: observation.rating,
                aich_hash: observation.aich_hash.clone(),
                complete: observation.complete,
                directory: observation.directory.clone(),
                observed_at_ms: observation.observed_at.timestamp_millis(),
            })
            .collect()
    };
    MetadataSearchResult {
        network: result.method.clone(),
        file_hash: result.hash.clone(),
        name: result.name.clone(),
        size_bytes: result.size_bytes,
        source_count: result.sources,
        complete_source_count: result.complete_sources,
        file_type: result.file_type.clone(),
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
        _ => (search.status, None),
    };
    Ok(Search {
        id: search.public_id.clone(),
        query: search.query,
        method: search.method,
        r#type: search.file_type_filter.clone(),
        status,
        status_reason,
        created_at,
        updated_at,
        results: search
            .results
            .into_iter()
            .map(|result| {
                search_result_from_metadata(&search.public_id, &search.file_type_filter, result)
            })
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
        method: result.network,
        r#type: file_type_filter.to_string(),
        hash: result.file_hash,
        name: result.name,
        size_bytes: result.size_bytes,
        sources: result.source_count,
        complete_sources: result.complete_source_count,
        source_client_id: source.map(|(client_id, _)| client_id),
        source_client_port: source.map(|(_, client_port)| client_port),
        file_type: result.file_type,
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
